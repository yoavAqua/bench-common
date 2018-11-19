// Copyright © 2017 Aqua Security Software Ltd. <info@aquasec.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package auditeval

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"reflect"
)

type binOp string

const (
	and binOp = "and"
	or        = "or"
)

// Tests combine test items with binary operations to evaluate results.
type Tests struct {
	TestItems []*testItem `yaml:"test_items"`
	BinOp     binOp       `yaml:"bin_op"`
}

type testItem struct {
	Flag    string
	Output  string
	Value   string
	Set     bool
	Compare compare
}

type compare struct {
	Op    string
	Value string
}

type testOutput struct {
	TestResult   bool
	ActualResult []map[string]interface{}
}

func (t *testItem) execute(s string) *testOutput {
	result := &testOutput{TestResult: true, ActualResult: []map[string]interface{}{}}

	s = strings.TrimRight(s, " \n")
	flagReg := regexp.MustCompile(t.Flag)

	// If the test should run on multipul values - if the flag occures more than once (Containers, Images, etc)
	if len(flagReg.FindAllStringIndex(s, -1)) > 1 {
		values := strings.Split(s, "\n")
		testResult := true

		for _, v := range values {
			testResult = t.evalTestResult(v)

			if !testResult {
				result.TestResult = false
				result.ActualResult = smartAppend(result.ActualResult, parseActualResult(v, t.Flag, t.Set))
			}
		}
	} else {
		result.TestResult = t.evalTestResult(s)

		if !result.TestResult && len(s) > 0 {
			result.ActualResult = smartAppend(result.ActualResult, parseActualResult(s, t.Flag, t.Set))
		}
	}

	return result
}

func (ts *Tests) Execute(s string) *testOutput {
	finalOutput := &testOutput{}
	var result bool
	if ts == nil {
		return finalOutput
	}

	res := make([]testOutput, len(ts.TestItems))
	if len(res) == 0 {
		return finalOutput
	}

	actualResult := []map[string]interface{}{}

	for i, t := range ts.TestItems {
		res[i] = *(t.execute(s))
		actualResult = smartAppend(actualResult, res[i].ActualResult...)
	}

	// If no binary operation is specified, default to AND
	switch ts.BinOp {
	default:
		fmt.Fprintf(os.Stderr, "unknown binary operator for tests %s\n", ts.BinOp)
		os.Exit(1)
	case and, "":
		result = true
		for i := range res {
			result = result && res[i].TestResult
		}
	case or:
		result = false
		for i := range res {
			result = result || res[i].TestResult
		}
	}
	finalOutput.TestResult = result
	finalOutput.ActualResult = actualResult

	return finalOutput
}

func eval(compareOp, flagVal, compareValue string) bool {
	switch compareOp {
	case "eq":
		value := strings.ToLower(flagVal)
		// Do case insensitive comparaison for booleans ...
		if value == "false" || value == "true" {
			return value == compareValue
		} else {
			return flagVal == compareValue
		}

	case "noteq":
		value := strings.ToLower(flagVal)
		// Do case insensitive comparaison for booleans ...
		if value == "false" || value == "true" {
			return !(value == compareValue)
		} else {
			return !(flagVal == compareValue)
		}

	case "gt":
		a, b, err := toNumeric(flagVal, compareValue)
		if err == nil {
			return a > b
		}

	case "gte":
		a, b, err := toNumeric(flagVal, compareValue)
		if err == nil {
			return a >= b
		}

	case "lt":
		a, b, err := toNumeric(flagVal, compareValue)
		if err == nil {
			return a < b
		}

	case "lte":
		a, b, err := toNumeric(flagVal, compareValue)
		if err == nil {
			return a <= b
		}

	case "has":
		return strings.Contains(flagVal, compareValue)

	case "nothave":
		return !strings.Contains(flagVal, compareValue)
	}

	return false

}

func smartAppend(arr []map[string]interface{}, elements ...map[string]interface{}) []map[string]interface{}{
	for _, element := range elements{
		isElemExists := false
		for _, obj := range arr {
			if reflect.DeepEqual(obj, element) {
				isElemExists = true
				break
			}
		}

		if !isElemExists {
			arr = append(arr, element)
		}
	}

	return arr
}

func toNumeric(a, b string) (c, d int, err error) {
	if len(a) == 0 || len(b) == 0 {
		return -1, -1, fmt.Errorf("Cannot convert blank value to numeric")
	}
	c, err = strconv.Atoi(a)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error converting %s: %s\n", a, err)
		os.Exit(1)
	}
	d, err = strconv.Atoi(b)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error converting %s: %s\n", b, err)
		os.Exit(1)
	}

	return c, d, err
}

func getFlagValue(s, flag string) string {
	var flagVal string
	pttns := []string{
		flag + `=([^ \n]*[a-zA-Z0-9])`,
		flag + `:([^ \n]*[a-zA-Z0-9])`,
		flag + ` +([^- ]+)`,
		`(?:^| +)` + `(` + flag + `)` + `(?: |$)`,
	}
	for _, pttn := range pttns {
		flagRe := regexp.MustCompile(pttn)
		vals := flagRe.FindStringSubmatch(s)
		for i, currentValue := range vals {
			if i == 0 {
				continue
			}
			if len(currentValue) > 0 {
				flagVal = currentValue
				return flagVal
			}
		}
	}
	return flagVal
}

func parseActualResult(s, flag string, set bool) map[string]interface{} {
	if !strings.Contains(s, "$$"){
		flagVal := getFlagValue(s, flag)
		if len(flagVal) > 0 {
			return map[string]interface{}{"Raw": flagVal}
		}
		return nil
	}

	a := map[string]interface{}{}
	abs := strings.Split(s, (":"))
	values := strings.Split(abs[0], ",")

	for _, value := range values {
		arguments := strings.Split(value, "$$")

		if len(arguments) > 1 {
			if arguments[0] == "Id" {
				arguments[1] = arguments[1][:5]
			}

			a[arguments[0]] = arguments[1]
		} else if len(value) > 0{
			a["Raw"] = value
		}
	}

	return a
}

func (t *testItem) evalTestResult(s string) bool{
	if t.Set {
		if t.Compare.Op != "" {
			flagVal := getFlagValue(s, t.Flag)
			return eval(t.Compare.Op, flagVal, t.Compare.Value)
		} else {
			r, _ := regexp.MatchString(t.Flag+`(?:[^a-zA-Z0-9-_]|$)`, s)
			return r
		}
	} else {
		r, _ := regexp.MatchString(t.Flag+`(?:[^a-zA-Z0-9-_]|$)`, s)
		return !r
	}
}
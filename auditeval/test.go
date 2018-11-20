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
	"reflect"
	"regexp"
	"strconv"
	"strings"
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
	ActualResult []Attributes
}

type Attribute struct {
	Name  string
	Value string
}

func (a *Attribute) Print() {
	fmt.Printf("\t%s: %v", a.Name, a.Value)
}

type Attributes []Attribute

func (t *testItem) execute(s string) *testOutput {
	result := &testOutput{TestResult: true, ActualResult: []Attributes{}}

	s = strings.TrimRight(s, " \n")
	flagReg := regexp.MustCompile(t.Flag)

	// If the test should run on multiple values - Meaning if the flag occures more than once (Containers, Images, etc)
	if len(flagReg.FindAllStringIndex(s, -1)) > 1 {
		values := strings.Split(s, "\n")
		var testResult bool

		for _, v := range values {
			testResult = t.evalTestResult(v)

			if !testResult {
				result.TestResult = false
				result.ActualResult = smartAppend(result.ActualResult, parseActualResult(v, t.Flag))
			}
		}
	} else {
		result.TestResult = t.evalTestResult(s)

		if !result.TestResult && len(s) > 0 {
			result.ActualResult = smartAppend(result.ActualResult, parseActualResult(s, t.Flag))
		}
	}

	return result
}

func (ts *Tests) Execute(s string) *testOutput {
	finalOutput := &testOutput{ActualResult: []Attributes{}}
	var result bool
	if ts == nil {
		return finalOutput
	}

	res := make([]testOutput, len(ts.TestItems))
	if len(res) == 0 {
		return finalOutput
	}

	actualResult := []Attributes{}

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

// Append elements to an array only if they don't exists in it
func smartAppend(arr []Attributes, elements ...Attributes) []Attributes {
	for _, element := range elements {
		if element == nil {
			continue
		}

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

func (t *testItem) evalTestResult(s string) bool {
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

func parseActualResult(s, flag string) (res Attributes) {
	// If there is no parsing to be done, return the entire string as raw string
	if !strings.Contains(s, "$$") {
		flagVal := getFlagValue(s, flag)
		if len(flagVal) > 0 {
			return Attributes{{"Raw", flagVal}}
		}
		return nil
	}

	// Discard the string after the delimiter, and split the output to attributes by the delimiter ','
	delimiterIndex := strings.Index(s, ":")
	values := strings.Split(s[:delimiterIndex], ",")

	for _, value := range values {
		attrs := strings.Split(value, "$$")

		// If there was at least one match of $$
		if len(attrs) > 1 {
			// If the attribute is Id, cut the id to be first 12 digits
			if attrs[0] == "Id" {
				attrs[1] = attrs[1][:12]
			}

			res = append(res, Attribute{Name: attrs[0], Value: attrs[1]})

		} else if len(value) == 1 {
			res = append(res, Attribute{Name: "Raw", Value: attrs[0]})
		}
	}

	return res
}

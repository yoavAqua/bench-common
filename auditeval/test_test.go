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
	"testing"
)

func TestGetFlagValue(t *testing.T) {

	type TestRegex struct {
		Input    string
		Flag     string
		Expected string
	}

	tests := []TestRegex{
		{Input: "XXX: User=root XXX", Flag: "User", Expected: "root"},
		{Input: "XXX: User=", Flag: "User", Expected: ""},
		{Input: "XXX: User= AAA XXX", Flag: "User", Expected: ""},
		{Input: "XXX: XXX User=some_user XXX", Flag: "User", Expected: "some_user"},
		{Input: "--flag=AAA,BBB,CCC XXX", Flag: "--flag", Expected: "AAA,BBB,CCC"},
		{Input: "--flag", Flag: "--flag", Expected: "--flag"},
		{Input: "XXX --flag AAA XXX", Flag: "--flag", Expected: "AAA"},
		{Input: "XXX --AAA BBB", Flag: "XXX", Expected: "XXX"},
		{Input: "XXX", Flag: "XXX", Expected: "XXX"},
		{Input: "CCC XXX AAA BBB", Flag: "XXX", Expected: "AAA"},
		{Input: "YXXX", Flag: "XXX", Expected: ""},
		{Input: "XXXY", Flag: "XXX", Expected: ""},
	}

	for i, test := range tests {
		actual := getFlagValue(test.Input, test.Flag)
		if test.Expected != actual {
			t.Errorf("test %d fail: expected: %v actual: %v\ntest details: %+v\n", i, test.Expected, actual, test)
		}
	}
}

/*
Copyright paskal.maksim@gmail.com
Licensed under the Apache License, Version 2.0 (the "License")
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package utils

import (
	"log/slog"
	"regexp"
)

type DebugWriter struct {
}

func (d *DebugWriter) Write(p []byte) (n int, err error) {
	slog.Debug("boundary", "output", string(p))

	return len(p), nil
}

func PadLeft(str string, length int) string {
	for len(str) < length {
		str = "0" + str
	}
	return str
}

func FormatPort(name string, length int) string {
	re2 := regexp.MustCompile(`[^0-9]+`)

	// Get all digits from the string
	port := re2.ReplaceAllString(name, "")

	return PadLeft(port, length)
}

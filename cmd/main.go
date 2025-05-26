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
package main

import (
	"boundary-cli/internal"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"

	"github.com/manifoldco/promptui"
)

var gitVersion = "dev"

func main() {
	verbose := flag.Bool("verbose", false, "Enable verbose logging")
	version := flag.Bool("version", false, "Show version information")
	flag.Parse()

	if *version {
		fmt.Println(gitVersion)
		return
	}

	if *verbose {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}

	application := internal.NewApplication()

	if err := application.Init(); err != nil {
		slog.Error("Error initializing application", "error", err.Error())
		return
	}

	if err := application.Run(context.Background()); err != nil {
		if errors.Is(err, promptui.ErrInterrupt) {
			slog.Debug("User interrupted the application")

			return
		}

		slog.Error("Error running application", "error", err.Error())
	}
}

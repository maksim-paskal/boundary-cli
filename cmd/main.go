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

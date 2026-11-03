package main

import (
	"errors"
	"os"

	"github.com/jurajpiar/devkit/internal/app"
)

func main() {
	if err := app.Execute(); err != nil {
		// Commands with a verdict (devkit audit) choose their own status.
		var coded interface{ ExitCode() int }
		if errors.As(err, &coded) {
			os.Exit(coded.ExitCode())
		}
		os.Exit(1)
	}
}

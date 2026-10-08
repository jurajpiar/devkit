package main

import (
	"os"

	"github.com/jurajpiar/devkit/internal/app"
)

func main() {
	if err := app.Execute(); err != nil {
		os.Exit(1)
	}
}

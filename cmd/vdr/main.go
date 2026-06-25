package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/matthewvenne/trivy-plugin-k8s-vdr/internal/config"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintf(os.Stderr, "vdr: %v\n", err)
		os.Exit(2)
	}
}

func run(args []string) error {
	_, err := config.ParseWithOutput(args, os.Stdout)
	return err
}

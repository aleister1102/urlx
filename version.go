package main

import (
	"fmt"
	"os"
)

// These variables are overridden at build time via -ldflags.
// Defaults are useful for local (non-release) builds.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// printVersion prints a single-line version summary.
func printVersion() {
	fmt.Printf("urlx %s (commit %s, built %s)\n", Version, Commit, Date)
}

// init checks for version and help request arguments early.
// Supported:
//   urlx version / -version / --version / -v
//   urlx help / -help / --help / -h
func init() {
	if len(os.Args) < 2 {
		return
	}
	for _, a := range os.Args[1:] {
		switch a {
		case "version", "-version", "--version", "-v":
			printVersion()
			os.Exit(0)
		case "help", "-help", "--help", "-h":
			usage()
			os.Exit(0)
		}
	}
}
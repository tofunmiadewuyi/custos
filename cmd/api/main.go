package main

import (
	"fmt"
	"os"
)

var version = "dev" // overridden at release via -ldflags -X main.version

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "version", "--version", "-v":
		fmt.Println("custos", version)
	case "migrate":
		cmdMigrate(os.Args[2:])
	case "gen-keys":
		cmdGenKeys(os.Args[2:])
	case "create-admin":
		cmdCreateAdmin(os.Args[2:])
	case "serve":
		cmdServe(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: custos <serve|migrate|create-admin|gen-keys|version> [flags]")
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

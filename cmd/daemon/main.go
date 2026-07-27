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
	case "install":
		cmdInstall(os.Args[2:])
	case "enroll":
		cmdEnroll(os.Args[2:])
	case "authkeys":
		cmdAuthkeys(os.Args[2:])
	case "run":
		cmdRun(os.Args[2:])
	case "exec":
		cmdExec(os.Args[2:])
	case "apply-update":
		cmdApplyUpdate(os.Args[2:])
	case "status":
		fatal("%s: not implemented yet", os.Args[1])
	case "version", "--version", "-v":
		fmt.Println("custosd", version)
	default:
		usage()
		os.Exit(2)
	}
}



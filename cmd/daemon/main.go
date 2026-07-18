package main

import (
	"os"

)

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
	case "status":
		fatal("%s: not implemented yet", os.Args[1])
	default:
		usage()
		os.Exit(2)
	}
}



package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/tofunmiadewuyi/custos/internal/daemon"
)


func cmdAuthkeys(args []string) {
	fs := flag.NewFlagSet("authkeys", flag.ExitOnError)
	dir := fs.String("dir", daemon.DefaultDir, "state directory")
	socket := fs.String("socket", daemon.DefaultSocket, "daemon socket path")
	fs.Parse(args)

	rest := fs.Args()
	if len(rest) != 3 {
		fmt.Fprintln(os.Stderr, "authkeys: expected <user> <keytype> <keyblob>")
		return
	}
	user, keyType, keyBlob := rest[0], rest[1], rest[2]

	store, err := daemon.OpenStore(*dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "authkeys: %v\n", err)
		return
	}
	line, err := daemon.AuthorizedKey(*socket, store, keyType, keyBlob, user)
	if err != nil {
		fmt.Fprintf(os.Stderr, "authkeys: %v\n", err)
		return
	}
	if line != "" {
		fmt.Println(line)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: custosd <enroll|run|authkeys|status> [flags]")
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

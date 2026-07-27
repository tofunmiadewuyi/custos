package main

import (
	"flag"
	"log"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"
	"time"

	"github.com/tofunmiadewuyi/custos/internal/daemon"
)

// cmdExec fetches a secret set from the daemon, injects it as env vars, and
// replaces itself with the target command. It fails closed and loud: on any
// rejection it exits non-zero WITHOUT starting the app, so a missing set can
// never launch the app with half its environment.
func cmdExec(args []string) {
	fs := flag.NewFlagSet("exec", flag.ExitOnError)
	set := fs.String("set", "", "secret set to inject as env vars")
	socket := fs.String("secret-socket", daemon.DefaultSecretSocket, "daemon secrets socket")
	timeout := fs.Duration("timeout", 30*time.Second, "how long to wait for the daemon to have the set")
	fs.Parse(args)

	cmdArgs := fs.Args()
	if *set == "" || len(cmdArgs) == 0 {
		fatal("usage: custosd exec --set NAME -- command [args...]")
	}

	values, err := daemon.FetchSet(*socket, *set, *timeout)
	if err != nil {
		fatal("exec: could not load set %q (running as %s): %v — app NOT started", *set, currentUser(), err)
	}
	if len(values) == 0 {
		log.Printf("exec: warning: set %q has no values; starting %s with nothing injected", *set, cmdArgs[0])
	}

	bin, err := exec.LookPath(cmdArgs[0])
	if err != nil {
		fatal("exec: %v", err)
	}
	env := os.Environ()
	for k, v := range values {
		env = append(env, k+"="+v)
	}
	// Replace this process: the values live only in the target's env memory.
	if err := syscall.Exec(bin, cmdArgs, env); err != nil {
		fatal("exec: %v", err)
	}
}

func currentUser() string {
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return "uid " + strconv.Itoa(os.Getuid())
}

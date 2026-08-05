package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/tofunmiadewuyi/custos/internal/daemon"
)

// cmdStatus reports what the daemon can tell from its state dir alone. It does
// not query the running daemon, so it can't report live connection state.
func cmdStatus(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	dir := fs.String("dir", daemon.DefaultDir, "state directory")
	fs.Parse(args)

	store, err := daemon.OpenStore(*dir)
	if err != nil {
		fatal("status: %v", err)
	}

	fmt.Printf("custosd %s\n", version)
	fmt.Printf("%-16s %s\n", "state dir:", *dir)

	if err := store.EnrollmentError(); errors.Is(err, os.ErrNotExist) {
		fmt.Printf("%-16s no (run `custosd enroll` first)\n", "enrolled:")
		return
	} else if err != nil {
		fatal("status: cannot read enrollment state in %s: %v", *dir, err)
	}
	cfg, err := store.LoadConfig()
	if err != nil {
		fatal("status: %v", err)
	}
	fmt.Printf("%-16s yes\n", "enrolled:")
	fmt.Printf("%-16s %s\n", "host id:", cfg.HostID)
	fmt.Printf("%-16s %s\n", "control plane:", cfg.ControlPlane)
	if st, err := store.LoadStatus(); err == nil {
		conn := "disconnected"
		if st.Connected {
			conn = "connected"
		}
		fmt.Printf("%-16s %s (updated %s ago)\n", "cp connection:", conn, time.Since(st.UpdatedAt).Round(time.Second))
	} else {
		fmt.Printf("%-16s unknown (daemon not started)\n", "cp connection:")
	}
	fmt.Printf("%-16s %s\n", "signing key:", presence(cfg.SigningPublicKey != ""))

	_, encErr := store.LoadEncryptionKey()
	fmt.Printf("%-16s %s\n", "encryption key:", presence(encErr == nil))

	if cache, err := store.LoadCache(); err == nil {
		fmt.Printf("%-16s %d\n", "cached ssh keys:", cache.Len())
	}

	// A staged OTA binary waiting for the next restart to be applied.
	if _, err := os.Stat(filepath.Join(*dir, "update", "custosd.staged")); err == nil {
		v := ""
		if data, err := os.ReadFile(filepath.Join(*dir, "update", "staged.json")); err == nil {
			var m daemon.StagedMeta
			if json.Unmarshal(data, &m) == nil {
				v = " " + m.Version
			}
		}
		fmt.Printf("%-16s yes%s (applies on next restart)\n", "staged upgrade:", v)
	} else {
		fmt.Printf("%-16s none\n", "staged upgrade:")
	}
}

func presence(ok bool) string {
	if ok {
		return "present"
	}
	return "absent"
}

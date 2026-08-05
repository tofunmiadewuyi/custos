package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/tofunmiadewuyi/custos/internal/daemon"
)

// cmdUninstall reverses install, in the safe order: it drops the sshd hook and
// reloads sshd before removing the binary, so AuthorizedKeysCommand never points
// at a missing file. Best-effort and idempotent — missing pieces are skipped.
func cmdUninstall(args []string) {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	purge := fs.Bool("purge", false, "also remove the state dir and custos user (de-enrolls the host)")
	skipControlPlane := fs.Bool("skip-control-plane", false, "do not notify the control plane that this host is being removed")
	fs.Parse(args)

	if os.Geteuid() != 0 {
		fatal("uninstall: must run as root (try sudo)")
	}

	if !*skipControlPlane {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		store, err := daemon.OpenStore(installStateDir)
		if err == nil {
			err = daemon.Decommission(ctx, store)
		}
		cancel()
		if err != nil {
			warn("control-plane decommission failed: %v", err)
		} else {
			fmt.Println("decommissioned host in control plane")
		}
	}

	// 1. Stop the service.
	runCmd("systemctl", "disable", "--now", "custosd")

	// 2. Remove the sshd drop-in and reload BEFORE the binary.
	if err := daemon.RemoveDropIn(""); err != nil {
		warn("remove sshd drop-in: %v", err)
	} else {
		if err := daemon.Validate(); err != nil {
			warn("sshd config invalid after removing drop-in: %v", err)
		} else if err := daemon.Reload(); err != nil {
			warn("reload sshd: %v", err)
		}
		fmt.Println("removed sshd drop-in:", daemon.DropInPath())
	}

	// 3. Remove the systemd unit.
	rmPath(installUnitPath)
	runCmd("systemctl", "daemon-reload")

	// 4. Remove the binary (and any staged rollback copy).
	rmPath(installBin)
	rmPath(installBin + ".prev")

	if *purge {
		if err := os.RemoveAll(installStateDir); err != nil {
			warn("remove %s: %v", installStateDir, err)
		} else {
			fmt.Println("removed state dir:", installStateDir)
		}
		if out, err := exec.Command("userdel", installUser).CombinedOutput(); err != nil {
			warn("remove user %s: %v: %s", installUser, err, out)
		} else {
			fmt.Println("removed user:", installUser)
		}
	} else {
		fmt.Printf("kept %s and user %s — re-enroll to reuse, or rerun with --purge to remove\n", installStateDir, installUser)
	}

	if *skipControlPlane {
		fmt.Println("uninstalled. on the control plane, revoke this host: POST /hosts/{id}/revoke")
	} else {
		fmt.Println("uninstalled")
	}
}

// runCmd runs a command best-effort, warning on failure.
func runCmd(name string, args ...string) {
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		warn("%s: %v: %s", name, err, out)
	}
}

func rmPath(path string) {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		warn("remove %s: %v", path, err)
	}
}

func warn(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "warning: "+format+"\n", args...)
}

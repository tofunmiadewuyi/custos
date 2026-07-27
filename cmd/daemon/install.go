package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"

	"github.com/tofunmiadewuyi/custos/internal/daemon"
)

const (
	installBin      = "/usr/local/bin/custosd"
	installStateDir = "/var/lib/custos"
	installSocket   = "/run/custos/custosd.sock"
	installUser     = "custos"
	installUnitPath = "/etc/systemd/system/custosd.service"
)

// RuntimeDirectory=custos makes systemd create /run/custos owned by the custos
// user, so the daemon (and authkeys, run as the same user) can reach the socket.
const systemdUnit = `[Unit]
Description=custos daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=custos
Group=custos
RuntimeDirectory=custos
# '+' runs this as root even though the service is User=custos: it swaps in a
# daemon-staged binary before start. No-op when nothing is staged.
ExecStartPre=+/usr/local/bin/custosd apply-update --dir /var/lib/custos
ExecStart=/usr/local/bin/custosd run --dir /var/lib/custos --socket /run/custos/custosd.sock
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
`

// cmdInstall does the one-time root setup: creates the custos user, installs the
// binary and systemd unit, and wires sshd. Enrollment (as the custos user) and
// starting the service come after.
func cmdInstall(args []string) {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	sshUser := fs.String("ssh-user", installUser, "AuthorizedKeysCommandUser")
	fs.Parse(args)

	if os.Geteuid() != 0 {
		fatal("install: must run as root (try sudo)")
	}
	self, err := os.Executable()
	if err != nil {
		fatal("install: cannot resolve own path: %v", err)
	}

	uid, gid := ensureUser(installUser)
	installBinary(self)
	makeStateDir(uid, gid)
	installUnit()
	setupSSHD(*sshUser, installStateDir, installSocket, installBin)

	fmt.Println("\ninstalled. next:")
	fmt.Printf("  sudo -u %s %s enroll --control-plane <url> --token <token> --dir %s\n", installUser, installBin, installStateDir)
	fmt.Println("  sudo systemctl enable --now custosd")
}

func ensureUser(name string) (uid, gid int) {
	u, err := user.Lookup(name)
	if err != nil {
		if out, err := exec.Command("useradd", "--system", "--shell", "/usr/sbin/nologin", name).CombinedOutput(); err != nil {
			fatal("install: create user %s: %v: %s", name, err, out)
		}
		if u, err = user.Lookup(name); err != nil {
			fatal("install: user %s missing after creation: %v", name, err)
		}
	}
	uid, _ = strconv.Atoi(u.Uid)
	gid, _ = strconv.Atoi(u.Gid)
	return uid, gid
}

func installBinary(self string) {
	if self == installBin {
		return
	}
	src, err := os.Open(self)
	if err != nil {
		fatal("install: open binary: %v", err)
	}
	defer src.Close()
	dst, err := os.OpenFile(installBin, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		fatal("install: write %s: %v", installBin, err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		fatal("install: copy binary: %v", err)
	}
	if err := dst.Close(); err != nil {
		fatal("install: %v", err)
	}
	os.Chmod(installBin, 0o755)
	fmt.Println("installed binary:", installBin)
}

func makeStateDir(uid, gid int) {
	updateDir := filepath.Join(installStateDir, "update")
	for _, d := range []string{installStateDir, updateDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			fatal("install: create %s: %v", d, err)
		}
		if err := os.Chown(d, uid, gid); err != nil {
			fatal("install: chown %s: %v", d, err)
		}
	}
}

func installUnit() {
	if err := os.WriteFile(installUnitPath, []byte(systemdUnit), 0o644); err != nil {
		fatal("install: write unit: %v", err)
	}
	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: systemctl daemon-reload failed: %v\n", err)
	}
	fmt.Println("installed unit:", installUnitPath)
}

// setupSSHD writes the sshd drop-in pointing authkeys at the installed binary,
// state dir, and socket, then validates and reloads. Failures degrade to a
// printed, actionable message rather than aborting.
func setupSSHD(sshUser, stateDir, socket, binaryPath string) {
	if ok, err := daemon.HasInclude(""); err != nil {
		fmt.Fprintf(os.Stderr, "warning: cannot read sshd_config: %v\n", err)
	} else if !ok {
		fmt.Fprintln(os.Stderr, "warning: sshd_config does not Include the drop-in dir; add: Include /etc/ssh/sshd_config.d/*.conf")
	}

	path, err := daemon.WriteDropIn("", binaryPath, sshUser, stateDir, socket)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sshd not configured: %v\n", err)
		printManualSSHD(binaryPath, sshUser, stateDir, socket)
		return
	}
	if err := daemon.Validate(); err != nil {
		daemon.RemoveDropIn("")
		fmt.Fprintf(os.Stderr, "sshd config invalid, rolled back: %v\n", err)
		printManualSSHD(binaryPath, sshUser, stateDir, socket)
		return
	}
	if err := daemon.Reload(); err != nil {
		fmt.Fprintf(os.Stderr, "wrote and validated %s, but reload failed; reload sshd manually: %v\n", path, err)
		return
	}
	fmt.Println("sshd configured:", path)
}

func printManualSSHD(binaryPath, sshUser, stateDir, socket string) {
	fmt.Fprintf(os.Stderr, "\nto finish, create %s with:\n\n%s\nthen run: sshd -t && systemctl reload ssh\n",
		daemon.DropInPath(), daemon.DropInContent(binaryPath, sshUser, stateDir, socket))
}

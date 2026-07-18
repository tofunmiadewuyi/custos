package daemon

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	sshDir     = "/etc/ssh"
	dropInName = "70-custos.conf"
)

// dropInContent points sshd's AuthorizedKeysCommand at this binary, so sshd
// asks custosd for the authorized keys on every login. The %% escapes produce
// literal %u %t %k tokens that sshd expands to user, key type, and key blob.
func dropInContent(binaryPath, user, stateDir, socket string) string {
	return fmt.Sprintf(`# Managed by custos. Do not edit.
AuthorizedKeysCommand %s authkeys --dir %s --socket %s %%u %%t %%k
AuthorizedKeysCommandUser %s
`, binaryPath, stateDir, socket, user)
}

// DropInContent is the sshd config to place by hand if enroll can't write it.
func DropInContent(binaryPath, user, stateDir, socket string) string {
	return dropInContent(binaryPath, user, stateDir, socket)
}

// DropInPath is where the drop-in file lives.
func DropInPath() string {
	return filepath.Join(sshDir, "sshd_config.d", dropInName)
}

// WriteDropIn writes our config into sshd's drop-in directory. It owns only
// this one file and never touches the main sshd_config. Returns the path.
func WriteDropIn(sshConfigDir, binaryPath, user, stateDir, socket string) (string, error) {
	if sshConfigDir == "" {
		sshConfigDir = sshDir
	}
	path := filepath.Join(sshConfigDir, "sshd_config.d", dropInName)
	if err := atomicWrite(path, []byte(dropInContent(binaryPath, user, stateDir, socket)), 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// RemoveDropIn deletes our drop-in file, for rollback or uninstall.
func RemoveDropIn(dir string) error {
	if dir == "" {
		dir = sshDir
	}
	err := os.Remove(filepath.Join(dir, "sshd_config.d", dropInName))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// HasInclude reports whether the main sshd_config pulls in the drop-in
// directory. Without an active Include line our drop-in is ignored, and the
// admin must add it themselves — the one thing we won't edit for them.
func HasInclude(dir string) (bool, error) {
	if dir == "" {
		dir = sshDir
	}
	data, err := os.ReadFile(filepath.Join(dir, "sshd_config"))
	if err != nil {
		return false, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.TrimSpace(line)
		if f == "" || strings.HasPrefix(f, "#") {
			continue
		}
		if strings.HasPrefix(strings.ToLower(f), "include") && strings.Contains(f, "sshd_config.d") {
			return true, nil
		}
	}
	return false, nil
}

// Validate runs `sshd -t` to check the config parses before a reload, so a bad
// drop-in is caught instead of taking effect.
func Validate() error {
	return exec.Command("sshd", "-t").Run()
}

// Reload asks sshd to re-read its config. The unit is "ssh" on Debian/Ubuntu
// and "sshd" elsewhere, so try both.
func Reload() error {
	if err := exec.Command("systemctl", "reload", "ssh").Run(); err == nil {
		return nil
	}
	return exec.Command("systemctl", "reload", "sshd").Run()
}

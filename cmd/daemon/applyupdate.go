package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/tofunmiadewuyi/custos/internal/daemon"
)

// cmdApplyUpdate runs as root via the unit's `ExecStartPre=+...` before each
// start: if the daemon staged a verified binary, swap it into place, else no-op.
func cmdApplyUpdate(args []string) {
	fs := flag.NewFlagSet("apply-update", flag.ExitOnError)
	dir := fs.String("dir", daemon.DefaultDir, "state directory")
	fs.Parse(args)

	updateDir := filepath.Join(*dir, "update")
	staged := filepath.Join(updateDir, "custosd.staged")
	metaPath := filepath.Join(updateDir, "staged.json")

	if _, err := os.Stat(staged); errors.Is(err, os.ErrNotExist) {
		return // normal boot, nothing staged
	}
	if os.Geteuid() != 0 {
		fatal("apply-update: must run as root")
	}

	meta, err := readMeta(metaPath)
	if err != nil {
		discardStaged(staged, metaPath, "unreadable metadata: %v", err)
		return
	}
	if sum, err := fileSHA256(staged); err != nil || sum != meta.BinSHA256 {
		discardStaged(staged, metaPath, "staged binary failed checksum (got %q want %q, err %v)", sum, meta.BinSHA256, err)
		return
	}
	if err := smokeTest(staged, meta.Version); err != nil {
		discardStaged(staged, metaPath, "staged binary smoke test failed: %v", err)
		return
	}

	// Keep the outgoing binary so a bad release can be rolled back.
	if err := copyFile(installBin, installBin+".prev", 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "apply-update: could not back up current binary: %v\n", err)
	}
	if err := replaceExecutable(staged, installBin); err != nil {
		fatal("apply-update: swap failed (keeping current): %v", err)
	}

	os.Remove(staged)
	os.Remove(metaPath)
	fmt.Println("apply-update: applied", meta.Version)
}

func readMeta(path string) (daemon.StagedMeta, error) {
	var m daemon.StagedMeta
	data, err := os.ReadFile(path)
	if err != nil {
		return m, err
	}
	return m, json.Unmarshal(data, &m)
}

// smokeTest runs the staged binary's version command and confirms it reports the
// expected version, so a corrupt/wrong-arch binary never replaces a working one.
func smokeTest(bin, want string) error {
	out, err := exec.Command(bin, "version").CombinedOutput()
	if err != nil {
		return err
	}
	if !strings.Contains(string(out), want) {
		return fmt.Errorf("reported %q, expected %s", strings.TrimSpace(string(out)), want)
	}
	return nil
}

// replaceExecutable atomically swaps dest for the bytes at src. src may be on a
// different filesystem, so it is copied to a temp beside dest, then renamed.
func replaceExecutable(src, dest string) error {
	tmp := dest + ".new"
	if err := copyFile(src, tmp, 0o755); err != nil {
		return err
	}
	if err := os.Rename(tmp, dest); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func copyFile(src, dest string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Chmod(dest, perm)
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// discardStaged removes a staged update that can't be trusted, so the daemon
// starts on the current binary and the bad update isn't retried every restart.
func discardStaged(staged, meta, format string, args ...any) {
	fmt.Fprintf(os.Stderr, "apply-update: "+format+"\n", args...)
	os.Remove(staged)
	os.Remove(meta)
}

package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/tofunmiadewuyi/custos/internal/daemon"
)

func cmdRun(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	dir := fs.String("dir", daemon.DefaultDir, "state directory")
	socket := fs.String("socket", daemon.DefaultSocket, "authkeys socket path")
	secretSocket := fs.String("secret-socket", daemon.DefaultSecretSocket, "secrets socket path (custosd exec)")
	fs.Parse(args)

	store, err := daemon.OpenStore(*dir)
	if err != nil {
		fatal("run: %v", err)
	}
	if !store.Enrolled() {
		fatal("run: not enrolled; run `custosd enroll` first")
	}
	cfg, err := store.LoadConfig()
	if err != nil {
		fatal("run: %v", err)
	}
	id, err := store.LoadIdentity()
	if err != nil {
		fatal("run: %v", err)
	}
	cache, err := store.LoadCache()
	if err != nil {
		fatal("run: %v", err)
	}
	encKey, err := store.LoadEncryptionKey()
	if err != nil {
		log.Printf("run: no encryption key (%v); machine secrets disabled", err)
	}

	// Keep secrets off swap and out of core dumps before any land in memory.
	hardenMemory()

	ln, err := listenSocket(*socket, 0o600)
	if err != nil {
		fatal("run: %v", err)
	}
	defer ln.Close()

	// The secrets socket needs app service users to reach it (custosd exec runs as
	// them), so 0660 + the custos group, not the authkeys socket's 0600.
	sln, err := listenSocket(*secretSocket, 0o660)
	if err != nil {
		fatal("run: %v", err)
	}
	defer sln.Close()

	secrets := daemon.NewSecretStore(encKey)
	client := daemon.NewClient(cfg, id, cache, secrets, version, filepath.Join(*dir, "update"))
	go daemon.ServeAuth(ln, cache, client.RecordAccess)
	go daemon.ServeSecrets(sln, secrets, client.RecordSecretRead)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Printf("custosd running: host %s, %d keys cached", cfg.HostID, cache.Len())
	err = client.Run(ctx)
	if errors.Is(err, daemon.ErrRestart) {
		log.Print("exiting to apply staged upgrade; systemd will restart")
		return // exit 0; ExecStartPre applies the staged binary on restart
	}
	if err != nil && ctx.Err() == nil {
		fatal("run: %v", err)
	}
}

// listenSocket binds the unix socket at path with the given mode, replacing any
// stale file left by a crash.
func listenSocket(path string, mode os.FileMode) (net.Listener, error) {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, mode); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

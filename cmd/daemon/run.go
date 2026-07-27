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
	socket := fs.String("socket", daemon.DefaultSocket, "daemon socket path")
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

	ln, err := listenSocket(*socket)
	if err != nil {
		fatal("run: %v", err)
	}
	defer ln.Close()

	client := daemon.NewClient(cfg, id, cache, version, filepath.Join(*dir, "update"))
	go daemon.ServeAuth(ln, cache, client.RecordAccess)

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

// listenSocket binds the unix socket, replacing any stale file left by a crash,
// and restricts it to the daemon user (authkeys runs as the same user).
func listenSocket(path string) (net.Listener, error) {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

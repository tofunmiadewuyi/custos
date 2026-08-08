package daemon

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os/user"
	"strconv"
	"strings"
	"time"

	"github.com/tofunmiadewuyi/custos/internal/protocol"
)

// DefaultSecretSocket is where the daemon serves secret sets to custosd exec.
// It lives in the systemd RuntimeDirectory (/run/custos), the only place the
// custos-user daemon can bind a socket.
const DefaultSecretSocket = "/run/custos/secrets.sock"

type secretResponse struct {
	OK     bool              `json:"ok"`
	Error  string            `json:"error,omitempty"`
	Values map[string]string `json:"values,omitempty"`
}

// ServeSecrets answers set requests on ln until it is closed. The only client is
// custosd exec: a request is one line naming a set, the reply is JSON. onRead, if
// set, receives every successful serve for machine-read audit.
func ServeSecrets(ln net.Listener, store *SecretStore, onRead func(protocol.SecretRead)) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go handleSecret(conn, store, onRead)
	}
}

func handleSecret(conn net.Conn, store *SecretStore, onRead func(protocol.SecretRead)) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))

	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return
	}
	name := strings.TrimSpace(line)

	values, asUser, ok := store.Get(name)
	if !ok {
		if !store.Ready() {
			writeSecret(conn, secretResponse{Error: "not ready"})
			return
		}
		writeSecret(conn, secretResponse{Error: "no such set"})
		return
	}
	// Scoped sets: the caller's kernel-verified uid must match as_user.
	if asUser != "" && !callerIs(conn, asUser) {
		log.Printf("secrets: denied set %q (caller uid does not match as_user %q)", name, asUser)
		writeSecret(conn, secretResponse{Error: "forbidden"})
		return
	}
	writeSecret(conn, secretResponse{OK: true, Values: values})
	if onRead != nil {
		onRead(protocol.SecretRead{SetName: name, At: time.Now()})
	}
}

func writeSecret(conn net.Conn, resp secretResponse) {
	json.NewEncoder(conn).Encode(resp)
}

// callerIs reports whether the socket peer's uid resolves to the named unix user.
func callerIs(conn net.Conn, username string) bool {
	uid, err := peerUID(conn)
	if err != nil {
		return false
	}
	u, err := user.Lookup(username)
	if err != nil {
		return false
	}
	return u.Uid == strconv.FormatUint(uint64(uid), 10)
}

// FetchSet asks the daemon for a set's values, retrying transient failures (the
// daemon still syncing, socket not up) until timeout. A forbidden reply is final.
func FetchSet(socket, name string, timeout time.Duration) (map[string]string, error) {
	deadline := time.Now().Add(timeout)
	for {
		values, retry, err := fetchSetOnce(socket, name)
		if err == nil {
			return values, nil
		}
		if !retry || time.Now().After(deadline) {
			return nil, err
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func fetchSetOnce(socket, name string) (map[string]string, bool, error) {
	conn, err := net.DialTimeout("unix", socket, 2*time.Second)
	if err != nil {
		return nil, true, err // daemon not up yet; retry
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))

	if _, err := fmt.Fprintf(conn, "%s\n", name); err != nil {
		return nil, true, err
	}
	var resp secretResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, true, err
	}
	if resp.OK {
		return resp.Values, false, nil
	}
	if resp.Error == "forbidden" {
		return nil, false, errors.New("forbidden") // final; do not retry
	}
	if resp.Error == "no such set" {
		return nil, false, errors.New("no such set") // synced; typo/missing set is final
	}
	return nil, true, errors.New(resp.Error) // e.g. not synced yet; retry
}

package daemon

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/tofunmiadewuyi/custos/internal/protocol"
)

// DefaultSocket is where the daemon listens for authkeys queries.
const DefaultSocket = "/run/custosd.sock"

// ServeAuth answers authkeys queries on ln until it is closed. Each query is a
// single line "fingerprint\taccount"; the reply is the authorized_keys line if
// the key may log in as that account, or nothing to deny. onAccess, if set,
// receives every decision for audit logging.
func ServeAuth(ln net.Listener, cache *Cache, onAccess func(protocol.AccessLog)) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go handleAuth(conn, cache, onAccess)
	}
}

func handleAuth(conn net.Conn, cache *Cache, onAccess func(protocol.AccessLog)) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))

	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return
	}
	fingerprint, account, ok := strings.Cut(strings.TrimRight(line, "\n"), "\t")
	if !ok {
		return
	}

	entry, allowed := authorize(cache, fingerprint, account)
	if allowed {
		fmt.Fprintf(conn, "%s %s\n", entry.KeyType, entry.KeyBlob)
	}
	if onAccess != nil {
		onAccess(protocol.AccessLog{
			Fingerprint: fingerprint,
			Account:     account,
			Allowed:     allowed,
			At:          time.Now(),
		})
	}
}

// authorize returns the cached entry and whether the key may log in as account.
func authorize(cache *Cache, fingerprint, account string) (protocol.AccessEntry, bool) {
	entry, ok := cache.Lookup(fingerprint)
	if !ok {
		return protocol.AccessEntry{}, false
	}
	for _, a := range entry.Accounts {
		if a == account {
			return entry, true
		}
	}
	return protocol.AccessEntry{}, false
}

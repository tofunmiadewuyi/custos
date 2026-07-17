package daemon

import (
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/tofunmiadewuyi/custos/internal/sshkey"
)

// AuthorizedKey returns the authorized_keys line for a login attempt, or "" to
// deny. It asks the running daemon over the socket (retrying, since a login must
// not fail just because the daemon is briefly busy); if the socket stays
// unreachable it falls back to the last-known-good cache on disk, so logins
// survive a dead daemon.
func AuthorizedKey(socketPath string, store *Store, keyType, keyBlob, account string) (string, error) {
	fingerprint, err := sshkey.Fingerprint(keyBlob)
	if err != nil {
		return "", err
	}
	if line, ok := querySocket(socketPath, fingerprint, account); ok {
		return line, nil
	}
	return authorizeFromDisk(store, fingerprint, account)
}

// querySocket asks the daemon and reports whether it got an answer. A definitive
// deny (empty reply) counts as an answer; only transport failures do not.
func querySocket(socketPath, fingerprint, account string) (line string, ok bool) {
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(100 * time.Millisecond)
		}
		conn, err := net.DialTimeout("unix", socketPath, 300*time.Millisecond)
		if err != nil {
			continue
		}
		conn.SetDeadline(time.Now().Add(2 * time.Second))

		if _, err := fmt.Fprintf(conn, "%s\t%s\n", fingerprint, account); err != nil {
			conn.Close()
			continue
		}
		data, err := io.ReadAll(conn)
		conn.Close()
		if err != nil {
			continue
		}
		return strings.TrimRight(string(data), "\n"), true
	}
	return "", false
}

func authorizeFromDisk(store *Store, fingerprint, account string) (string, error) {
	cache, err := store.LoadCache()
	if err != nil {
		return "", err
	}
	entry, allowed := authorize(cache, fingerprint, account)
	if !allowed {
		return "", nil
	}
	return fmt.Sprintf("%s %s", entry.KeyType, entry.KeyBlob), nil
}

//go:build !linux

package daemon

import (
	"errors"
	"net"
)

// peerUID is unsupported off Linux, so scoped sets can't be served there.
func peerUID(net.Conn) (uint32, error) {
	return 0, errors.New("peer credentials unsupported on this platform")
}

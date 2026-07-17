// Package sshkey holds SSH public-key helpers shared by the daemon and the
// control plane.
package sshkey

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// Fingerprint returns the OpenSSH SHA256 fingerprint of a base64 key blob (the
// middle field of an authorized_keys line), e.g. "SHA256:KCcR...". It matches
// `ssh-keygen -lf`: the hash is over the raw key bytes, which already encode
// the key type, so the type is not needed here.
func Fingerprint(blob string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(blob)
	if err != nil {
		return "", fmt.Errorf("invalid key blob: %w", err)
	}
	sum := sha256.Sum256(raw)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]), nil
}

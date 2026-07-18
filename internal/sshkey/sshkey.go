// Package sshkey holds SSH public-key helpers shared by the daemon and the
// control plane.
package sshkey

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// ParseAuthorizedKey splits an authorized_keys line into its type and base64 blob.
func ParseAuthorizedKey(line string) (keyType, blob string, err error) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return "", "", errors.New("invalid authorized key")
	}
	if _, err := base64.StdEncoding.DecodeString(fields[1]); err != nil {
		return "", "", errors.New("invalid key blob")
	}
	return fields[0], fields[1], nil
}

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

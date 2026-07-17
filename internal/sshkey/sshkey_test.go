package sshkey

import "testing"

func TestFingerprintMatchesOpenSSH(t *testing.T) {
	// Golden vector produced by `ssh-keygen -lf` on a real ed25519 key.
	const (
		blob = "AAAAC3NzaC1lZDI1NTE5AAAAIF79/jbso5ZK5Lvu2nbla+Ba7nMgnFIiTRc+G1hohsYO"
		want = "SHA256:KCcRgYXrek07AU5Sr8Uy/cTjHh/EjelltqNXfmHrVWc"
	)
	got, err := Fingerprint(blob)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("Fingerprint = %q, want %q", got, want)
	}
}

func TestFingerprintRejectsGarbage(t *testing.T) {
	if _, err := Fingerprint("not base64!!!"); err == nil {
		t.Fatal("expected error on invalid blob")
	}
}

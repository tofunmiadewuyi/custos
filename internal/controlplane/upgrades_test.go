package controlplane

import (
	"strings"
	"testing"
)

func TestParseChecksums(t *testing.T) {
	const version = "v1.2.0"
	body := strings.Join([]string{
		"aaa  custosd_v1.2.0_linux_amd64.tar.gz",
		"bbb  custosd_v1.2.0_linux_arm64.tar.gz",
		"ccc  custosd_v1.2.0_checksums.txt", // ignored
	}, "\n")

	m, err := parseChecksums(strings.NewReader(body), version)
	if err != nil {
		t.Fatal(err)
	}
	if m["amd64"] != "aaa" || m["arm64"] != "bbb" {
		t.Fatalf("bad map: %+v", m)
	}
	if len(m) != 2 {
		t.Fatalf("expected 2 arches, got %d", len(m))
	}
}

func TestParseChecksumsEmpty(t *testing.T) {
	if _, err := parseChecksums(strings.NewReader("xyz  unrelated.txt"), "v1.2.0"); err == nil {
		t.Fatal("expected error when no custosd digests present")
	}
}

func TestVersionRe(t *testing.T) {
	ok := []string{"v1.2.3", "v0.0.1", "v10.20.30"}
	bad := []string{"1.2.3", "v1.2", "v1.2.3-rc1", "latest", "", "v1.2.3 "}
	for _, s := range ok {
		if !versionRe.MatchString(s) {
			t.Errorf("%q should be valid", s)
		}
	}
	for _, s := range bad {
		if versionRe.MatchString(s) {
			t.Errorf("%q should be invalid", s)
		}
	}
}

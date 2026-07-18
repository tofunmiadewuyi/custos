package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteDropIn(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "sshd_config.d"), 0o755); err != nil {
		t.Fatal(err)
	}

	path, err := WriteDropIn(dir, "/usr/local/bin/custosd", "custos", "/var/lib/custos", "/run/custosd.sock")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	for _, want := range []string{
		"AuthorizedKeysCommand /usr/local/bin/custosd authkeys --dir /var/lib/custos --socket /run/custosd.sock %u %t %k",
		"AuthorizedKeysCommandUser custos",
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("drop-in missing %q, got:\n%s", want, content)
		}
	}

	if err := RemoveDropIn(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("drop-in should be gone after RemoveDropIn")
	}
	// RemoveDropIn is idempotent.
	if err := RemoveDropIn(dir); err != nil {
		t.Fatalf("second remove should be a no-op, got %v", err)
	}
}

func TestHasInclude(t *testing.T) {
	cases := map[string]bool{
		"Include /etc/ssh/sshd_config.d/*.conf\n": true,
		"  Include /etc/ssh/sshd_config.d/*.conf": true,
		"# Include /etc/ssh/sshd_config.d/*.conf": false,
		"Port 22\n":                               false,
		"":                                        false,
	}
	for content, want := range cases {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "sshd_config"), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		got, err := HasInclude(dir)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("HasInclude(%q) = %v, want %v", content, got, want)
		}
	}
}

package daemon

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/tofunmiadewuyi/custos/internal/protocol"
)

// tarball builds a gzip'd tar containing a single "custosd" entry with body.
func tarball(t *testing.T, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "custosd", Mode: 0o755, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func sha(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func newTestClient(t *testing.T) *Client {
	t.Helper()
	store, _ := OpenStore(t.TempDir())
	cache, _ := store.LoadCache()
	return NewClient(Config{HostID: "h"}, nil, cache, nil, "v1.0.0", filepath.Join(t.TempDir(), "update"))
}

func TestStageUpgrade(t *testing.T) {
	binBody := []byte("new custosd binary bytes")
	tar := tarball(t, binBody)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(tar)
	}))
	defer srv.Close()

	c := newTestClient(t)
	// Point the download at the test server by overriding the URL builder isn't
	// possible, so verify via the exported stage path using a fake tarball URL.
	up := protocol.Upgrade{Version: "v1.1.0", SHA256: map[string]string{runtime.GOARCH: sha(tar)}}
	if err := c.stageUpgradeFrom(t.Context(), up, srv.URL); err != nil {
		t.Fatalf("stageUpgrade: %v", err)
	}

	staged := filepath.Join(c.updateDir, stagedBin)
	got, err := os.ReadFile(staged)
	if err != nil {
		t.Fatalf("staged binary missing: %v", err)
	}
	if !bytes.Equal(got, binBody) {
		t.Fatal("staged binary body mismatch")
	}

	metaRaw, err := os.ReadFile(filepath.Join(c.updateDir, stagedMeta))
	if err != nil {
		t.Fatalf("staged meta missing: %v", err)
	}
	var meta StagedMeta
	if err := json.Unmarshal(metaRaw, &meta); err != nil {
		t.Fatal(err)
	}
	if meta.Version != "v1.1.0" || meta.BinSHA256 != sha(binBody) {
		t.Fatalf("bad meta: %+v", meta)
	}
}

func TestStageUpgradeChecksumMismatch(t *testing.T) {
	tar := tarball(t, []byte("body"))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(tar)
	}))
	defer srv.Close()

	c := newTestClient(t)
	up := protocol.Upgrade{Version: "v1.1.0", SHA256: map[string]string{runtime.GOARCH: sha([]byte("wrong"))}}
	if err := c.stageUpgradeFrom(t.Context(), up, srv.URL); err == nil {
		t.Fatal("expected checksum mismatch error")
	}
	if _, err := os.Stat(filepath.Join(c.updateDir, stagedBin)); !os.IsNotExist(err) {
		t.Fatal("nothing should be staged on mismatch")
	}
}

func TestStageUpgradeNoArch(t *testing.T) {
	c := newTestClient(t)
	up := protocol.Upgrade{Version: "v1.1.0", SHA256: map[string]string{"nonsense-arch": "x"}}
	if err := c.stageUpgradeFrom(t.Context(), up, "http://unused"); err == nil {
		t.Fatal("expected error for missing arch checksum")
	}
}

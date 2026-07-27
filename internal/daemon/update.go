package daemon

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/tofunmiadewuyi/custos/internal/protocol"
)

const releaseRepo = "tofunmiadewuyi/custos"

const (
	stagedBin  = "custosd.staged"
	stagedMeta = "staged.json"
)

const downloadTimeout = 5 * time.Minute

// StagedMeta records what apply-update needs to re-verify the staged binary.
type StagedMeta struct {
	Version   string `json:"version"`
	BinSHA256 string `json:"bin_sha256"`
}

// tarballURL is the release asset for a version+arch, matching install.sh.
func tarballURL(version, arch string) string {
	name := fmt.Sprintf("custosd_%s_linux_%s.tar.gz", version, arch)
	return fmt.Sprintf("https://github.com/%s/releases/download/custosd/%s/%s", releaseRepo, version, name)
}

// stageUpgrade downloads the target tarball, verifies it against the control
// plane's digest, extracts custosd, and stages it for the root apply-update step.
func (c *Client) stageUpgrade(ctx context.Context, up protocol.Upgrade) error {
	return c.stageUpgradeFrom(ctx, up, tarballURL(up.Version, runtime.GOARCH))
}

// stageUpgradeFrom is stageUpgrade with an explicit tarball URL (for tests).
func (c *Client) stageUpgradeFrom(ctx context.Context, up protocol.Upgrade, url string) error {
	arch := runtime.GOARCH
	want := up.SHA256[arch]
	if want == "" {
		return fmt.Errorf("no checksum for arch %s", arch)
	}
	if err := os.MkdirAll(c.updateDir, 0o700); err != nil {
		return err
	}

	tarPath, err := c.download(ctx, url, want)
	if err != nil {
		return err
	}
	defer os.Remove(tarPath)

	binTmp, binSHA, err := c.extractBinary(tarPath)
	if err != nil {
		return err
	}
	defer os.Remove(binTmp) // no-op once renamed

	meta, err := json.Marshal(StagedMeta{Version: up.Version, BinSHA256: binSHA})
	if err != nil {
		return err
	}
	if err := atomicWrite(filepath.Join(c.updateDir, stagedMeta), meta, 0o600); err != nil {
		return err
	}
	// Rename the binary in last; apply-update keys off its presence.
	return os.Rename(binTmp, filepath.Join(c.updateDir, stagedBin))
}

// download streams url to a temp file, checking its sha256 against want.
func (c *Client) download(ctx context.Context, url, want string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, downloadTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download %s: HTTP %d", url, resp.StatusCode)
	}

	tmp, err := os.CreateTemp(c.updateDir, "dl-*.tar.gz")
	if err != nil {
		return "", err
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, h), resp.Body); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", err
	}
	tmp.Close()

	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		os.Remove(tmp.Name())
		return "", fmt.Errorf("checksum mismatch: got %s want %s", got, want)
	}
	return tmp.Name(), nil
}

// extractBinary pulls the custosd entry out of the tarball into a temp file and
// returns its path and sha256.
func (c *Client) extractBinary(tarPath string) (path, sum string, err error) {
	f, err := os.Open(tarPath)
	if err != nil {
		return "", "", err
	}
	defer f.Close()
	gzr, err := gzip.NewReader(f)
	if err != nil {
		return "", "", err
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return "", "", fmt.Errorf("custosd not found in archive")
		}
		if err != nil {
			return "", "", err
		}
		if hdr.Name != "custosd" {
			continue
		}
		out, err := os.CreateTemp(c.updateDir, "bin-*")
		if err != nil {
			return "", "", err
		}
		h := sha256.New()
		if _, err := io.Copy(io.MultiWriter(out, h), tr); err != nil {
			out.Close()
			os.Remove(out.Name())
			return "", "", err
		}
		out.Close()
		if err := os.Chmod(out.Name(), 0o755); err != nil {
			os.Remove(out.Name())
			return "", "", err
		}
		return out.Name(), hex.EncodeToString(h.Sum(nil)), nil
	}
}

package controlplane

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tofunmiadewuyi/custos/internal/controlplane/db"
	"github.com/tofunmiadewuyi/custos/internal/protocol"
)

const upgradeRepo = "tofunmiadewuyi/custos"

var upgradeArches = []string{"amd64", "arm64"}

var versionRe = regexp.MustCompile(`^v\d+\.\d+\.\d+$`)

// resolveChecksums returns arch -> tarball digest for a release, reading the
// published checksums file once per version and caching the result.
func (s *Server) resolveChecksums(ctx context.Context, version string) (map[string]string, error) {
	s.checksumMu.Lock()
	defer s.checksumMu.Unlock()
	if m, ok := s.checksums[version]; ok {
		return m, nil
	}

	url := fmt.Sprintf("https://github.com/%s/releases/download/custosd/%s/custosd_%s_checksums.txt", upgradeRepo, version, version)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch checksums for %s: HTTP %d", version, resp.StatusCode)
	}

	m, err := parseChecksums(resp.Body, version)
	if err != nil {
		return nil, err
	}
	s.checksums[version] = m
	return m, nil
}

// parseChecksums maps each arch to its digest from lines of "<sha>  <filename>".
func parseChecksums(r io.Reader, version string) (map[string]string, error) {
	want := map[string]string{}
	for _, arch := range upgradeArches {
		want[fmt.Sprintf("custosd_%s_linux_%s.tar.gz", version, arch)] = arch
	}
	out := map[string]string{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) != 2 {
			continue
		}
		if arch, ok := want[fields[1]]; ok {
			out[arch] = fields[0]
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no custosd tarball digests in checksums for %s", version)
	}
	return out, nil
}

// buildUpgrade assembles the Upgrade message for a target version.
func (s *Server) buildUpgrade(ctx context.Context, version string) (protocol.Upgrade, error) {
	sums, err := s.resolveChecksums(ctx, version)
	if err != nil {
		return protocol.Upgrade{}, err
	}
	return protocol.Upgrade{Version: version, SHA256: sums}, nil
}

type upgradeRequest struct {
	Version string `json:"version"`
}

type upgradeOutcome struct {
	HostID   string `json:"host_id"`
	Hostname string `json:"hostname"`
	Outcome  string `json:"outcome"` // pushed | already-current | offline-queued
}

func (s *Server) handleUpgradeHost(w http.ResponseWriter, r *http.Request) {
	auth := authFrom(r.Context())
	hostID, err := parseUUID(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid host id", http.StatusBadRequest)
		return
	}
	if !s.canHost(r.Context(), auth, "host.upgrade", hostID) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	var req upgradeRequest
	if err := s.readRequest(r, &req); err != nil || !versionRe.MatchString(req.Version) {
		http.Error(w, "version must look like vX.Y.Z", http.StatusBadRequest)
		return
	}
	host, err := s.q.GetHostByID(r.Context(), hostID)
	if err != nil {
		http.Error(w, "host not found", http.StatusNotFound)
		return
	}
	if host.Status != "active" {
		http.Error(w, "host not active", http.StatusConflict)
		return
	}
	up, err := s.buildUpgrade(r.Context(), req.Version)
	if err != nil {
		serverError(w, "could not resolve release", err)
		return
	}
	out := s.pushUpgrade(r.Context(), host.ID, host.Hostname, host.AgentVersion, req.Version, up)
	s.writeResponse(w, authFrom(r.Context()).ClientPublicKey, out)
}

func (s *Server) handleUpgradeFleet(w http.ResponseWriter, r *http.Request) {
	var req upgradeRequest
	if err := s.readRequest(r, &req); err != nil || !versionRe.MatchString(req.Version) {
		http.Error(w, "version must look like vX.Y.Z", http.StatusBadRequest)
		return
	}
	up, err := s.buildUpgrade(r.Context(), req.Version)
	if err != nil {
		serverError(w, "could not resolve release", err)
		return
	}
	hosts, err := s.q.ListActiveHosts(r.Context())
	if err != nil {
		serverError(w, "could not list hosts", err)
		return
	}
	results := make([]upgradeOutcome, 0, len(hosts))
	for _, h := range hosts {
		results = append(results, s.pushUpgrade(r.Context(), h.ID, h.Hostname, h.AgentVersion, req.Version, up))
	}
	s.writeResponse(w, authFrom(r.Context()).ClientPublicKey, results)
}

// pushUpgrade records the desired version and delivers the Upgrade to a live
// daemon; offline hosts pick it up on reconnect. Idempotent per host.
func (s *Server) pushUpgrade(ctx context.Context, id pgtype.UUID, hostname, current, target string, up protocol.Upgrade) upgradeOutcome {
	out := upgradeOutcome{HostID: uuidString(id), Hostname: hostname}
	if current == target {
		out.Outcome = "already-current"
		return out
	}
	if err := s.q.SetHostDesiredVersion(ctx, db.SetHostDesiredVersionParams{ID: id, DesiredVersion: target}); err != nil {
		out.Outcome = "error"
		return out
	}
	env, err := protocol.NewEnvelope(protocol.TypeUpgrade, up)
	if err != nil {
		out.Outcome = "error"
		return out
	}
	if s.hub.online(uuidString(id)) {
		s.hub.push(uuidString(id), env)
		out.Outcome = "pushed"
	} else {
		out.Outcome = "offline-queued"
	}
	return out
}

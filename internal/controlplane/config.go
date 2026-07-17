// Package controlplane is the custos API server
package controlplane

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

const (
	envDatabaseURL = "CUSTOS_DATABASE_URL"
	envListenAddr  = "CUSTOS_LISTEN_ADDR"
	envMasterKey   = "CUSTOS_MASTER_KEY"
	envHybridKey   = "CUSTOS_HYBRID_PRIVATE_KEY"

	defaultListenAddr = ":8080"
	keySize           = 32
)

// Config is the control plane's runtime configuration, loaded from the
// environment once at startup.
type Config struct {
	DatabaseURL      string
	ListenAddr       string
	MasterKey        []byte // vault master key
	HybridPrivateKey []byte // server X25519 private key
}

// LoadConfig reads and validates configuration from the environment. It reports
// every problem at once rather than one at a time.
func LoadConfig() (Config, error) {
	var cfg Config
	var missing []string

	cfg.DatabaseURL = os.Getenv(envDatabaseURL)
	if cfg.DatabaseURL == "" {
		missing = append(missing, envDatabaseURL)
	}

	cfg.ListenAddr = os.Getenv(envListenAddr)
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = defaultListenAddr
	}

	masterKey, err := decodeKey(envMasterKey)
	if err != nil {
		return Config{}, err
	}
	if masterKey == nil {
		missing = append(missing, envMasterKey)
	}
	cfg.MasterKey = masterKey

	hybridKey, err := decodeKey(envHybridKey)
	if err != nil {
		return Config{}, err
	}
	if hybridKey == nil {
		missing = append(missing, envHybridKey)
	}
	cfg.HybridPrivateKey = hybridKey

	if len(missing) > 0 {
		return Config{}, fmt.Errorf("missing required env vars: %s", strings.Join(missing, ", "))
	}
	return cfg, nil
}

// decodeKey returns nil (no error) when the var is unset, so the caller can
// collect it as missing; a set-but-malformed key is an error.
func decodeKey(env string) ([]byte, error) {
	raw := os.Getenv(env)
	if raw == "" {
		return nil, nil
	}
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: invalid base64: %w", env, err)
	}
	if len(key) != keySize {
		return nil, fmt.Errorf("%s: must decode to %d bytes, got %d", env, keySize, len(key))
	}
	return key, nil
}

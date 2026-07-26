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
	envSigningKey  = "CUSTOS_SIGNING_PRIVATE_KEY"
	envClientKey   = "CUSTOS_CLIENT_PRIVATE_KEY"
	envEncryption  = "CUSTOS_ENCRYPTION"
	envEmailFrom   = "CUSTOS_EMAIL_FROM"
	envAppURL      = "CUSTOS_APP_URL"
	envCorsOrigins = "CUSTOS_CORS_ORIGINS"
	envResendKey   = "RESEND_API_KEY"

	defaultListenAddr = ":8080"
	keySize           = 32
)

type Config struct {
	DatabaseURL       string
	ListenAddr        string
	MasterKey         []byte
	SigningKey        string
	HybridPrivateKey  []byte
	EncryptionEnabled bool
	ResendAPIKey      string
	EmailFrom         string
	AppURL            string
	CorsOrigins       []string // allowed browser origins; empty → allow all (dev)
}

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

	cfg.SigningKey = os.Getenv(envSigningKey)
	if cfg.SigningKey == "" {
		missing = append(missing, envSigningKey)
	}

	cfg.EncryptionEnabled = envEnabled(envEncryption, true)
	cfg.ResendAPIKey = os.Getenv(envResendKey)
	cfg.EmailFrom = os.Getenv(envEmailFrom)
	cfg.AppURL = os.Getenv(envAppURL)
	cfg.CorsOrigins = splitCSV(os.Getenv(envCorsOrigins))

	clientKey, err := decodeKey(envClientKey)
	if err != nil {
		return Config{}, err
	}
	if cfg.EncryptionEnabled && clientKey == nil {
		missing = append(missing, envClientKey)
	}
	cfg.HybridPrivateKey = clientKey

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

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func envEnabled(key string, def bool) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "":
		return def
	case "0", "false", "off", "no":
		return false
	default:
		return true
	}
}

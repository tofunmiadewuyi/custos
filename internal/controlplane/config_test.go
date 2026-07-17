package controlplane

import (
	"encoding/base64"
	"strings"
	"testing"
)

func setValidKeys(t *testing.T) {
	t.Helper()
	key := base64.StdEncoding.EncodeToString(make([]byte, keySize))
	t.Setenv(envMasterKey, key)
	t.Setenv(envHybridKey, key)
}

func TestLoadConfigDefaults(t *testing.T) {
	t.Setenv(envDatabaseURL, "postgres://localhost/custos")
	setValidKeys(t)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ListenAddr != defaultListenAddr {
		t.Fatalf("ListenAddr = %q, want default %q", cfg.ListenAddr, defaultListenAddr)
	}
	if len(cfg.MasterKey) != keySize || len(cfg.HybridPrivateKey) != keySize {
		t.Fatal("keys not decoded to expected length")
	}
}

func TestLoadConfigReportsAllMissing(t *testing.T) {
	t.Setenv(envDatabaseURL, "")
	t.Setenv(envMasterKey, "")
	t.Setenv(envHybridKey, "")

	_, err := LoadConfig()
	if err == nil {
		t.Fatal("expected error when required vars are missing")
	}
	for _, want := range []string{envDatabaseURL, envMasterKey, envHybridKey} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %s, got: %v", want, err)
		}
	}
}

func TestLoadConfigRejectsBadKey(t *testing.T) {
	t.Setenv(envDatabaseURL, "postgres://localhost/custos")
	t.Setenv(envHybridKey, base64.StdEncoding.EncodeToString(make([]byte, keySize)))

	t.Setenv(envMasterKey, "not-base64!!!")
	if _, err := LoadConfig(); err == nil {
		t.Fatal("expected error on invalid base64 key")
	}

	t.Setenv(envMasterKey, base64.StdEncoding.EncodeToString(make([]byte, 16))) // wrong length
	if _, err := LoadConfig(); err == nil {
		t.Fatal("expected error on wrong-length key")
	}
}

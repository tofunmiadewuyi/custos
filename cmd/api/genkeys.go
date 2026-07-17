package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/tofunmiadewuyi/custos/internal/hybrid"
)

func cmdGenKeys(args []string) {
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		fatal("gen-keys: %v", err)
	}
	priv, pub, err := hybrid.GenerateKeyPair()
	if err != nil {
		fatal("gen-keys: %v", err)
	}
	enc := base64.StdEncoding.EncodeToString

	fmt.Println("# control-plane environment:")
	fmt.Printf("CUSTOS_MASTER_KEY=%s\n", enc(master))
	fmt.Printf("CUSTOS_HYBRID_PRIVATE_KEY=%s\n", enc(priv))
	fmt.Println("# embed in the frontend:")
	fmt.Printf("HYBRID_PUBLIC_KEY=%s\n", enc(pub))
}

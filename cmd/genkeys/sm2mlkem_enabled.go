//go:build sm2mlkem

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/qs3c/e2e-secure-ws/crypto/sm2mlkem"
)

const (
	sm2MLKEMPrivateKeyFile = "sm2mlkem_private.bin"
	sm2MLKEMPublicKeyFile  = "sm2mlkem_public.bin"
)

func generateSM2MLKEMKeyFiles(dir string, force bool) error {
	providerPath := os.Getenv("TONGSUO_PQ_PROVIDER_PATH")
	if providerPath == "" {
		providerPath = sm2mlkem.DefaultProviderPath()
	}
	if err := sm2mlkem.Init(providerPath); err != nil {
		return fmt.Errorf("initialize SM2MLKEM provider: %w", err)
	}

	key, err := sm2mlkem.GenerateKey()
	if err != nil {
		return fmt.Errorf("generate SM2MLKEM key: %w", err)
	}
	defer key.Close()

	priv, err := key.ExportPrivateKey()
	if err != nil {
		return fmt.Errorf("export SM2MLKEM private key: %w", err)
	}
	if len(priv) != sm2mlkem.PrivateKeySize {
		return fmt.Errorf("SM2MLKEM private key length = %d, want %d", len(priv), sm2mlkem.PrivateKeySize)
	}
	if err := writeKeyFile(filepath.Join(dir, sm2MLKEMPrivateKeyFile), priv, 0o600, force); err != nil {
		return err
	}

	pub, err := key.ExportPublicKey()
	if err != nil {
		return fmt.Errorf("export SM2MLKEM public key: %w", err)
	}
	if len(pub) != sm2mlkem.PublicKeySize {
		return fmt.Errorf("SM2MLKEM public key length = %d, want %d", len(pub), sm2mlkem.PublicKeySize)
	}
	return writeKeyFile(filepath.Join(dir, sm2MLKEMPublicKeyFile), pub, 0o644, force)
}

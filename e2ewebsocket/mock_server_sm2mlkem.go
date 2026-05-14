//go:build sm2mlkem

package e2ewebsocket

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/qs3c/e2e-secure-ws/crypto/sm2mlkem"
)

func setupSM2MLKEMKeyStore(t *testing.T, dir string) {
	t.Helper()

	providerPath := os.Getenv("TONGSUO_PQ_PROVIDER_PATH")
	if providerPath == "" {
		providerPath = sm2mlkem.DefaultProviderPath()
	}
	if err := sm2mlkem.Init(providerPath); err != nil {
		t.Fatalf("initialize SM2MLKEM provider: %v", err)
	}

	key, err := sm2mlkem.GenerateKey()
	if err != nil {
		t.Fatalf("generate SM2MLKEM key: %v", err)
	}
	defer key.Close()

	priv, err := key.ExportPrivateKey()
	if err != nil {
		t.Fatalf("export SM2MLKEM private key: %v", err)
	}
	if len(priv) != sm2mlkem.PrivateKeySize {
		t.Fatalf("SM2MLKEM private key length = %d, want %d", len(priv), sm2mlkem.PrivateKeySize)
	}
	if err := os.WriteFile(filepath.Join(dir, sm2MLKEMPrivateKeyFile), priv, 0o600); err != nil {
		t.Fatal(err)
	}

	pub, err := key.ExportPublicKey()
	if err != nil {
		t.Fatalf("export SM2MLKEM public key: %v", err)
	}
	if len(pub) != sm2mlkem.PublicKeySize {
		t.Fatalf("SM2MLKEM public key length = %d, want %d", len(pub), sm2mlkem.PublicKeySize)
	}
	if err := os.WriteFile(filepath.Join(dir, sm2MLKEMPublicKeyFile), pub, 0o644); err != nil {
		t.Fatal(err)
	}

	t.Logf("wrote %s and %s", sm2MLKEMPrivateKeyFile, sm2MLKEMPublicKeyFile)
}

func requireSM2MLKEMKeyFiles(dir string) error {
	files := map[string]int{
		sm2MLKEMPrivateKeyFile: sm2mlkem.PrivateKeySize,
		sm2MLKEMPublicKeyFile:  sm2mlkem.PublicKeySize,
	}
	for name, wantSize := range files {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		if info.Size() != int64(wantSize) {
			return fmt.Errorf("%s size = %d, want %d", name, info.Size(), wantSize)
		}
	}
	return nil
}

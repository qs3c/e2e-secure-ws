package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	qcrypto "github.com/qs3c/e2e-secure-ws/crypto"
)

const (
	sm2PrivateKeyFile = "private_key.pem"
	sm2PublicKeyFile  = "public_key.pem"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "genkeys:", err)
		os.Exit(1)
	}
}

func run() error {
	outDir := flag.String("out", "static_key", "directory to write per-user key folders")
	idsFlag := flag.String("ids", "", "comma-separated user IDs")
	withSM2MLKEM := flag.Bool("sm2mlkem", false, "also generate SM2+ML-KEM key files; requires building with -tags sm2mlkem")
	force := flag.Bool("force", false, "overwrite existing key files")
	flag.Parse()

	ids := parseIDs(*idsFlag)
	if len(ids) == 0 {
		return errors.New("at least one id is required, for example: -ids 1111111111,2222222222")
	}

	for _, id := range ids {
		if err := generateUserKeys(*outDir, id, *withSM2MLKEM, *force); err != nil {
			return fmt.Errorf("%s: %w", id, err)
		}
		fmt.Printf("wrote keys for %s under %s\n", id, filepath.Join(*outDir, id))
	}
	return nil
}

func parseIDs(raw string) []string {
	parts := strings.Split(raw, ",")
	ids := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		id := strings.TrimSpace(part)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	return ids
}

func generateUserKeys(baseDir, id string, withSM2MLKEM, force bool) error {
	dir := filepath.Join(baseDir, id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	priv, err := qcrypto.GenerateECKey(qcrypto.SM2Curve)
	if err != nil {
		return fmt.Errorf("generate SM2 key: %w", err)
	}
	pemPriv, err := priv.MarshalPKCS8PrivateKeyPEM()
	if err != nil {
		return fmt.Errorf("marshal SM2 private key: %w", err)
	}
	if err := writeKeyFile(filepath.Join(dir, sm2PrivateKeyFile), pemPriv, 0o600, force); err != nil {
		return err
	}

	pub := priv.Public()
	if pub == nil {
		return errors.New("derive SM2 public key failed")
	}
	pemPub, err := pub.MarshalPKIXPublicKeyPEM()
	if err != nil {
		return fmt.Errorf("marshal SM2 public key: %w", err)
	}
	if err := writeKeyFile(filepath.Join(dir, sm2PublicKeyFile), pemPub, 0o644, force); err != nil {
		return err
	}

	if withSM2MLKEM {
		if err := generateSM2MLKEMKeyFiles(dir, force); err != nil {
			return err
		}
	}
	return nil
}

func writeKeyFile(path string, data []byte, perm os.FileMode, force bool) error {
	flag := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if force {
		flag = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	f, err := os.OpenFile(path, flag, perm)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%s already exists; pass -force to overwrite", path)
		}
		return err
	}
	defer f.Close()

	if _, err := f.Write(data); err != nil {
		return err
	}
	return f.Chmod(perm)
}

//go:build sm2mlkem

package e2ewebsocket

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	ccrypto "github.com/qs3c/e2e-secure-ws/crypto"
	"github.com/qs3c/e2e-secure-ws/crypto/sm2mlkem"
)

const (
	sm2MLKEMPrivateKeyFile = "sm2mlkem_private.bin"
	sm2MLKEMPublicKeyFile  = "sm2mlkem_public.bin"
)

func (hs *handshakeState) newKeyAgreement() (keyAgreement, error) {
	switch hs.suite.ka.(type) {
	case *sm2KeyAgreement:
		return hs.newSM2KeyAgreement()
	case *sm2MLKEMKeyAgreement:
		return hs.newSM2MLKEMKeyAgreement()
	default:
		return nil, fmt.Errorf("internal error: unsupported key agreement type: %T", hs.suite.ka)
	}
}

func (hs *handshakeState) newSM2KeyAgreement() (keyAgreement, error) {
	localPrivateKey, err := ccrypto.LoadPrivateKeyFileFromPEM(filepath.Join(hs.s.conn.config.keyStorePath(), hs.localId, "private_key.pem"))
	if err != nil {
		return nil, err
	}
	remotePublicKey, err := ccrypto.LoadPublicKeyFileFromPEM(filepath.Join(hs.s.conn.config.keyStorePath(), hs.remoteId, "public_key.pem"))
	if err != nil {
		return nil, err
	}
	newKA := NewSM2KeyAgreement(localPrivateKey, hs.localId, remotePublicKey, hs.remoteId)
	if newKA == nil {
		return nil, errors.New("failed to initialize SM2 Key Agreement")
	}
	return newKA, nil
}

func (hs *handshakeState) newSM2MLKEMKeyAgreement() (keyAgreement, error) {
	providerPath := os.Getenv("TONGSUO_PQ_PROVIDER_PATH")
	if providerPath == "" {
		providerPath = sm2mlkem.DefaultProviderPath()
	}
	if err := sm2mlkem.Init(providerPath); err != nil {
		return nil, fmt.Errorf("initialize SM2MLKEM provider: %w", err)
	}

	localSignKey, err := ccrypto.LoadPrivateKeyFileFromPEM(filepath.Join(hs.s.conn.config.keyStorePath(), hs.localId, "private_key.pem"))
	if err != nil {
		return nil, err
	}
	remoteSignKey, err := ccrypto.LoadPublicKeyFileFromPEM(filepath.Join(hs.s.conn.config.keyStorePath(), hs.remoteId, "public_key.pem"))
	if err != nil {
		return nil, err
	}

	localKEMKey, err := sm2mlkem.LoadPrivateKey(filepath.Join(hs.s.conn.config.keyStorePath(), hs.localId, sm2MLKEMPrivateKeyFile))
	if err != nil {
		return nil, err
	}
	remoteKEMKey, err := sm2mlkem.LoadPublicKey(filepath.Join(hs.s.conn.config.keyStorePath(), hs.remoteId, sm2MLKEMPublicKeyFile))
	if err != nil {
		localKEMKey.Close()
		return nil, err
	}

	return NewSM2MLKEMKeyAgreement(localSignKey, hs.localId, remoteSignKey, hs.remoteId, localKEMKey, remoteKEMKey), nil
}

//go:build !sm2mlkem

package e2ewebsocket

import (
	"errors"
	"fmt"
	"path/filepath"

	ccrypto "github.com/qs3c/e2e-secure-ws/crypto"
)

func (hs *handshakeState) newKeyAgreement() (keyAgreement, error) {
	switch hs.suite.ka.(type) {
	case *sm2KeyAgreement:
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
	default:
		return nil, fmt.Errorf("internal error: unsupported key agreement type: %T", hs.suite.ka)
	}
}

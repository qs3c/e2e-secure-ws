//go:build sm2mlkem

package e2ewebsocket

import (
	"errors"
	"fmt"

	ccrypto "github.com/qs3c/e2e-secure-ws/crypto"
	"github.com/qs3c/e2e-secure-ws/crypto/sm2mlkem"
	"github.com/qs3c/e2e-secure-ws/crypto/sm2tongsuo"
)

type sm2MLKEMKeyAgreement struct {
	localSignPrivateKey ccrypto.EVPPrivateKey
	remoteSignPublicKey ccrypto.EVPPublicKey
	localId             string
	remoteId            string
	localKEMPrivateKey  *sm2mlkem.Key
	remoteKEMPublicKey  *sm2mlkem.Key
	localSecret         []byte
}

func NewSM2MLKEMKeyAgreement(localSign ccrypto.EVPPrivateKey, localId string, remoteSign ccrypto.EVPPublicKey, remoteId string, localKEMPrivate, remoteKEMPublic *sm2mlkem.Key) *sm2MLKEMKeyAgreement {
	if localSign == nil || remoteSign == nil || localKEMPrivate == nil || remoteKEMPublic == nil {
		return nil
	}
	return &sm2MLKEMKeyAgreement{
		localSignPrivateKey: localSign,
		remoteSignPublicKey: remoteSign,
		localId:             localId,
		remoteId:            remoteId,
		localKEMPrivateKey:  localKEMPrivate,
		remoteKEMPublicKey:  remoteKEMPublic,
	}
}

func (ka *sm2MLKEMKeyAgreement) generateLocalKeyExchange(config *Config, signatureScheme SignatureScheme, hello *helloMsg, remoteHello *helloMsg) (*keyExchangeMsg, error) {
	ciphertext, secret, err := ka.remoteKEMPublicKey.Encapsulate()
	if err != nil {
		return nil, err
	}
	ka.localSecret = secret

	localKEMParams := make([]byte, 4+len(ciphertext))
	groupID := uint16(sm2mlkem.GroupID)
	localKEMParams[0] = byte(groupID >> 8)
	localKEMParams[1] = byte(groupID)
	localKEMParams[2] = byte(len(ciphertext) >> 8)
	localKEMParams[3] = byte(len(ciphertext))
	copy(localKEMParams[4:], ciphertext)

	sigType, sigHash, err := typeAndHashFromSignatureScheme(signatureScheme)
	if err != nil {
		return nil, err
	}

	var signed []byte
	if ka.localId > ka.remoteId {
		signed = hashForKeyExchange(sigType, sigHash, hello.random, remoteHello.random, localKEMParams)
	} else {
		signed = hashForKeyExchange(sigType, sigHash, remoteHello.random, hello.random, localKEMParams)
	}
	signature, err := sm2tongsuo.SignASN1(ka.localSignPrivateKey, signed)
	if err != nil {
		return nil, err
	}

	kxm := &keyExchangeMsg{key: localKEMParams}
	kxm.key = append(kxm.key, byte(signatureScheme>>8), byte(signatureScheme))
	sigLen := uint16(len(signature))
	kxm.key = append(kxm.key, byte(sigLen>>8), byte(sigLen))
	kxm.key = append(kxm.key, signature...)
	return kxm, nil
}

func (ka *sm2MLKEMKeyAgreement) processRemoteKeyExchange(config *Config, signatureScheme SignatureScheme, hello *helloMsg, remoteHello *helloMsg, kxm *keyExchangeMsg) ([]byte, error) {
	if len(kxm.key) < 4 {
		return nil, errKeyExchange
	}
	groupID := BEUint16(kxm.key[:2])
	if groupID != sm2mlkem.GroupID {
		return nil, fmt.Errorf("remote used unsupported KEM group: 0x%04x", groupID)
	}
	ciphertextLen := int(BEUint16(kxm.key[2:4]))
	if ciphertextLen != sm2mlkem.CiphertextSize || 4+ciphertextLen > len(kxm.key) {
		return nil, errKeyExchange
	}

	remoteKEMParams := kxm.key[:4+ciphertextLen]
	ciphertext := remoteKEMParams[4:]
	sig := kxm.key[4+ciphertextLen:]
	if len(sig) < 4 {
		return nil, errKeyExchange
	}

	signatureAlgorithm := SignatureScheme(sig[0])<<8 | SignatureScheme(sig[1])
	if signatureAlgorithm != signatureScheme {
		return nil, errors.New("used with invalid signature algorithm")
	}
	sig = sig[2:]

	sigLen := int(sig[0])<<8 | int(sig[1])
	if sigLen+2 != len(sig) {
		return nil, errKeyExchange
	}
	sig = sig[2:]

	sigType, sigHash, err := typeAndHashFromSignatureScheme(signatureScheme)
	if err != nil {
		return nil, err
	}
	if sigType != signatureSM2 {
		return nil, errKeyExchange
	}

	var signed []byte
	if ka.localId > ka.remoteId {
		signed = hashForKeyExchange(sigType, sigHash, hello.random, remoteHello.random, remoteKEMParams)
	} else {
		signed = hashForKeyExchange(sigType, sigHash, remoteHello.random, hello.random, remoteKEMParams)
	}
	if err := verifyHandshakeSignature(sigType, ka.remoteSignPublicKey, sigHash, signed, sig); err != nil {
		return nil, errors.New("invalid signature by the peer certificate: " + err.Error())
	}

	remoteSecret, err := ka.localKEMPrivateKey.Decapsulate(ciphertext)
	if err != nil {
		return nil, err
	}
	if len(ka.localSecret) != sm2mlkem.SharedSecretSize || len(remoteSecret) != sm2mlkem.SharedSecretSize {
		return nil, errKeyExchange
	}

	preMasterSecret := make([]byte, 0, sm2mlkem.SharedSecretSize*2)
	if ka.localId > ka.remoteId {
		preMasterSecret = append(preMasterSecret, ka.localSecret...)
		preMasterSecret = append(preMasterSecret, remoteSecret...)
	} else {
		preMasterSecret = append(preMasterSecret, remoteSecret...)
		preMasterSecret = append(preMasterSecret, ka.localSecret...)
	}
	return preMasterSecret, nil
}

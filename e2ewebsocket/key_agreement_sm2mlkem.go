//go:build sm2mlkem

package e2ewebsocket

import (
	"errors"
	"fmt"

	ccrypto "github.com/qs3c/e2e-secure-ws/crypto"
	"github.com/qs3c/e2e-secure-ws/crypto/ecdh_curve"
	"github.com/qs3c/e2e-secure-ws/crypto/sm2keyexch"
	"github.com/qs3c/e2e-secure-ws/crypto/sm2mlkem"
	"github.com/qs3c/e2e-secure-ws/crypto/sm2tongsuo"
)

type sm2MLKEMKeyAgreement struct {
	localSignPrivateKey ccrypto.EVPPrivateKey
	remoteSignPublicKey ccrypto.EVPPublicKey
	localId             string
	remoteId            string
	ctxLocal            *sm2keyexch.KAPCtx
	localKEMPrivateKey  *sm2mlkem.Key
	remoteKEMPublicKey  *sm2mlkem.Key
	localKEMSecret      []byte
}

func NewSM2MLKEMKeyAgreement(localSign ccrypto.EVPPrivateKey, localId string, remoteSign ccrypto.EVPPublicKey, remoteId string, localKEMPrivate, remoteKEMPublic *sm2mlkem.Key) *sm2MLKEMKeyAgreement {
	if localSign == nil || remoteSign == nil || localKEMPrivate == nil || remoteKEMPublic == nil {
		return nil
	}
	localECKey, err := ccrypto.ToECKey(localSign)
	if err != nil {
		return nil
	}
	remoteECKey, err := ccrypto.ToECKey(remoteSign)
	if err != nil {
		return nil
	}
	ctxLocal := sm2keyexch.NewKAPCtx()
	if err := ctxLocal.Init(localECKey, localId, remoteECKey, remoteId, localId > remoteId, true); err != nil {
		return nil
	}
	return &sm2MLKEMKeyAgreement{
		localSignPrivateKey: localSign,
		remoteSignPublicKey: remoteSign,
		localId:             localId,
		remoteId:            remoteId,
		ctxLocal:            ctxLocal,
		localKEMPrivateKey:  localKEMPrivate,
		remoteKEMPublicKey:  remoteKEMPublic,
	}
}

func (ka *sm2MLKEMKeyAgreement) generateLocalKeyExchange(config *Config, signatureScheme SignatureScheme, hello *helloMsg, remoteHello *helloMsg) (*keyExchangeMsg, error) {
	ra, err := ka.ctxLocal.Prepare()
	if err != nil {
		return nil, err
	}
	if len(ra) > 255 {
		return nil, errKeyExchange
	}
	localSM2Params := make([]byte, 4+len(ra))
	localSM2Params[0] = byte(3)
	localSM2Params[1] = byte(uint16(SM2CurveP256V1) >> 8)
	localSM2Params[2] = byte(uint16(SM2CurveP256V1) & 0xff)
	localSM2Params[3] = byte(len(ra))
	copy(localSM2Params[4:], ra)

	ciphertext, secret, err := ka.remoteKEMPublicKey.Encapsulate()
	if err != nil {
		return nil, err
	}
	ka.localKEMSecret = secret

	localKEMParams := make([]byte, 4+len(ciphertext))
	groupID := uint16(sm2mlkem.GroupID)
	localKEMParams[0] = byte(groupID >> 8)
	localKEMParams[1] = byte(groupID)
	localKEMParams[2] = byte(len(ciphertext) >> 8)
	localKEMParams[3] = byte(len(ciphertext))
	copy(localKEMParams[4:], ciphertext)

	localParams := make([]byte, 0, len(localSM2Params)+len(localKEMParams))
	localParams = append(localParams, localSM2Params...)
	localParams = append(localParams, localKEMParams...)

	sigType, sigHash, err := typeAndHashFromSignatureScheme(signatureScheme)
	if err != nil {
		return nil, err
	}

	var signed []byte
	if ka.localId > ka.remoteId {
		signed = hashForKeyExchange(sigType, sigHash, hello.random, remoteHello.random, localParams)
	} else {
		signed = hashForKeyExchange(sigType, sigHash, remoteHello.random, hello.random, localParams)
	}
	signature, err := sm2tongsuo.SignASN1(ka.localSignPrivateKey, signed)
	if err != nil {
		return nil, err
	}

	kxm := &keyExchangeMsg{key: localParams}
	kxm.key = append(kxm.key, byte(signatureScheme>>8), byte(signatureScheme))
	sigLen := uint16(len(signature))
	kxm.key = append(kxm.key, byte(sigLen>>8), byte(sigLen))
	kxm.key = append(kxm.key, signature...)
	return kxm, nil
}

func (ka *sm2MLKEMKeyAgreement) processRemoteKeyExchange(config *Config, signatureScheme SignatureScheme, hello *helloMsg, remoteHello *helloMsg, kxm *keyExchangeMsg) ([]byte, error) {
	if len(kxm.key) < 8 {
		return nil, errKeyExchange
	}
	if kxm.key[0] != 3 {
		return nil, errors.New("remote used unsupported curve")
	}
	curveID := CurveID(kxm.key[1])<<8 | CurveID(kxm.key[2])
	if curveID != SM2CurveP256V1 {
		return nil, errors.New("remote used unsupported curve")
	}
	publicLen := int(kxm.key[3])
	if publicLen+8 > len(kxm.key) {
		return nil, errKeyExchange
	}

	remoteSM2Params := kxm.key[:4+publicLen]
	offset := 4 + publicLen
	groupID := BEUint16(kxm.key[offset : offset+2])
	if groupID != sm2mlkem.GroupID {
		return nil, fmt.Errorf("remote used unsupported KEM group: 0x%04x", groupID)
	}
	ciphertextLen := int(BEUint16(kxm.key[offset+2 : offset+4]))
	if ciphertextLen != sm2mlkem.CiphertextSize || offset+4+ciphertextLen > len(kxm.key) {
		return nil, errKeyExchange
	}

	remoteParams := kxm.key[:offset+4+ciphertextLen]
	ciphertext := kxm.key[offset+4 : offset+4+ciphertextLen]
	sig := kxm.key[offset+4+ciphertextLen:]
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
		signed = hashForKeyExchange(sigType, sigHash, hello.random, remoteHello.random, remoteParams)
	} else {
		signed = hashForKeyExchange(sigType, sigHash, remoteHello.random, hello.random, remoteParams)
	}
	if err := verifyHandshakeSignature(sigType, ka.remoteSignPublicKey, sigHash, signed, sig); err != nil {
		return nil, errors.New("invalid signature by the peer certificate: " + err.Error())
	}

	sm2Curve := ecdh_curve.NewSm2P256V1(ka.localId > ka.remoteId)
	key := ecdh_curve.NewEmptySm2PrivateKey(sm2Curve)
	peerKey, err := key.Curve().NewPublicKey(remoteSM2Params[4:])
	if err != nil {
		return nil, errKeyExchange
	}
	sm2Secret, err := key.ComputeSecret(ka.ctxLocal, peerKey)
	if err != nil {
		return nil, errKeyExchange
	}

	remoteKEMSecret, err := ka.localKEMPrivateKey.Decapsulate(ciphertext)
	if err != nil {
		return nil, err
	}
	if len(ka.localKEMSecret) != sm2mlkem.SharedSecretSize || len(remoteKEMSecret) != sm2mlkem.SharedSecretSize {
		return nil, errKeyExchange
	}

	preMasterSecret := make([]byte, 0, len(sm2Secret)+sm2mlkem.SharedSecretSize*2)
	preMasterSecret = append(preMasterSecret, sm2Secret...)
	if ka.localId > ka.remoteId {
		preMasterSecret = append(preMasterSecret, ka.localKEMSecret...)
		preMasterSecret = append(preMasterSecret, remoteKEMSecret...)
	} else {
		preMasterSecret = append(preMasterSecret, remoteKEMSecret...)
		preMasterSecret = append(preMasterSecret, ka.localKEMSecret...)
	}
	return preMasterSecret, nil
}

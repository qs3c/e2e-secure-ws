//go:build sm2mlkem

package e2ewebsocket

import (
	"bytes"
	"os"
	"testing"

	qcrypto "github.com/qs3c/e2e-secure-ws/crypto"
	"github.com/qs3c/e2e-secure-ws/crypto/sm2mlkem"
)

func TestSM2MLKEMKeyAgreementRoundTrip(t *testing.T) {
	providerPath := os.Getenv("TONGSUO_PQ_PROVIDER_PATH")
	if providerPath == "" {
		providerPath = sm2mlkem.DefaultProviderPath()
	}
	if err := sm2mlkem.Init(providerPath); err != nil {
		t.Fatalf("initialize SM2MLKEM provider: %v", err)
	}

	aliceSign, err := qcrypto.GenerateECKey(qcrypto.SM2Curve)
	if err != nil {
		t.Fatal(err)
	}
	bobSign, err := qcrypto.GenerateECKey(qcrypto.SM2Curve)
	if err != nil {
		t.Fatal(err)
	}

	aliceKEMPrivate, err := sm2mlkem.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer aliceKEMPrivate.Close()
	bobKEMPrivate, err := sm2mlkem.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer bobKEMPrivate.Close()

	aliceKEMPublicBytes, err := aliceKEMPrivate.ExportPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	bobKEMPublicBytes, err := bobKEMPrivate.ExportPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	aliceKEMPublicForBob, err := sm2mlkem.ImportPublicKey(aliceKEMPublicBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer aliceKEMPublicForBob.Close()
	bobKEMPublicForAlice, err := sm2mlkem.ImportPublicKey(bobKEMPublicBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer bobKEMPublicForAlice.Close()

	aliceID := "1111111111"
	bobID := "2222222222"
	aliceKA := NewSM2MLKEMKeyAgreement(aliceSign, aliceID, bobSign.Public(), bobID, aliceKEMPrivate, bobKEMPublicForAlice)
	bobKA := NewSM2MLKEMKeyAgreement(bobSign, bobID, aliceSign.Public(), aliceID, bobKEMPrivate, aliceKEMPublicForBob)
	if aliceKA == nil || bobKA == nil {
		t.Fatal("NewSM2MLKEMKeyAgreement returned nil")
	}

	aliceHello := &helloMsg{random: bytes.Repeat([]byte{0xA1}, 32)}
	bobHello := &helloMsg{random: bytes.Repeat([]byte{0xB2}, 32)}

	aliceKXM, err := aliceKA.generateLocalKeyExchange(&Config{}, SM2WithSM3, aliceHello, bobHello)
	if err != nil {
		t.Fatalf("Alice generateLocalKeyExchange: %v", err)
	}
	bobKXM, err := bobKA.generateLocalKeyExchange(&Config{}, SM2WithSM3, bobHello, aliceHello)
	if err != nil {
		t.Fatalf("Bob generateLocalKeyExchange: %v", err)
	}

	aliceSecret, err := aliceKA.processRemoteKeyExchange(&Config{}, SM2WithSM3, aliceHello, bobHello, bobKXM)
	if err != nil {
		t.Fatalf("Alice processRemoteKeyExchange: %v", err)
	}
	bobSecret, err := bobKA.processRemoteKeyExchange(&Config{}, SM2WithSM3, bobHello, aliceHello, aliceKXM)
	if err != nil {
		t.Fatalf("Bob processRemoteKeyExchange: %v", err)
	}
	if !bytes.Equal(aliceSecret, bobSecret) {
		t.Fatal("preMasterSecret differs")
	}
}

//go:build sm2mlkem

package sm2mlkem

import (
	"bytes"
	"os"
	"testing"
)

func TestEncapsulateDecapsulate(t *testing.T) {
	providerPath := os.Getenv("TONGSUO_PQ_PROVIDER_PATH")
	if providerPath == "" {
		providerPath = DefaultProviderPath()
	}
	if err := Init(providerPath); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	recipient, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	defer recipient.Close()

	pub, err := recipient.ExportPublicKey()
	if err != nil {
		t.Fatalf("ExportPublicKey failed: %v", err)
	}
	if len(pub) != PublicKeySize {
		t.Fatalf("public key length = %d, want %d", len(pub), PublicKeySize)
	}

	recipientPub, err := ImportPublicKey(pub)
	if err != nil {
		t.Fatalf("ImportPublicKey failed: %v", err)
	}
	defer recipientPub.Close()

	priv, err := recipient.ExportPrivateKey()
	if err != nil {
		t.Fatalf("ExportPrivateKey failed: %v", err)
	}
	if len(priv) != PrivateKeySize {
		t.Fatalf("private key length = %d, want %d", len(priv), PrivateKeySize)
	}
	recipientPriv, err := ImportPrivateKey(priv)
	if err != nil {
		t.Fatalf("ImportPrivateKey failed: %v", err)
	}
	defer recipientPriv.Close()

	ct, senderSecret, err := recipientPub.Encapsulate()
	if err != nil {
		t.Fatalf("Encapsulate failed: %v", err)
	}
	if len(ct) != CiphertextSize {
		t.Fatalf("ciphertext length = %d, want %d", len(ct), CiphertextSize)
	}
	if len(senderSecret) != SharedSecretSize {
		t.Fatalf("sender secret length = %d, want %d", len(senderSecret), SharedSecretSize)
	}

	recipientSecret, err := recipientPriv.Decapsulate(ct)
	if err != nil {
		t.Fatalf("Decapsulate failed: %v", err)
	}
	if !bytes.Equal(senderSecret, recipientSecret) {
		t.Fatalf("shared secrets differ: sm2_equal=%v mlkem_equal=%v",
			bytes.Equal(senderSecret[:32], recipientSecret[:32]),
			bytes.Equal(senderSecret[32:], recipientSecret[32:]))
	}
}

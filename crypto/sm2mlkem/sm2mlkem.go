//go:build sm2mlkem

package sm2mlkem

import (
	"crypto/mlkem"
	"errors"
	"fmt"
	"os"
)

const (
	GroupID          uint16 = 0x11EE
	PublicKeySize           = mlkem.EncapsulationKeySize768
	PrivateKeySize          = mlkem.SeedSize
	CiphertextSize          = mlkem.CiphertextSize768
	SharedSecretSize        = mlkem.SharedKeySize
)

type Key struct {
	private *mlkem.DecapsulationKey768
	public  *mlkem.EncapsulationKey768
}

func Init(providerPath string) error {
	return nil
}

func DefaultProviderPath() string {
	return ""
}

func GenerateKey() (*Key, error) {
	private, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, err
	}
	return &Key{
		private: private,
		public:  private.EncapsulationKey(),
	}, nil
}

func ImportPublicKey(data []byte) (*Key, error) {
	if len(data) != PublicKeySize {
		return nil, fmt.Errorf("invalid SM2MLKEM public key length: got %d, want %d", len(data), PublicKeySize)
	}
	public, err := mlkem.NewEncapsulationKey768(data)
	if err != nil {
		return nil, err
	}
	return &Key{public: public}, nil
}

func ImportPrivateKey(data []byte) (*Key, error) {
	if len(data) != PrivateKeySize {
		return nil, fmt.Errorf("invalid SM2MLKEM private key length: got %d, want %d", len(data), PrivateKeySize)
	}
	private, err := mlkem.NewDecapsulationKey768(data)
	if err != nil {
		return nil, err
	}
	return &Key{
		private: private,
		public:  private.EncapsulationKey(),
	}, nil
}

func LoadPublicKey(path string) (*Key, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ImportPublicKey(data)
}

func LoadPrivateKey(path string) (*Key, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ImportPrivateKey(data)
}

func (k *Key) ExportPublicKey() ([]byte, error) {
	if k == nil || k.public == nil {
		return nil, errors.New("nil SM2MLKEM public key")
	}
	return k.public.Bytes(), nil
}

func (k *Key) ExportPrivateKey() ([]byte, error) {
	if k == nil || k.private == nil {
		return nil, errors.New("nil SM2MLKEM private key")
	}
	return k.private.Bytes(), nil
}

func (k *Key) Encapsulate() (ciphertext []byte, sharedSecret []byte, err error) {
	if k == nil || k.public == nil {
		return nil, nil, errors.New("nil SM2MLKEM public key")
	}
	sharedSecret, ciphertext = k.public.Encapsulate()
	return ciphertext, sharedSecret, nil
}

func (k *Key) Decapsulate(ciphertext []byte) ([]byte, error) {
	if k == nil || k.private == nil {
		return nil, errors.New("nil SM2MLKEM private key")
	}
	if len(ciphertext) != CiphertextSize {
		return nil, fmt.Errorf("invalid SM2MLKEM ciphertext length: got %d, want %d", len(ciphertext), CiphertextSize)
	}
	return k.private.Decapsulate(ciphertext)
}

func (k *Key) Close() {
}

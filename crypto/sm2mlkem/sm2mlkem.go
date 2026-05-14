//go:build sm2mlkem

package sm2mlkem

/*
#cgo CFLAGS: -I${SRCDIR}
#cgo windows LDFLAGS: -L${SRCDIR} -lsm2mlkem_wrapper
#cgo linux LDFLAGS: -L${SRCDIR} -lsm2mlkem_wrapper -Wl,-rpath,${SRCDIR}
#cgo darwin LDFLAGS: -L${SRCDIR} -lsm2mlkem_wrapper -Wl,-rpath,${SRCDIR}
#include "wrapper.h"
#include <stdlib.h>
*/
import "C"

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"unsafe"
)

const (
	GroupID          uint16 = C.SM2MLKEM_GROUP_ID
	PublicKeySize           = C.SM2MLKEM_PUBLIC_KEY_LEN
	PrivateKeySize          = C.SM2MLKEM_PRIVATE_KEY_LEN
	CiphertextSize          = C.SM2MLKEM_CIPHERTEXT_LEN
	SharedSecretSize        = C.SM2MLKEM_SHARED_SECRET_LEN
)

type Key struct {
	ptr *C.SM2MLKEM_KEY
}

func Init(providerPath string) error {
	var cpath *C.char
	if providerPath != "" {
		cpath = C.CString(providerPath)
		defer C.free(unsafe.Pointer(cpath))
	}
	if C.sm2mlkem_init(cpath) != 1 {
		return lastError()
	}
	return nil
}

func DefaultProviderPath() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return ""
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	return filepath.Join(repoRoot, "third_party", "tongsuo-pq-install", "lib", "ossl-modules")
}

func GenerateKey() (*Key, error) {
	ptr := C.sm2mlkem_generate_key()
	if ptr == nil {
		return nil, lastError()
	}
	return newKey(ptr), nil
}

func ImportPublicKey(data []byte) (*Key, error) {
	if len(data) != PublicKeySize {
		return nil, fmt.Errorf("invalid SM2MLKEM public key length: got %d, want %d", len(data), PublicKeySize)
	}
	ptr := C.sm2mlkem_import_public_key((*C.uchar)(unsafe.Pointer(&data[0])), C.size_t(len(data)))
	if ptr == nil {
		return nil, lastError()
	}
	return newKey(ptr), nil
}

func ImportPrivateKey(data []byte) (*Key, error) {
	if len(data) != PrivateKeySize {
		return nil, fmt.Errorf("invalid SM2MLKEM private key length: got %d, want %d", len(data), PrivateKeySize)
	}
	ptr := C.sm2mlkem_import_private_key((*C.uchar)(unsafe.Pointer(&data[0])), C.size_t(len(data)))
	if ptr == nil {
		return nil, lastError()
	}
	return newKey(ptr), nil
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
	if k == nil || k.ptr == nil {
		return nil, errors.New("nil SM2MLKEM key")
	}
	out := make([]byte, PublicKeySize)
	outLen := C.size_t(len(out))
	if C.sm2mlkem_export_public_key(k.ptr, (*C.uchar)(unsafe.Pointer(&out[0])), &outLen) != 1 {
		return nil, lastError()
	}
	return out[:int(outLen)], nil
}

func (k *Key) ExportPrivateKey() ([]byte, error) {
	if k == nil || k.ptr == nil {
		return nil, errors.New("nil SM2MLKEM key")
	}
	out := make([]byte, PrivateKeySize)
	outLen := C.size_t(len(out))
	if C.sm2mlkem_export_private_key(k.ptr, (*C.uchar)(unsafe.Pointer(&out[0])), &outLen) != 1 {
		return nil, lastError()
	}
	return out[:int(outLen)], nil
}

func (k *Key) Encapsulate() (ciphertext []byte, sharedSecret []byte, err error) {
	if k == nil || k.ptr == nil {
		return nil, nil, errors.New("nil SM2MLKEM key")
	}
	ciphertext = make([]byte, CiphertextSize)
	sharedSecret = make([]byte, SharedSecretSize)
	cLen := C.size_t(len(ciphertext))
	sLen := C.size_t(len(sharedSecret))
	if C.sm2mlkem_encapsulate(k.ptr,
		(*C.uchar)(unsafe.Pointer(&ciphertext[0])), &cLen,
		(*C.uchar)(unsafe.Pointer(&sharedSecret[0])), &sLen) != 1 {
		return nil, nil, lastError()
	}
	return ciphertext[:int(cLen)], sharedSecret[:int(sLen)], nil
}

func (k *Key) Decapsulate(ciphertext []byte) ([]byte, error) {
	if k == nil || k.ptr == nil {
		return nil, errors.New("nil SM2MLKEM key")
	}
	if len(ciphertext) != CiphertextSize {
		return nil, fmt.Errorf("invalid SM2MLKEM ciphertext length: got %d, want %d", len(ciphertext), CiphertextSize)
	}
	sharedSecret := make([]byte, SharedSecretSize)
	sLen := C.size_t(len(sharedSecret))
	if C.sm2mlkem_decapsulate(k.ptr,
		(*C.uchar)(unsafe.Pointer(&ciphertext[0])), C.size_t(len(ciphertext)),
		(*C.uchar)(unsafe.Pointer(&sharedSecret[0])), &sLen) != 1 {
		return nil, lastError()
	}
	return sharedSecret[:int(sLen)], nil
}

func (k *Key) Close() {
	if k == nil || k.ptr == nil {
		return
	}
	C.sm2mlkem_free_key(k.ptr)
	k.ptr = nil
	runtime.SetFinalizer(k, nil)
}

func newKey(ptr *C.SM2MLKEM_KEY) *Key {
	k := &Key{ptr: ptr}
	runtime.SetFinalizer(k, (*Key).Close)
	return k
}

func lastError() error {
	return errors.New(C.GoString(C.sm2mlkem_last_error()))
}

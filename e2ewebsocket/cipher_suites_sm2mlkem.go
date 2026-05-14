//go:build sm2mlkem

package e2ewebsocket

import "github.com/qs3c/e2e-secure-ws/crypto/sm4tongsuo"

const E2E_SM2MLKEM768_WITH_SM4_128_GCM_SM3 uint16 = 0x0031

var sm2MLKEMKA = &sm2MLKEMKeyAgreement{}

func init() {
	cipherSuitesPreferenceOrder = append([]uint16{
		E2E_SM2MLKEM768_WITH_SM4_128_GCM_SM3,
	}, cipherSuitesPreferenceOrder...)

	cipherSuites[E2E_SM2MLKEM768_WITH_SM4_128_GCM_SM3] = &cipherSuite{
		id:     E2E_SM2MLKEM768_WITH_SM4_128_GCM_SM3,
		keyLen: 16,
		macLen: 0,
		ivLen:  4,
		ka:     sm2MLKEMKA,
		flags:  suiteTLS12 | suiteSM3,
		aead:   sm4tongsuo.NewSm4AEADCipher,
	}
}

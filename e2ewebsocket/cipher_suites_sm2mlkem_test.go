//go:build sm2mlkem

package e2ewebsocket

import "testing"

func TestSM2MLKEMDefaultCipherSuiteOptIn(t *testing.T) {
	if containsCipherSuite((&Config{}).cipherSuites(), E2E_SM2MLKEM768_WITH_SM4_128_GCM_SM3) {
		t.Fatal("SM2MLKEM should not be in the default cipher suite list without opt-in")
	}
	if !containsCipherSuite((&Config{EnableSM2MLKEM: true}).cipherSuites(), E2E_SM2MLKEM768_WITH_SM4_128_GCM_SM3) {
		t.Fatal("SM2MLKEM should be in the default cipher suite list with opt-in")
	}
	if !containsCipherSuite((&Config{CipherSuites: []uint16{E2E_SM2MLKEM768_WITH_SM4_128_GCM_SM3}}).cipherSuites(), E2E_SM2MLKEM768_WITH_SM4_128_GCM_SM3) {
		t.Fatal("explicit SM2MLKEM cipher suite should be honored")
	}
}

func containsCipherSuite(suites []uint16, want uint16) bool {
	for _, suite := range suites {
		if suite == want {
			return true
		}
	}
	return false
}

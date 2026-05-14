//go:build !sm2mlkem

package e2ewebsocket

func defaultCipherSuitesForConfig(c *Config, suites []uint16) []uint16 {
	return suites
}

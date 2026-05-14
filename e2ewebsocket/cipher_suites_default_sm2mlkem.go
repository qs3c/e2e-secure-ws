//go:build sm2mlkem

package e2ewebsocket

func defaultCipherSuitesForConfig(c *Config, suites []uint16) []uint16 {
	if c != nil && c.EnableSM2MLKEM {
		return suites
	}

	filtered := make([]uint16, 0, len(suites))
	for _, suiteID := range suites {
		if suiteID != E2E_SM2MLKEM768_WITH_SM4_128_GCM_SM3 {
			filtered = append(filtered, suiteID)
		}
	}
	return filtered
}

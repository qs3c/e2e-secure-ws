//go:build sm2mlkem

package e2ewebsocket

import (
	"path/filepath"
	"testing"
)

func TestSetupKeyStoreWritesSM2MLKEMKeys(t *testing.T) {
	baseDir := t.TempDir()
	id := "1111111111"

	setupKeyStore(t, baseDir, id)

	if err := requireSM2MLKEMKeyFiles(filepath.Join(baseDir, id)); err != nil {
		t.Fatal(err)
	}
}

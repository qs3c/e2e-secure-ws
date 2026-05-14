//go:build !sm2mlkem

package main

import "errors"

func generateSM2MLKEMKeyFiles(dir string, force bool) error {
	return errors.New("SM2MLKEM key generation requires: go run -tags sm2mlkem ./cmd/genkeys -sm2mlkem ...")
}

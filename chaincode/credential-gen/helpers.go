package main

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func loadSecretScalarBig(keyFile string) (*big.Int, error) {
	keyHex, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("cannot read key file: %w", err)
	}

	xBytes, err := hex.DecodeString(strings.TrimSpace(string(keyHex)))
	if err != nil {
		return nil, fmt.Errorf("secret key is not valid hex: %w", err)
	}
	if len(xBytes) != 32 {
		return nil, fmt.Errorf("secret key must be 32 bytes")
	}

	var xFr fr.Element
	xFr.SetBytes(xBytes)
	var xBig big.Int
	xFr.BigInt(&xBig)
	return &xBig, nil
}

func parseAttributes(attrsRaw string) ([]string, error) {
	parts := strings.Split(attrsRaw, ",")
	attrs := make([]string, 0, len(parts))
	for _, p := range parts {
		v := strings.TrimSpace(p)
		if v != "" {
			attrs = append(attrs, v)
		}
	}
	if len(attrs) == 0 {
		return nil, fmt.Errorf("at least one attribute is required")
	}
	return attrs, nil
}

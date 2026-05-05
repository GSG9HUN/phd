package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func die(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(1)
}

func decodeHex(s, name string, wantLen int) []byte {
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != wantLen {
		die(fmt.Sprintf("invalid --%s: must be %d-byte hex", name, wantLen))
	}
	return b
}

func frFrom(b []byte) fr.Element {
	var e fr.Element
	e.SetBytes(b)
	return e
}

func splitTrim(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

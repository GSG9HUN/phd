package main

// issuer-keygen – Issuer keypair generator (off-chain)
//
// # Role in the system
//
// During the Setup phase, each Issuer receives a BLS12-381 elliptic curve
// keypair:
//
//	secret key: x ∈ Zq  (random scalar from the field of the curve order)
//	public key: X = x·G₂  (G2 point, 96 bytes compressed)
//
// The secret key remains only with the Issuer (saved to a file).
// The public key must be uploaded to the setupcc chaincode using the
// RegisterIssuerKey call so that the Verifier can see it.
//
// # Usage
//
//	go run main.go --issuer issuer-org1 [--out ./keys]
//
// Output:
//
//	./keys/issuer-org1-secret.key  – secret key in hex (32 bytes)
//	./keys/issuer-org1-public.key  – public key in hex (48 bytes, compressed G1)
//	stdout: peer chaincode invoke ... RegisterIssuerKey command

import (
	"encoding/hex"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func main() {
	issuerID := flag.String("issuer", "", "Issuer identifier (e.g., issuer-org1)")
	outDir := flag.String("out", "./keys", "Output directory for key files")
	flag.Parse()

	if *issuerID == "" {
		fmt.Fprintln(os.Stderr, "Error: --issuer argument is required")
		flag.Usage()
		os.Exit(1)
	}

	x, err := generateSecretKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Secret key generation error: %v\n", err)
		os.Exit(1)
	}

	X := computePublicKey(x)

	// 3. Hex encoding
	//    - secret key: 32-byte big-endian scalar → hex
	//    - public key: 96-byte compressed G2 point → hex
	xBytes := x.Bytes() // [32]byte, big-endian
	XBytes := X.Bytes() // [96]byte, compressed G2

	xHex := hex.EncodeToString(xBytes[:])
	XHex := hex.EncodeToString(XBytes[:])

	// 4. Save to files
	if err := os.MkdirAll(*outDir, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "Directory creation error: %v\n", err)
		os.Exit(1)
	}

	secretPath := filepath.Join(*outDir, *issuerID+"-secret.key")
	publicPath := filepath.Join(*outDir, *issuerID+"-public.key")

	// Secret key: owner only (0600)
	if err := os.WriteFile(secretPath, []byte(xHex+"\n"), 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Secret key save error: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(publicPath, []byte(XHex+"\n"), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Public key save error: %v\n", err)
		os.Exit(1)
	}

	// 5. Stdout output
	fmt.Printf("=== Issuer keypair generated: %s ===\n\n", *issuerID)
	fmt.Printf("Secret key (CONFIDENTIAL): %s\n", secretPath)
	fmt.Printf("  x = %s\n\n", xHex)
	fmt.Printf("Public key: %s\n", publicPath)
	fmt.Printf("  X = %s\n\n", XHex)
}

// SetRandom can fail and can generate zero, which we exclude.
func generateSecretKey() (*fr.Element, error) {
	var x fr.Element
	for {
		if _, err := x.SetRandom(); err != nil {
			return nil, fmt.Errorf("crypto/rand reading error: %w", err)
		}
		if !x.IsZero() {
			return &x, nil
		}
	}
}

func computePublicKey(x *fr.Element) *bls12381.G2Affine {
	_, _, _, G2 := bls12381.Generators()
	var xBig big.Int
	x.BigInt(&xBig)
	var X bls12381.G2Affine
	X.ScalarMultiplication(&G2, &xBig)
	return &X
}

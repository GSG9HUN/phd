package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// dst is the domain separation tag used for HashToG1.
// Must be the same in all components of the system.
var dst = []byte("BLS12381G1_XMD:SHA-256_SSWU_RO_ACS_")

func main() {
	issuerID := flag.String("issuer", "", "Issuer identifier (e.g. issuer-org1)")
	userID := flag.String("user", "", "User identifier (e.g. alice)")
	attrsRaw := flag.String("attrs", "", "Comma-separated attributes: key:value,key:value")
	keyFile := flag.String("key", "", "Path to issuer secret key file (hex, 32 bytes)")
	flag.Parse()

	if *issuerID == "" || *userID == "" || *attrsRaw == "" || *keyFile == "" {
		fmt.Fprintln(os.Stderr, "Usage: credential-gen --issuer <id> --user <id> --attrs <k:v,...> --key <file>")
		flag.Usage()
		os.Exit(1)
	}

	// Read and parse secret key
	keyHex, err := os.ReadFile(*keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot read key file: %v\n", err)
		os.Exit(1)
	}
	xBytes, err := hex.DecodeString(strings.TrimSpace(string(keyHex)))
	if err != nil || len(xBytes) != 32 {
		fmt.Fprintln(os.Stderr, "Invalid secret key: must be 32-byte hex")
		os.Exit(1)
	}
	var xFr fr.Element
	xFr.SetBytes(xBytes)
	var xBig big.Int
	xFr.BigInt(&xBig)

	// Parse attributes
	attrs := strings.Split(*attrsRaw, ",")
	if len(attrs) == 0 || (len(attrs) == 1 && attrs[0] == "") {
		fmt.Fprintln(os.Stderr, "At least one attribute is required")
		os.Exit(1)
	}

	fmt.Printf("=== Credential generation: %s (issuer: %s) ===\n\n", *userID, *issuerID)
	fmt.Printf("Attributes (%d):\n", len(attrs))

	components := make([]string, 0, len(attrs))
	var TU bls12381.G1Affine
	TUset := false

	for i, attr := range attrs {
		attr = strings.TrimSpace(attr)
		fmt.Printf("  [%d] %s\n", i, attr)

		// H(mᵢ) = hash attribute string to G1
		hm, err := bls12381.HashToG1([]byte(attr), dst)
		if err != nil {
			fmt.Fprintf(os.Stderr, "HashToG1 failed for attr %q: %v\n", attr, err)
			os.Exit(1)
		}

		// Cᵢ = x · H(mᵢ)
		var Ci bls12381.G1Affine
		Ci.ScalarMultiplication(&hm, &xBig)

		ciBytes := Ci.Bytes()
		ciHex := hex.EncodeToString(ciBytes[:])
		components = append(components, ciHex)

		// T_U += Cᵢ
		if !TUset {
			TU = Ci
			TUset = true
		} else {
			TU.Add(&TU, &Ci)
		}
	}

	tuBytes := TU.Bytes()
	tuHex := hex.EncodeToString(tuBytes[:])

	componentsJSON, _ := json.Marshal(components)

	fmt.Printf("\nT_U (tuHex):       %s\n", tuHex)
	fmt.Printf("Components JSON:   %s\n\n", string(componentsJSON))

	fmt.Printf("--- IssueCredential invoke command ---\n")
	fmt.Printf("# Org1 MSP context (setGlobals 1), verify-channel, issuancecc\n")
	fmt.Printf("peer chaincode invoke \\\n")
	fmt.Printf("  -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com \\\n")
	fmt.Printf("  --tls --cafile \"$ORDERER_CA\" \\\n")
	fmt.Printf("  -C verify-channel -n issuancecc \\\n")
	fmt.Printf("  --peerAddresses localhost:7051 --tlsRootCertFiles \"$PEER0_ORG1_CA\" \\\n")
	fmt.Printf("  --peerAddresses localhost:9051 --tlsRootCertFiles \"$PEER0_ORG2_CA\" \\\n")
	fmt.Printf("  -c '{\"function\":\"IssueCredential\",\"Args\":[\"%s\",\"%s\",\"%s\",%s]}'\n",
		*userID, *issuerID, tuHex, string(componentsJSON))
}

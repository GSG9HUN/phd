package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"

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

	xBig, err := loadSecretScalarBig(*keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid secret key: %v\n", err)
		os.Exit(1)
	}

	attrs, err := parseAttributes(*attrsRaw)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	fmt.Printf("=== Credential generation: %s (issuer: %s) ===\n\n", *userID, *issuerID)
	fmt.Printf("Attributes (%d):\n", len(attrs))

	components := make([]string, 0, len(attrs))
	var TU bls12381.G1Affine
	TUset := false

	for i, attr := range attrs {
		fmt.Printf("  [%d] %s\n", i, attr)

		// H(mᵢ) = hash attribute string to G1
		hm, err := bls12381.HashToG1([]byte(attr), dst)
		if err != nil {
			fmt.Fprintf(os.Stderr, "HashToG1 failed for attr %q: %v\n", attr, err)
			os.Exit(1)
		}

		// Cᵢ = x · H(mᵢ)
		var Ci bls12381.G1Affine
		Ci.ScalarMultiplication(&hm, xBig)

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

	// --- u·G̅ és xu·G̅ generálás (cikk: Issuance phase) ---
	// A felhasználó választ egy u ∈ Zq véletlen értéket.
	// Az issuer kiszámolja xu·G̅ = x·(u·G₁_gen), majd
	// TU_comm = TU + xu·G̅ lesz a commitment alapja.
	// u·G̅ értéke off-chain marad a felhasználónál (presentationhoz kell).
	var uScalar fr.Element
	if _, err := uScalar.SetRandom(); err != nil {
		fmt.Fprintf(os.Stderr, "SetRandom failed: %v\n", err)
		os.Exit(1)
	}
	var uBig big.Int
	uScalar.BigInt(&uBig)

	G1genJac, _, _, _ := bls12381.Generators()
	var G1gen bls12381.G1Affine
	G1gen.FromJacobian(&G1genJac)

	// u·G̅  (a felhasználó titkos szorzója a G1 generátoron)
	var uGBar bls12381.G1Affine
	uGBar.ScalarMultiplication(&G1gen, &uBig)

	// xu·G̅ = x · (u·G̅)  (issuer titkos kulcsával skálázva)
	var xuGBar bls12381.G1Affine
	xuGBar.ScalarMultiplication(&uGBar, xBig)

	// TU_comm = TU + xu·G̅  →  ez kerül a ComputeCommitment-be
	var TUcomm bls12381.G1Affine
	TUcomm.Add(&TU, &xuGBar)

	uGBarBytes := uGBar.Bytes()
	uGBarHex := hex.EncodeToString(uGBarBytes[:])
	tuCommBytes := TUcomm.Bytes()
	tuCommHex := hex.EncodeToString(tuCommBytes[:])

	componentsJSON, _ := json.Marshal(components)

	fmt.Printf("\nT_U (tuHex):           %s\n", tuHex)
	fmt.Printf("T_U+xuG̅ (tuCommHex):   %s\n", tuCommHex)
	fmt.Printf("u·G̅  (uGBarHex):       %s\n", uGBarHex)
	fmt.Printf("Components JSON:       %s\n\n", string(componentsJSON))

	fmt.Printf("--- IssueCredential invoke command ---\n")
	fmt.Printf("# Org1 MSP context (setGlobals 1), verify-channel, issuancecc\n")
	fmt.Printf("peer chaincode invoke \\\n")
	fmt.Printf("  -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com \\\n")
	fmt.Printf("  --tls --cafile \"$ORDERER_CA\" \\\n")
	fmt.Printf("  -C verify-channel -n issuancecc \\\n")
	fmt.Printf("  --peerAddresses localhost:7051 --tlsRootCertFiles \"$PEER0_ORG1_CA\" \\\n")
	fmt.Printf("  --peerAddresses localhost:9051 --tlsRootCertFiles \"$PEER0_ORG2_CA\" \\\n")
	fmt.Printf("  -c '{\"function\":\"IssueCredential\",\"Args\":[\"%s\",\"%s\",\"<intervalID>\",\"%s\",\"%s\",%s,\"<commitmentHex>\"]}'\n",
		*userID, *issuerID, tuHex, tuCommHex, string(componentsJSON))
	fmt.Printf("\n# ComputeCommitment (rand-channel) — tuCommHex-et kell átadni:\n")
	fmt.Printf("# peer chaincode query -C rand-channel -n randomcc \\\n")
	fmt.Printf("#   -c '{\"function\":\"ComputeCommitment\",\"Args\":[\"<intervalID>\",\"%s\"]}'\n", tuCommHex)
	fmt.Printf("\n# u·G̅ (uGBarHex) — a felhasználó tárolja el offline (presentation-hez szükséges):\n")
	fmt.Printf("# %s\n", uGBarHex)
}

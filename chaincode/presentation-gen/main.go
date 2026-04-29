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

var dst = []byte("BLS12381G1_XMD:SHA-256_SSWU_RO_ACS_")

// VerifyInput is the JSON payload for VerifyPresentation.
// MissingG1Hex is only set when k < n (selective disclosure).
type VerifyInput struct {
	IssuerID      string `json:"issuerId"`
	CommitmentHex string `json:"commitmentHex"`
	LeftG1Hex     string `json:"leftG1Hex"`
	LeftG2Hex     string `json:"leftG2Hex"`
	RightG1Hex    string `json:"rightG1Hex"`
	RightG2Hex    string `json:"rightG2Hex"`
	MissingG1Hex  string `json:"missingG1Hex,omitempty"`
}

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

func main() {
	issuerID := flag.String("issuer", "", "issuer identifier")
	userID := flag.String("user", "", "user identifier")
	attrsRaw := flag.String("attrs", "", "all credential attributes in order: k:v,k:v")
	showRaw := flag.String("show", "", "subset to disclose (empty = all): k:v,k:v")
	componentsJ := flag.String("components", "", "JSON array of C_i hexes from credential")
	tuHexFlag := flag.String("tu", "", "T_U hex (G1, 48 bytes)")
	rtHexFlag := flag.String("rt", "", "r_t hex (32 bytes)")
	stHexFlag := flag.String("st", "", "s_t hex (32 bytes)")
	pkHexFlag := flag.String("pubkey", "", "issuer public key hex (G2, 96 bytes)")
	flag.Parse()

	if *issuerID == "" || *userID == "" || *attrsRaw == "" ||
		*componentsJ == "" || *tuHexFlag == "" ||
		*rtHexFlag == "" || *stHexFlag == "" || *pkHexFlag == "" {
		fmt.Fprintln(os.Stderr, "usage: presentation-gen --issuer <id> --user <id> --attrs <all> [--show <subset>] --components <json> --tu <hex> --rt <hex> --st <hex> --pubkey <hex>")
		os.Exit(1)
	}

	allAttrs := splitTrim(*attrsRaw)
	if len(allAttrs) == 0 {
		die("--attrs must not be empty")
	}

	showList := []string{}
	if *showRaw == "" {
		showList = append(showList, allAttrs...)
	} else {
		showList = splitTrim(*showRaw)
	}
	if len(showList) == 0 {
		die("--show must contain at least one attribute")
	}

	showSet := make(map[string]bool, len(showList))
	for _, a := range showList {
		showSet[a] = true
	}

	var compHexes []string
	if err := json.Unmarshal([]byte(*componentsJ), &compHexes); err != nil {
		die("invalid --components JSON: " + err.Error())
	}
	if len(compHexes) != len(allAttrs) {
		die(fmt.Sprintf("--components count (%d) != --attrs count (%d)", len(compHexes), len(allAttrs)))
	}

	rt := frFrom(decodeHex(*rtHexFlag, "rt", 32))
	st := frFrom(decodeHex(*stHexFlag, "st", 32))

	pkBytes := decodeHex(*pkHexFlag, "pubkey", 96)
	var X bls12381.G2Affine
	if err := X.Unmarshal(pkBytes); err != nil {
		die("invalid --pubkey: " + err.Error())
	}

	tuBytes := decodeHex(*tuHexFlag, "tu", 48)
	var TU bls12381.G1Affine
	if err := TU.Unmarshal(tuBytes); err != nil {
		die("invalid --tu: " + err.Error())
	}

	var rtSt fr.Element
	rtSt.Mul(&rt, &st)
	var rtStBig big.Int
	rtSt.BigInt(&rtStBig)

	var stInv fr.Element
	stInv.Inverse(&st)
	var stInvBig big.Int
	stInv.BigInt(&stInvBig)

	var rtBig big.Int
	rt.BigInt(&rtBig)

	// leftG1 = r_t·s_t · Sum{sel} C_i
	var sumSel bls12381.G1Affine
	selFirst := true
	for i, attr := range allAttrs {
		if !showSet[attr] {
			continue
		}
		cb, err := hex.DecodeString(strings.TrimSpace(compHexes[i]))
		if err != nil || len(cb) != 48 {
			die(fmt.Sprintf("invalid components[%d]: must be 48-byte hex", i))
		}
		var Ci bls12381.G1Affine
		if err := Ci.Unmarshal(cb); err != nil {
			die(fmt.Sprintf("invalid components[%d] G1 point: %v", i, err))
		}
		if selFirst {
			sumSel = Ci
			selFirst = false
		} else {
			sumSel.Add(&sumSel, &Ci)
		}
	}
	if selFirst {
		// If no claimed shown attribute matches on-chain attribute strings,
		// use TU so verification proceeds and returns valid=false instead of aborting.
		sumSel = TU
	}
	var leftG1 bls12381.G1Affine
	leftG1.ScalarMultiplication(&sumSel, &rtStBig)

	// rightG1 = Σ H(claimed_shown_attributes)
	var rightG1 bls12381.G1Affine
	selFirst = true
	for _, attr := range showList {
		hm, err := bls12381.HashToG1([]byte(attr), dst)
		if err != nil {
			die("HashToG1 failed: " + err.Error())
		}
		if selFirst {
			rightG1 = hm
			selFirst = false
		} else {
			rightG1.Add(&rightG1, &hm)
		}
	}

	// leftG2 = s_t^-1 · G₂
	_, _, _, G2gen := bls12381.Generators()
	var leftG2 bls12381.G2Affine
	leftG2.ScalarMultiplication(&G2gen, &stInvBig)

	// rightG2 = r_t · X
	var rightG2 bls12381.G2Affine
	rightG2.ScalarMultiplication(&X, &rtBig)

	// commitmentHex = (r_t·s_t)·T_U  — for on-chain membership lookup
	var commitPoint bls12381.G1Affine
	commitPoint.ScalarMultiplication(&TU, &rtStBig)
	commitB := commitPoint.Bytes()

	// missingG1 = r_t·s_t · Sum{miss} H(m_j)
	var missingG1Hex string
	var sumMiss bls12381.G1Affine
	missFirst := true
	for _, attr := range allAttrs {
		if showSet[attr] {
			continue
		}
		hm, err := bls12381.HashToG1([]byte(attr), dst)
		if err != nil {
			die("HashToG1 failed: " + err.Error())
		}
		if missFirst {
			sumMiss = hm
			missFirst = false
		} else {
			sumMiss.Add(&sumMiss, &hm)
		}
	}
	if !missFirst {
		var missingG1 bls12381.G1Affine
		missingG1.ScalarMultiplication(&sumMiss, &rtStBig)
		mb := missingG1.Bytes()
		missingG1Hex = hex.EncodeToString(mb[:])
	}

	leftG1B := leftG1.Bytes()
	leftG2B := leftG2.Bytes()
	rightG1B := rightG1.Bytes()
	rightG2B := rightG2.Bytes()

	input := VerifyInput{
		IssuerID:      *issuerID,
		CommitmentHex: hex.EncodeToString(commitB[:]),
		LeftG1Hex:     hex.EncodeToString(leftG1B[:]),
		LeftG2Hex:     hex.EncodeToString(leftG2B[:]),
		RightG1Hex:    hex.EncodeToString(rightG1B[:]),
		RightG2Hex:    hex.EncodeToString(rightG2B[:]),
		MissingG1Hex:  missingG1Hex,
	}

	shown := append([]string{}, showList...)
	hidden := []string{}
	for _, a := range allAttrs {
		if showSet[a] {
			continue
		} else {
			hidden = append(hidden, a)
		}
	}

	out, _ := json.Marshal(input)
	fmt.Fprintf(os.Stderr, "=== Presentation: %s (issuer: %s) ===\n", *userID, *issuerID)
	fmt.Fprintf(os.Stderr, "Disclosed (%d): %v\n", len(shown), shown)
	fmt.Fprintf(os.Stderr, "Hidden    (%d): %v\n", len(hidden), hidden)
	fmt.Fprintf(os.Stderr, "commitmentHex: %s\n", input.CommitmentHex)
	if missingG1Hex != "" {
		fmt.Fprintf(os.Stderr, "missingG1Hex:  %s\n", missingG1Hex)
	}
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Print(string(out))
}

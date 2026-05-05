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

// PrepareOutput a --mode prepare kimenet JSON-je.
// Tartalmazza a rand-channelre küldendő vakított összegeket,
// az unblinding-hoz szükséges inverz skalárokat és a részleges VerifyInput-ot.
type PrepareOutput struct {
	// rand-channelre: randomcc.RandomizePresentation argumentumai
	BlindedSelHex  string `json:"blindedSelHex"`  // ℓ · Σ_{sel} C_i
	BlindedMissHex string `json:"blindedMissHex"` // ℓ'· (Σ_{miss} H(m) + u·G̅)
	// Unblinding skalárok (felhasználó tárolja)
	LInvHex      string `json:"lInvHex"`
	LPrimeInvHex string `json:"lPrimeInvHex"`
	// Részleges VerifyInput (LeftG1Hex és MissingG1Hex a finalize lépésben kerül be)
	BaseInput VerifyInput `json:"baseInput"`
	// Szelektív feltárás van-e?
	Selective bool `json:"selective"`
}

func main() {
	mode := flag.String("mode", "prepare", "prepare | finalize")

	// prepare mode flagek
	issuerID := flag.String("issuer", "", "issuer identifier")
	userID := flag.String("user", "", "user identifier")
	attrsRaw := flag.String("attrs", "", "all credential attributes in order: k:v,k:v")
	showRaw := flag.String("show", "", "subset to disclose (empty = all): k:v,k:v")
	componentsJ := flag.String("components", "", "JSON array of C_i hexes from credential")
	leftG2Flag := flag.String("left-g2", "", "s_t^-1·G2 hex (96 bytes), rand-channel output")
	rightG2Flag := flag.String("right-g2", "", "r_t·X hex (96 bytes), rand-channel output")
	commitFlag := flag.String("commitment", "", "credential commitment hex (48 bytes)")
	uGBarFlag := flag.String("u-g-bar", "", "u·G̅ hex (G1, 48 bytes) — felhasználó privacy faktora")

	// finalize mode flagek
	randLeftFlag := flag.String("rand-left", "", "rts·ℓ·selSum a randomcc-től (G1, 48 bytes)")
	randMissFlag := flag.String("rand-miss", "", "rts·ℓ'·missSum a randomcc-től (G1, 48 bytes)")
	lInvFlag := flag.String("l-inv", "", "ℓ⁻¹ skalár (32 byte hex)")
	lPrimeInvFlag := flag.String("l-prime-inv", "", "ℓ'⁻¹ skalár (32 byte hex)")
	baseInputFlag := flag.String("base-input", "", "PrepareOutput JSON a prepare lépésből")

	flag.Parse()

	switch *mode {
	case "prepare":
		runPrepare(issuerID, userID, attrsRaw, showRaw, componentsJ,
			leftG2Flag, rightG2Flag, commitFlag, uGBarFlag)
	case "finalize":
		runFinalize(randLeftFlag, randMissFlag, lInvFlag, lPrimeInvFlag, baseInputFlag)
	default:
		die("--mode must be 'prepare' or 'finalize'")
	}
}

// runPrepare kiszámolja a vakított összegeket és a részleges VerifyInput-ot.
// Cikk: Presentation Phase 1. lépés — a felhasználó ℓ, ℓ'∈Zq véletleneket választ,
// beadja ℓ·Σ_{sel}C_i  és  ℓ'·(Σ_{miss}H(m)+u·G̅) értékeket a rand-channelnek.
func runPrepare(issuerID, userID, attrsRaw, showRaw, componentsJ,
	leftG2Flag, rightG2Flag, commitFlag, uGBarFlag *string) {

	if *issuerID == "" || *userID == "" || *attrsRaw == "" ||
		*componentsJ == "" || *leftG2Flag == "" ||
		*rightG2Flag == "" || *commitFlag == "" {
		die("usage: presentation-gen --mode prepare --issuer <id> --user <id> --attrs <all> " +
			"[--show <subset>] --components <json> --left-g2 <hex> --right-g2 <hex> " +
			"--commitment <hex> [--u-g-bar <hex>]")
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

	leftG2Bytes := decodeHex(*leftG2Flag, "left-g2", 96)
	var leftG2 bls12381.G2Affine
	if err := leftG2.Unmarshal(leftG2Bytes); err != nil {
		die("invalid --left-g2: " + err.Error())
	}

	rightG2Bytes := decodeHex(*rightG2Flag, "right-g2", 96)
	var rightG2 bls12381.G2Affine
	if err := rightG2.Unmarshal(rightG2Bytes); err != nil {
		die("invalid --right-g2: " + err.Error())
	}

	commitBytes := decodeHex(*commitFlag, "commitment", 48)
	var commitment bls12381.G1Affine
	if err := commitment.Unmarshal(commitBytes); err != nil {
		die("invalid --commitment: " + err.Error())
	}

	// u·G̅ — a felhasználó privacy faktora (cikk: missing rész védelme)
	var uGBar bls12381.G1Affine
	hasUGBar := false
	if strings.TrimSpace(*uGBarFlag) != "" {
		ugb := decodeHex(*uGBarFlag, "u-g-bar", 48)
		if err := uGBar.Unmarshal(ugb); err != nil {
			die("invalid --u-g-bar: " + err.Error())
		}
		hasUGBar = true
	}

	// --- selSum = Σ_{sel} C_i ---
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
		die("no selected attributes found in component list")
	}

	// --- missSum = Σ_{miss} H(m_j) + u·G̅  (cikk: eq.1 — kötelező u·G̅!) ---
	// Az u·G̅ nélkül egy adverser, aki ismeri a lehetséges hiányzó attribútumokat,
	// ki tudja számítani Σ H(m_miss) és megtudhatja, hogy pontosan melyik hiányzik.
	selective := false
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
		selective = true
	}
	if selective {
		if hasUGBar {
			// missSum += u·G̅  — cikk szerint kötelező a privacy védelemhez
			sumMiss.Add(&sumMiss, &uGBar)
		} else {
			fmt.Fprintln(os.Stderr,
				"FIGYELMEZTETÉS: --u-g-bar nincs megadva → a hiányzó attribútumok "+
					"nem kapnak u·G̅ védelmet (cikkel ellentétes)!")
		}
	}

	// --- ℓ, ℓ' véletlen blinding skalárok generálása ---
	// Cél: a rand-chain (amelyet az issuer-ek üzemeltetnek) ne lássa a nyers
	// attribútum-összegeket. A user ℓ·selSum és ℓ'·missSum értékeket küld,
	// majd a visszakapott rand-chain-es szorzatot visszaosztja ℓ-lel ill. ℓ'-vel.
	var l, lPrime fr.Element
	if _, err := l.SetRandom(); err != nil {
		die("SetRandom failed for ℓ: " + err.Error())
	}
	if _, err := lPrime.SetRandom(); err != nil {
		die("SetRandom failed for ℓ': " + err.Error())
	}
	var lBig, lPrimeBig big.Int
	l.BigInt(&lBig)
	lPrime.BigInt(&lPrimeBig)

	// blindedSel  = ℓ · selSum
	var blindedSel bls12381.G1Affine
	blindedSel.ScalarMultiplication(&sumSel, &lBig)

	// blindedMiss = ℓ' · missSum  (csak szelektív feltárásnál van értelme)
	var blindedMiss bls12381.G1Affine
	if selective {
		blindedMiss.ScalarMultiplication(&sumMiss, &lPrimeBig)
	} else {
		// Nincs hiányzó attribútum → placeholder (randomcc-nek muszáj valid G1 pont)
		blindedMiss = blindedSel
	}

	// ℓ⁻¹, ℓ'⁻¹ — az unblinding lépéshez (finalize módban)
	var lInv, lPrimeInv fr.Element
	lInv.Inverse(&l)
	lPrimeInv.Inverse(&lPrime)
	lInvBytes := lInv.Bytes()
	lPrimeInvBytes := lPrimeInv.Bytes()

	// --- rightG1 = Σ H(megmutatott attrib) ---
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

	bsB := blindedSel.Bytes()
	bmB := blindedMiss.Bytes()
	leftG2B := leftG2.Bytes()
	rightG1B := rightG1.Bytes()
	rightG2B := rightG2.Bytes()
	commitB := commitment.Bytes()

	baseInput := VerifyInput{
		IssuerID:      *issuerID,
		CommitmentHex: hex.EncodeToString(commitB[:]),
		LeftG1Hex:     "", // finalize lépésben kerül be
		LeftG2Hex:     hex.EncodeToString(leftG2B[:]),
		RightG1Hex:    hex.EncodeToString(rightG1B[:]),
		RightG2Hex:    hex.EncodeToString(rightG2B[:]),
		MissingG1Hex:  "", // finalize lépésben kerül be
	}

	out := PrepareOutput{
		BlindedSelHex:  hex.EncodeToString(bsB[:]),
		BlindedMissHex: hex.EncodeToString(bmB[:]),
		LInvHex:        hex.EncodeToString(lInvBytes[:]),
		LPrimeInvHex:   hex.EncodeToString(lPrimeInvBytes[:]),
		BaseInput:      baseInput,
		Selective:      selective,
	}

	hidden := []string{}
	for _, a := range allAttrs {
		if !showSet[a] {
			hidden = append(hidden, a)
		}
	}
	fmt.Fprintf(os.Stderr, "=== Presentation prepare: %s (issuer: %s) ===\n", *userID, *issuerID)
	fmt.Fprintf(os.Stderr, "Disclosed (%d): %v\n", len(showList), showList)
	fmt.Fprintf(os.Stderr, "Hidden    (%d): %v\n", len(hidden), hidden)
	fmt.Fprintf(os.Stderr, "commitmentHex: %s\n", baseInput.CommitmentHex)
	fmt.Fprintf(os.Stderr, "Szelektív feltárás: %v, u·G̅ alkalmazva: %v\n\n", selective, selective && hasUGBar)

	j, _ := json.Marshal(out)
	fmt.Print(string(j))
}

// runFinalize elvégzi az unblinding lépést a randomcc visszatérési értékei alapján.
// Cikk: Presentation Phase — a felhasználó kiszámolja rₜsₜ·ΣxH(m_sel) és
// rₜsₜ·(ΣH(m_miss)+u·G̅) értékeket az ℓ⁻¹, ℓ'⁻¹ skalárokkal.
func runFinalize(randLeftFlag, randMissFlag, lInvFlag, lPrimeInvFlag, baseInputFlag *string) {
	if *randLeftFlag == "" || *lInvFlag == "" || *baseInputFlag == "" {
		die("usage: presentation-gen --mode finalize --rand-left <hex> --rand-miss <hex> " +
			"--l-inv <hex> --l-prime-inv <hex> --base-input <json>")
	}

	var prep PrepareOutput
	if err := json.Unmarshal([]byte(*baseInputFlag), &prep); err != nil {
		die("invalid --base-input JSON: " + err.Error())
	}

	// Unblind leftG1: ℓ⁻¹ · (rts·ℓ·selSum) = rts·selSum
	rlBytes := decodeHex(*randLeftFlag, "rand-left", 48)
	var randLeft bls12381.G1Affine
	if err := randLeft.Unmarshal(rlBytes); err != nil {
		die("invalid --rand-left G1 point: " + err.Error())
	}
	lInv := frFrom(decodeHex(*lInvFlag, "l-inv", 32))
	var lInvBig big.Int
	lInv.BigInt(&lInvBig)
	var leftG1 bls12381.G1Affine
	leftG1.ScalarMultiplication(&randLeft, &lInvBig)
	leftG1B := leftG1.Bytes()

	// Unblind missingG1: ℓ'⁻¹ · (rts·ℓ'·missSum) = rts·(Σ_{miss}H(m)+u·G̅)
	var missingG1Hex string
	if prep.Selective && strings.TrimSpace(*randMissFlag) != "" &&
		strings.TrimSpace(*lPrimeInvFlag) != "" {
		rmBytes := decodeHex(*randMissFlag, "rand-miss", 48)
		var randMiss bls12381.G1Affine
		if err := randMiss.Unmarshal(rmBytes); err != nil {
			die("invalid --rand-miss G1 point: " + err.Error())
		}
		lPrimeInv := frFrom(decodeHex(*lPrimeInvFlag, "l-prime-inv", 32))
		var lPrimeInvBig big.Int
		lPrimeInv.BigInt(&lPrimeInvBig)
		var missingG1 bls12381.G1Affine
		missingG1.ScalarMultiplication(&randMiss, &lPrimeInvBig)
		mb := missingG1.Bytes()
		missingG1Hex = hex.EncodeToString(mb[:])
	}

	finalInput := prep.BaseInput
	finalInput.LeftG1Hex = hex.EncodeToString(leftG1B[:])
	finalInput.MissingG1Hex = missingG1Hex

	j, _ := json.Marshal(finalInput)
	fmt.Print(string(j))
}

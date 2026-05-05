package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

const (
	statusOpen      = "OPEN"
	statusReady     = "READY"
	statusFinalized = "FINALIZED"
)

// SetupContract manages the randomization interval lifecycle on the rand-channel.
type SetupContract struct {
	contractapi.Contract
}

// IntervalRecord is stored under key interval:<intervalID>.
//
// A skaláris rt = r1*r2*... és st = s1*s2*... soha nem tárolódik összesítve.
// Helyette a per-node ri, si értékek tárolódnak, és a G1/G2 műveletek
// sorban alkalmazzák őket: minden node ri·si-vel szorozza az akkumulátort.
type IntervalRecord struct {
	IntervalID   string            `json:"intervalId"`
	Status       string            `json:"status"`
	ContribR     map[string]string `json:"contribR"`     // MSP → rᵢ (32 byte fr.Element hex)
	ContribS     map[string]string `json:"contribS"`     // MSP → sᵢ (32 byte fr.Element hex)
	ContribOrder []string          `json:"contribOrder"` // Beadás sorrendje
	Threshold    int               `json:"threshold"`
	// StInvG2Hex = (s₁·s₂·…·sₙ)⁻¹ · G₂  — szekvenciálisan számolva FinalizeInterval-kor
	// Verifikációhoz: e(leftG1, StInvG2) == e(ΣH(m_sel), rt·X)
	StInvG2Hex    string `json:"stInvG2Hex,omitempty"` // G2, 96 byte hex
	CreatedAt     string `json:"createdAtTx"`
	FinalizedAtTx string `json:"finalizedAtTx,omitempty"`
}

// RandomizationResult is returned by RandomizePresentation.
type RandomizationResult struct {
	IntervalID   string `json:"intervalID"`
	LeftG1Hex    string `json:"leftG1Hex"`
	MissingG1Hex string `json:"missingG1Hex"`
	// RtStHex NINCS — a kombinált rt·st skalár soha nem keletkezik
}

func (c *SetupContract) SetIntervalRandoms(ctx contractapi.TransactionContextInterface, intervalID string) error {
	if intervalID == "" {
		return fmt.Errorf("intervalID is required")
	}
	if err := requireIssuerRole(ctx); err != nil {
		return err
	}

	existing, err := loadIntervalRecord(ctx, intervalID)
	if err != nil {
		return err
	}
	if existing != nil {
		return fmt.Errorf("interval already initialized")
	}

	record := &IntervalRecord{
		IntervalID:   intervalID,
		Status:       statusOpen,
		ContribR:     map[string]string{},
		ContribS:     map[string]string{},
		ContribOrder: []string{},
		Threshold:    2,
		CreatedAt:    ctx.GetStub().GetTxID(),
	}

	if err := saveIntervalRecord(ctx, record); err != nil {
		return err
	}
	if err := ctx.GetStub().PutState(currentIntervalKey(), []byte(intervalID)); err != nil {
		return fmt.Errorf("failed to update current interval pointer: %w", err)
	}
	if err := emitEvent(ctx, "IntervalInitialized", record); err != nil {
		return err
	}

	return nil
}

// ContributeRandom regisztrálja az adott node rᵢ és sᵢ véletlen skalárjait.
// A kombinált rt = r1·r2·… és st = s1·s2·… skalár soha nem keletkezik;
// helyette a G1/G2 pontokat szekvenciálisan szorozzák a nodeok.
func (c *SetupContract) ContributeRandom(ctx contractapi.TransactionContextInterface, intervalID, riHex, siHex string) error {
	if intervalID == "" {
		return fmt.Errorf("intervalID is required")
	}
	if _, err := scalarFromHex(riHex, "riHex"); err != nil {
		return fmt.Errorf("invalid riHex: %w", err)
	}
	if _, err := scalarFromHex(siHex, "siHex"); err != nil {
		return fmt.Errorf("invalid siHex: %w", err)
	}
	if err := requireIssuerRole(ctx); err != nil {
		return err
	}

	record, err := loadIntervalRecord(ctx, intervalID)
	if err != nil {
		return err
	}
	if record == nil {
		return fmt.Errorf("interval not found")
	}
	if record.Status != statusOpen {
		return fmt.Errorf("interval not open for contributions")
	}

	clientMSP, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return fmt.Errorf("failed to get client MSP ID: %w", err)
	}
	if _, exists := record.ContribR[clientMSP]; exists {
		return fmt.Errorf("contribution already exists for org: %s", clientMSP)
	}

	record.ContribR[clientMSP] = strings.ToLower(riHex)
	record.ContribS[clientMSP] = strings.ToLower(siHex)
	record.ContribOrder = append(record.ContribOrder, clientMSP)
	if len(record.ContribR) >= record.Threshold {
		record.Status = statusReady
	}

	if err := saveIntervalRecord(ctx, record); err != nil {
		return err
	}
	if err := emitEvent(ctx, "RandomContributed", map[string]string{
		"intervalID": intervalID,
		"clientMSP":  clientMSP,
	}); err != nil {
		return err
	}

	return nil
}

// FinalizeInterval lezárja az intervallumot és kiszámolja a verifikációhoz
// szükséges StInvG2Hex = (s₁·s₂·…·sₙ)⁻¹ · G₂ pontot szekvenciálisan.
// Az rt és st skalárokat NEM tárolja — csak az egyes nodeok rᵢ, sᵢ értékei
// maradnak meg, a G1 műveletek mindig sorban alkalmazzák őket.
func (c *SetupContract) FinalizeInterval(ctx contractapi.TransactionContextInterface, intervalID string) error {
	if intervalID == "" {
		return fmt.Errorf("intervalID is required")
	}
	if err := requireIssuerRole(ctx); err != nil {
		return err
	}

	record, err := loadIntervalRecord(ctx, intervalID)
	if err != nil {
		return err
	}
	if record == nil {
		return fmt.Errorf("interval not found")
	}
	if len(record.ContribR) < record.Threshold {
		return fmt.Errorf("not enough contributions to finalize interval")
	}
	if record.Status == statusFinalized {
		return fmt.Errorf("interval already finalized")
	}

	// Szekvenciálisan számítjuk: (s₁·s₂·…·sₙ)⁻¹ · G₂
	// = sₙ⁻¹ · (… · (s₂⁻¹ · (s₁⁻¹ · G₂)))
	stInvG2Hex, err := computeStInvG2(record)
	if err != nil {
		return fmt.Errorf("failed to compute StInvG2: %w", err)
	}

	record.StInvG2Hex = stInvG2Hex
	record.Status = statusFinalized
	record.FinalizedAtTx = ctx.GetStub().GetTxID()

	if err := saveIntervalRecord(ctx, record); err != nil {
		return err
	}
	if err := emitEvent(ctx, "IntervalFinalized", map[string]string{
		"intervalID": intervalID,
		"stInvG2Hex": stInvG2Hex,
	}); err != nil {
		return err
	}

	return nil
}

// RandomizePresentation a presentation fázis szekvenciális G1 randomizálása.
// Minden node sorban alkalmazza rᵢ·sᵢ szorzóját a bemenő G1 pontokra.
// Az rt = r1·r2·… és st = s1·s2·… skalár soha nem keletkezik.
func (c *SetupContract) RandomizePresentation(ctx contractapi.TransactionContextInterface, intervalID, selSumHex, missSumHex string) (string, error) {
	if intervalID == "" || selSumHex == "" || missSumHex == "" {
		return "", fmt.Errorf("intervalID, selSumHex, and missSumHex are required")
	}
	if _, err := parseHexFixed(selSumHex, 48, "selSumHex"); err != nil {
		return "", err
	}
	if _, err := parseHexFixed(missSumHex, 48, "missSumHex"); err != nil {
		return "", err
	}

	record, err := loadIntervalRecord(ctx, intervalID)
	if err != nil {
		return "", err
	}
	if record == nil {
		return "", fmt.Errorf("interval not found")
	}
	if record.Status != statusFinalized {
		return "", fmt.Errorf("interval not finalized")
	}

	// selSum szekvenciális randomizálása: selOut = (r1·s1)·((r2·s2)·(… selSum))
	selBytes, _ := parseHexFixed(selSumHex, 48, "selSumHex")
	var selG1 bls12381.G1Affine
	if err := selG1.Unmarshal(selBytes); err != nil {
		return "", fmt.Errorf("invalid selSumHex G1 point: %w", err)
	}
	leftOut, err := seqApplyRiSiG1(record, &selG1)
	if err != nil {
		return "", err
	}
	leftBytes := leftOut.Bytes()

	// missSum szekvenciális randomizálása
	missBytes, _ := parseHexFixed(missSumHex, 48, "missSumHex")
	var missG1 bls12381.G1Affine
	if err := missG1.Unmarshal(missBytes); err != nil {
		return "", fmt.Errorf("invalid missSumHex G1 point: %w", err)
	}
	missingOut, err := seqApplyRiSiG1(record, &missG1)
	if err != nil {
		return "", err
	}
	missingBytes := missingOut.Bytes()

	result := RandomizationResult{
		IntervalID:   intervalID,
		LeftG1Hex:    hex.EncodeToString(leftBytes[:]),
		MissingG1Hex: hex.EncodeToString(missingBytes[:]),
	}

	audit := map[string]string{
		"intervalID": intervalID,
		"txID":       ctx.GetStub().GetTxID(),
	}
	auditBytes, err := json.Marshal(audit)
	if err != nil {
		return "", fmt.Errorf("failed to marshal audit payload: %w", err)
	}
	if err := ctx.GetStub().PutState("randreq:"+ctx.GetStub().GetTxID(), auditBytes); err != nil {
		return "", fmt.Errorf("failed to persist randomization audit record: %w", err)
	}

	resultBytes, err := json.Marshal(result)
	if err != nil {
		return "", fmt.Errorf("failed to marshal randomization result: %w", err)
	}
	return string(resultBytes), nil
}

// ComputeCommitment szekvenciálisan alkalmazza az egyes nodeok rᵢ·sᵢ szorzóját
// a TU_comm = TU + xu·G̅ G1 pontra. Az rt·st skalár soha nem keletkezik.
// Csak issuer jogosultság szükséges.
func (c *SetupContract) ComputeCommitment(ctx contractapi.TransactionContextInterface, intervalID, tuHex string) (string, error) {
	if intervalID == "" || strings.TrimSpace(tuHex) == "" {
		return "", fmt.Errorf("intervalID and tuHex are required")
	}
	if err := requireIssuerRole(ctx); err != nil {
		return "", err
	}

	tuBytes, err := parseHexFixed(tuHex, 48, "tuHex")
	if err != nil {
		return "", err
	}
	var TU bls12381.G1Affine
	if err := TU.Unmarshal(tuBytes); err != nil {
		return "", fmt.Errorf("invalid tuHex G1 point: %w", err)
	}

	record, err := loadIntervalRecord(ctx, intervalID)
	if err != nil {
		return "", err
	}
	if record == nil {
		return "", fmt.Errorf("interval not found")
	}
	if record.Status != statusFinalized {
		return "", fmt.Errorf("interval not finalized")
	}

	// Szekvenciális G1 szorzás: commitment = (r1·s1)·((r2·s2)·(… TU_comm))
	commitment, err := seqApplyRiSiG1(record, &TU)
	if err != nil {
		return "", err
	}
	compBytes := commitment.Bytes()
	return hex.EncodeToString(compBytes[:]), nil
}

// GetStInvG2 visszaadja a (s₁·s₂·…·sₙ)⁻¹ · G₂ verifikációs G2 pontot.
// A verifier ezt használja az eq.2 párosítás bal oldali G2 argumentumaként.
func (c *SetupContract) GetStInvG2(ctx contractapi.TransactionContextInterface, intervalID string) (string, error) {
	record, err := loadIntervalRecord(ctx, intervalID)
	if err != nil {
		return "", err
	}
	if record == nil {
		return "", fmt.Errorf("interval not found")
	}
	if record.StInvG2Hex == "" {
		return "", fmt.Errorf("stInvG2 not available for interval (not finalized?)")
	}
	return record.StInvG2Hex, nil
}

// ApplyRtToG2 kiszámítja az rt · inputG2 = (r1·r2·…·rn) · inputG2 értéket
// szekvenciálisan. Jellemzően inputG2 = X (issuer publikus kulcs), így
// az eredmény rt·X, amit a verifier az eq.2 párosításban használ.
// Az rt skalár soha nem keletkezik összesítve.
func (c *SetupContract) ApplyRtToG2(ctx contractapi.TransactionContextInterface, intervalID, g2PointHex string) (string, error) {
	if _, err := parseHexFixed(g2PointHex, 96, "g2PointHex"); err != nil {
		return "", err
	}
	record, err := loadIntervalRecord(ctx, intervalID)
	if err != nil {
		return "", err
	}
	if record == nil {
		return "", fmt.Errorf("interval not found")
	}
	if record.Status != statusFinalized {
		return "", fmt.Errorf("interval not finalized")
	}

	g2Bytes, _ := parseHexFixed(g2PointHex, 96, "g2PointHex")
	var acc bls12381.G2Affine
	if err := acc.Unmarshal(g2Bytes); err != nil {
		return "", fmt.Errorf("invalid g2PointHex: %w", err)
	}

	// Szekvenciális G2 szorzás rᵢ-vel: acc = r1·(r2·(…·(rn·inputG2)))
	for _, msp := range record.ContribOrder {
		ri, err := scalarFromHex(record.ContribR[msp], "ri("+msp+")")
		if err != nil {
			return "", err
		}
		var riBig big.Int
		ri.BigInt(&riBig)
		acc.ScalarMultiplication(&acc, &riBig)
	}

	outBytes := acc.Bytes()
	return hex.EncodeToString(outBytes[:]), nil
}

func (c *SetupContract) GetIntervalParameters(ctx contractapi.TransactionContextInterface, intervalID string) (string, error) {
	record, err := loadIntervalRecord(ctx, intervalID)
	if err != nil {
		return "", err
	}
	if record == nil {
		return "", fmt.Errorf("interval not found")
	}
	recordBytes, err := json.Marshal(record)
	if err != nil {
		return "", fmt.Errorf("failed to marshal interval record: %w", err)
	}
	return string(recordBytes), nil
}

func (c *SetupContract) GetCurrentInterval(ctx contractapi.TransactionContextInterface) (string, error) {
	value, err := ctx.GetStub().GetState(currentIntervalKey())
	if err != nil {
		return "", fmt.Errorf("failed to read current interval pointer: %w", err)
	}
	if value == nil {
		return "", fmt.Errorf("current interval is not set")
	}
	return string(value), nil
}

func main() {
	cc, err := contractapi.NewChaincode(&SetupContract{})
	if err != nil {
		panic(err.Error())
	}
	if err := cc.Start(); err != nil {
		panic(err.Error())
	}
}

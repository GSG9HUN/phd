package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	fr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

func requireIssuerRole(ctx contractapi.TransactionContextInterface) error {
	val, found, err := ctx.GetClientIdentity().GetAttributeValue("role")
	if err != nil {
		return fmt.Errorf("failed to read client attribute 'role': %w", err)
	}
	if !found || val != "issuer" {
		return fmt.Errorf("access denied: 'issuer' role required")
	}
	return nil
}

func intervalKey(intervalID string) string {
	return "interval:" + intervalID
}

func currentIntervalKey() string {
	return "interval:current"
}

func loadIntervalRecord(ctx contractapi.TransactionContextInterface, intervalID string) (*IntervalRecord, error) {
	if intervalID == "" {
		return nil, fmt.Errorf("intervalID is required")
	}
	state, err := ctx.GetStub().GetState(intervalKey(intervalID))
	if err != nil {
		return nil, fmt.Errorf("failed to read interval from world state: %w", err)
	}
	if state == nil {
		return nil, nil
	}

	var record IntervalRecord
	if err := json.Unmarshal(state, &record); err != nil {
		return nil, fmt.Errorf("failed to decode interval record: %w", err)
	}
	if record.ContribR == nil {
		record.ContribR = map[string]string{}
	}
	if record.ContribS == nil {
		record.ContribS = map[string]string{}
	}
	if record.ContribOrder == nil {
		record.ContribOrder = []string{}
	}
	return &record, nil
}

func saveIntervalRecord(ctx contractapi.TransactionContextInterface, record *IntervalRecord) error {
	recordBytes, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal interval record: %w", err)
	}
	if err := ctx.GetStub().PutState(intervalKey(record.IntervalID), recordBytes); err != nil {
		return fmt.Errorf("failed to persist interval record: %w", err)
	}
	return nil
}

func emitEvent(ctx contractapi.TransactionContextInterface, name string, payload any) error {
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal event %s: %w", name, err)
	}
	if err := ctx.GetStub().SetEvent(name, payloadBytes); err != nil {
		return fmt.Errorf("failed to emit event %s: %w", name, err)
	}
	return nil
}

// seqApplyRiSiG1 szekvenciálisan alkalmazza az összes node ri·si szorzóját
// a bemeneti G1 pontra: acc = (r1·s1)·((r2·s2)·(…·input))
// Az rt = r1·r2·… és st = s1·s2·… skalárok soha nem keletkeznek összesítve.
func seqApplyRiSiG1(record *IntervalRecord, input *bls12381.G1Affine) (bls12381.G1Affine, error) {
	acc := *input
	for _, msp := range record.ContribOrder {
		ri, err := scalarFromHex(record.ContribR[msp], "ri("+msp+")")
		if err != nil {
			return bls12381.G1Affine{}, err
		}
		si, err := scalarFromHex(record.ContribS[msp], "si("+msp+")")
		if err != nil {
			return bls12381.G1Affine{}, err
		}
		// risi = ri · si (fr szorzás)
		var risi fr.Element
		risi.Mul(&ri, &si)
		var risiBig big.Int
		risi.BigInt(&risiBig)
		acc.ScalarMultiplication(&acc, &risiBig)
	}
	return acc, nil
}

// computeStInvG2 szekvenciálisan számítja (s1·s2·…·sn)⁻¹ · G₂ értékét.
// Minden si⁻¹ sorban kerül alkalmazásra: acc = s1⁻¹·(s2⁻¹·(…·G₂))
// Az st = s1·s2·… skalár soha nem keletkezik összesítve.
func computeStInvG2(record *IntervalRecord) (string, error) {
	_, _, _, G2gen := bls12381.Generators()
	acc := G2gen

	for _, msp := range record.ContribOrder {
		si, err := scalarFromHex(record.ContribS[msp], "si("+msp+")")
		if err != nil {
			return "", err
		}
		var siInv fr.Element
		siInv.Inverse(&si)
		var siInvBig big.Int
		siInv.BigInt(&siInvBig)
		acc.ScalarMultiplication(&acc, &siInvBig)
	}

	outBytes := acc.Bytes()
	return hex.EncodeToString(outBytes[:]), nil
}

func scalarFromHex(value string, field string) (fr.Element, error) {
	b, err := parseHexFixed(value, 32, field)
	if err != nil {
		return fr.Element{}, err
	}
	var out fr.Element
	out.SetBytes(b)
	if out.IsZero() {
		return fr.Element{}, fmt.Errorf("%s must be non-zero", field)
	}
	return out, nil
}

func parseHexFixed(value string, size int, field string) ([]byte, error) {
	clean := strings.TrimSpace(value)
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("%s is not valid hex: %w", field, err)
	}
	if len(b) != size {
		return nil, fmt.Errorf("%s size must be %d bytes, got %d", field, size, len(b))
	}
	return b, nil
}

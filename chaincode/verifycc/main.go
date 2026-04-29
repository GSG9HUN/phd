package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// VerifyContract implements the verification phase of the anonymous credential system.
type VerifyContract struct {
	contractapi.Contract
}

// VerifyInput is the JSON payload passed to VerifyPresentation.
// All G1 points are 48-byte compressed hex; G2 points are 96-byte compressed hex.
//
// Pairing equation checked:
//
//	e(LeftG1, LeftG2) == e(RightG1, RightG2)
//	e(r_t·s_t·SumxH(m), s_t^-1·G₂) == e(Sum{H(m)}, r_t·X)
type VerifyInput struct {
	IssuerID      string `json:"issuerId"`
	CommitmentHex string `json:"commitmentHex"`          // G1, 48 bytes – for membership check
	LeftG1Hex     string `json:"leftG1Hex"`              // r_t·s_t·Sum{sel} C_i,  G1 48 bytes
	LeftG2Hex     string `json:"leftG2Hex"`              // s_t^-1·G₂,        G2 96 bytes
	RightG1Hex    string `json:"rightG1Hex"`             // Sum{H(m)},            G1 48 bytes
	RightG2Hex    string `json:"rightG2Hex"`             // r_t·X,            G2 96 bytes
	MissingG1Hex  string `json:"missingG1Hex,omitempty"` // r_t·s_t·Sum{miss} H(m), G1 48 bytes (k<n)
}

// VerifyResult is the JSON response returned by VerifyPresentation.
type VerifyResult struct {
	Valid      bool   `json:"valid"`
	TxID       string `json:"txId"`
	IssuerID   string `json:"issuerId"`
	FailReason string `json:"failReason,omitempty"`
}

// VerifyPresentation verifies an anonymous credential presentation.
// It checks the pairing equation and commitment list membership.
//
//   - setupCCName: name of the setupcc chaincode on the same channel (e.g. "setupcc")
//   - issueCCName: name of the issuancecc chaincode on the same channel (e.g. "issuancecc")
func (c *VerifyContract) VerifyPresentation(
	ctx contractapi.TransactionContextInterface,
	verifyInputJSON, setupCCName, issueCCName string,
) (string, error) {
	if err := ensureVerifierRole(ctx); err != nil {
		return "", err
	}

	var input VerifyInput
	if err := json.Unmarshal([]byte(verifyInputJSON), &input); err != nil {
		return "", fmt.Errorf("invalid input JSON: %w", err)
	}
	if strings.TrimSpace(input.IssuerID) == "" {
		return "", fmt.Errorf("issuerId is required")
	}

	result := VerifyResult{
		TxID:     ctx.GetStub().GetTxID(),
		IssuerID: input.IssuerID,
	}

	// --- Parse G1 points (48 bytes each) ---
	leftG1Bytes, err := parseHexFixed(input.LeftG1Hex, 48, "leftG1Hex")
	if err != nil {
		return "", err
	}
	rightG1Bytes, err := parseHexFixed(input.RightG1Hex, 48, "rightG1Hex")
	if err != nil {
		return "", err
	}
	commitBytes, err := parseHexFixed(input.CommitmentHex, 48, "commitmentHex")
	if err != nil {
		return "", err
	}

	// --- Parse G2 points (96 bytes each) ---
	leftG2Bytes, err := parseHexFixed(input.LeftG2Hex, 96, "leftG2Hex")
	if err != nil {
		return "", err
	}
	rightG2Bytes, err := parseHexFixed(input.RightG2Hex, 96, "rightG2Hex")
	if err != nil {
		return "", err
	}

	var leftG1, rightG1, commit bls12381.G1Affine
	if err := leftG1.Unmarshal(leftG1Bytes); err != nil {
		return "", fmt.Errorf("invalid leftG1Hex: %w", err)
	}
	if err := rightG1.Unmarshal(rightG1Bytes); err != nil {
		return "", fmt.Errorf("invalid rightG1Hex: %w", err)
	}
	if err := commit.Unmarshal(commitBytes); err != nil {
		return "", fmt.Errorf("invalid commitmentHex: %w", err)
	}

	var leftG2, rightG2 bls12381.G2Affine
	if err := leftG2.Unmarshal(leftG2Bytes); err != nil {
		return "", fmt.Errorf("invalid leftG2Hex: %w", err)
	}
	if err := rightG2.Unmarshal(rightG2Bytes); err != nil {
		return "", fmt.Errorf("invalid rightG2Hex: %w", err)
	}

	// --- Pairing check: e(leftG1, leftG2) == e(rightG1, rightG2) ---
	// Rewritten as: e(leftG1, leftG2) · e(-rightG1, rightG2) == 1
	negRightG1 := new(bls12381.G1Affine).Neg(&rightG1)
	pairingOK, err := bls12381.PairingCheck(
		[]bls12381.G1Affine{leftG1, *negRightG1},
		[]bls12381.G2Affine{leftG2, rightG2},
	)
	if err != nil {
		return "", fmt.Errorf("pairing check failed: %w", err)
	}
	if !pairingOK {
		result.Valid = false
		result.FailReason = "pairing equation not satisfied"
		buf, _ := json.Marshal(result)
		return string(buf), nil
	}

	// --- Commitment membership check via issuancecc ---
	commitResp := ctx.GetStub().InvokeChaincode(
		issueCCName,
		[][]byte{[]byte("GetCommitmentList")},
		"", // same channel
	)
	if commitResp.Status != shim.OK {
		result.Valid = false
		result.FailReason = fmt.Sprintf("failed to get commitment list: %s", commitResp.Message)
		buf, _ := json.Marshal(result)
		return string(buf), nil
	}

	var commitList []struct {
		Index         int    `json:"index"`
		CommitmentHex string `json:"commitmentHex"`
	}
	if err := json.Unmarshal(commitResp.Payload, &commitList); err != nil {
		return "", fmt.Errorf("invalid commitment list payload: %w", err)
	}

	targetHex := strings.ToLower(hex.EncodeToString(commitBytes))
	inList := false
	for _, entry := range commitList {
		if strings.ToLower(entry.CommitmentHex) == targetHex {
			inList = true
			break
		}
	}

	result.Valid = inList
	if !inList {
		result.FailReason = "commitment not found in public list"
	}
	if !inList {
		buf, _ := json.Marshal(result)
		return string(buf), nil
	}

	// --- Eq.3: commitment validity check ---
	// Case k==n (all attrs shown): commitmentHex == leftG1Hex (same G1 point)
	// Case k<n  (selective):       e(leftG1, G₂)·e(missingG1, X)·e(-commitment, G₂) == 1
	if strings.TrimSpace(input.MissingG1Hex) == "" {
		// All attributes disclosed — commitment must equal leftG1
		if !strings.EqualFold(input.CommitmentHex, input.LeftG1Hex) {
			result.Valid = false
			result.FailReason = "Eq.3 failed: full-disclosure commitment mismatch"
			buf, _ := json.Marshal(result)
			return string(buf), nil
		}
	} else {
		// Selective disclosure — fetch issuer pubkey X from setupcc
		pkResp := ctx.GetStub().InvokeChaincode(
			setupCCName,
			[][]byte{[]byte("GetIssuerKey"), []byte(input.IssuerID)},
			"",
		)
		if pkResp.Status != shim.OK {
			return "", fmt.Errorf("failed to get issuer key: %s", pkResp.Message)
		}
		var issuerRec struct {
			PubKeyHex string `json:"pubKeyHex"`
		}
		if err := json.Unmarshal(pkResp.Payload, &issuerRec); err != nil {
			return "", fmt.Errorf("invalid issuer key payload: %w", err)
		}
		pkBytes, err := parseHexFixed(issuerRec.PubKeyHex, 96, "pubKeyHex")
		if err != nil {
			return "", fmt.Errorf("issuer pubkey from chain: %w", err)
		}
		var X bls12381.G2Affine
		if err := X.Unmarshal(pkBytes); err != nil {
			return "", fmt.Errorf("invalid issuer pubkey G2 point: %w", err)
		}

		missingBytes, err := parseHexFixed(input.MissingG1Hex, 48, "missingG1Hex")
		if err != nil {
			return "", err
		}
		var missingG1 bls12381.G1Affine
		if err := missingG1.Unmarshal(missingBytes); err != nil {
			return "", fmt.Errorf("invalid missingG1Hex: %w", err)
		}

		// e(leftG1, G₂) · e(missingG1, X) · e(-commitment, G₂) == 1
		_, _, _, G2gen := bls12381.Generators()
		negCommit := new(bls12381.G1Affine).Neg(&commit)
		eq3OK, err := bls12381.PairingCheck(
			[]bls12381.G1Affine{leftG1, missingG1, *negCommit},
			[]bls12381.G2Affine{G2gen, X, G2gen},
		)
		if err != nil {
			return "", fmt.Errorf("Eq.3 pairing check error: %w", err)
		}
		if !eq3OK {
			result.Valid = false
			result.FailReason = "Eq.3 failed: selective disclosure commitment mismatch"
			buf, _ := json.Marshal(result)
			return string(buf), nil
		}
	}

	result.Valid = true
	buf, _ := json.Marshal(result)
	return string(buf), nil
}

// Ping is a simple readiness check.
func (c *VerifyContract) Ping(ctx contractapi.TransactionContextInterface) (string, error) {
	return "verifycc:ok", nil
}

func main() {
	cc, err := contractapi.NewChaincode(new(VerifyContract))
	if err != nil {
		panic(err.Error())
	}
	if err := cc.Start(); err != nil {
		panic(err.Error())
	}
}

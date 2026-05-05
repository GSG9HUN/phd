package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// appendToCommitmentList appends one commitment to the on-chain commitment list.
func appendToCommitmentList(ctx contractapi.TransactionContextInterface, commitmentHex string) error {
	var list []CommitmentEntry
	buf, err := ctx.GetStub().GetState(commitListKey)
	if err != nil {
		return fmt.Errorf("failed to read commitment list: %w", err)
	}
	if buf != nil {
		if err := json.Unmarshal(buf, &list); err != nil {
			return fmt.Errorf("failed to unmarshal commitment list: %w", err)
		}
	}
	list = append(list, CommitmentEntry{Index: len(list), CommitmentHex: commitmentHex})
	updated, err := json.Marshal(list)
	if err != nil {
		return fmt.Errorf("failed to marshal commitment list: %w", err)
	}
	return ctx.GetStub().PutState(commitListKey, updated)
}

// parseG1Point decodes compressed G1 hex.
func parseG1Point(hexStr, field string) (bls12381.G1Affine, error) {
	var pt bls12381.G1Affine
	clean := strings.TrimSpace(hexStr)
	b, err := hex.DecodeString(clean)
	if err != nil {
		return pt, fmt.Errorf("%s is not valid hex: %w", field, err)
	}
	if len(b) != 48 {
		return pt, fmt.Errorf("%s must be 48 bytes (compressed G1), got %d", field, len(b))
	}
	if err := pt.Unmarshal(b); err != nil {
		return pt, fmt.Errorf("%s is not a valid G1 point: %w", field, err)
	}
	return pt, nil
}

// ensureIssuerOrg verifies issuer role.
func ensureIssuerOrg(ctx contractapi.TransactionContextInterface) error {
	val, found, err := ctx.GetClientIdentity().GetAttributeValue("role")
	if err != nil {
		return fmt.Errorf("failed to read client attribute 'role': %w", err)
	}
	if !found || val != "issuer" {
		return fmt.Errorf("access denied: 'issuer' role required")
	}
	return nil
}

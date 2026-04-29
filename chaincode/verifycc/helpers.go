package main

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// SystemParams matches the JSON returned by setupcc.GetSystemParams.
type SystemParams struct {
	CurveName    string `json:"curveName"`
	GeneratorHex string `json:"generatorHex"`
	OrderHex     string `json:"orderHex"`
	SetByMSP     string `json:"setByMsp"`
	TxID         string `json:"txId"`
}

// IssuerKey matches the JSON returned by setupcc.GetIssuerKey.
type IssuerKey struct {
	IssuerID  string `json:"issuerId"`
	PubKeyHex string `json:"pubKeyHex"`
	CreatedBy string `json:"createdByMsp"`
	CreatedTx string `json:"createdTx"`
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

// ensureVerifierRole checks that the caller has 'issuer' role.
func ensureVerifierRole(ctx contractapi.TransactionContextInterface) error {
	val, found, err := ctx.GetClientIdentity().GetAttributeValue("role")
	if err != nil {
		return fmt.Errorf("failed to read client attribute 'role': %w", err)
	}
	if !found || val != "issuer" {
		return fmt.Errorf("access denied: 'issuer' role required")
	}
	return nil
}

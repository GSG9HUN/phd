package main

import (
	"encoding/hex"
	"fmt"
	"strings"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// SystemParams are public setup parameters published on verify-channel.
type SystemParams struct {
	CurveName    string `json:"curveName"`
	GeneratorHex string `json:"generatorHex"`
	OrderHex     string `json:"orderHex"`
	SetByMSP     string `json:"setByMsp"`
	TxID         string `json:"txId"`
}

// IssuerKey stores one issuer public key.
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

func issuerStateKey(issuerID string) string {
	return issuerKeyPrefix + issuerID
}

func deriveBLS12381SystemParams() (curveName, generatorHex, orderHex string) {
	_, _, g1, _ := bls12381.Generators()
	g1Bytes := g1.Bytes()

	curveName = "BLS12-381"
	generatorHex = hex.EncodeToString(g1Bytes[:])
	orderHex = fmt.Sprintf("%064x", fr.Modulus())

	return curveName, strings.ToLower(generatorHex), strings.ToLower(orderHex)
}

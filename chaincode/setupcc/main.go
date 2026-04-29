package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// SetupContract manages setup-layer public parameters and issuer public keys.
type SetupContract struct {
	contractapi.Contract
}

const (
	systemParamsKey = "setup:system-params"
	issuerKeyPrefix = "setup:issuer:"
)

// SetupParams stores setup parameters once. Only Org1MSP/Org2MSP may call it.
func (c *SetupContract) SetupParams(ctx contractapi.TransactionContextInterface, curveName, generatorHex, orderHex string) error {
	if err := ensureIssuerOrg(ctx); err != nil {
		return err
	}
	if strings.TrimSpace(curveName) == "" || strings.TrimSpace(generatorHex) == "" || strings.TrimSpace(orderHex) == "" {
		return fmt.Errorf("curveName, generatorHex and orderHex are required")
	}
	if _, err := parseHexFixed(generatorHex, 48, "generatorHex"); err != nil {
		return err
	}
	if _, err := parseHexFixed(orderHex, 32, "orderHex"); err != nil {
		return err
	}

	existing, err := ctx.GetStub().GetState(systemParamsKey)
	if err != nil {
		return fmt.Errorf("failed to read existing params: %w", err)
	}
	if existing != nil {
		return fmt.Errorf("system params already initialized")
	}

	mspID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return fmt.Errorf("failed to get client MSP ID: %w", err)
	}

	params := SystemParams{
		CurveName:    curveName,
		GeneratorHex: strings.ToLower(generatorHex),
		OrderHex:     strings.ToLower(orderHex),
		SetByMSP:     mspID,
		TxID:         ctx.GetStub().GetTxID(),
	}

	buf, err := json.Marshal(params)
	if err != nil {
		return fmt.Errorf("failed to marshal system params: %w", err)
	}

	return ctx.GetStub().PutState(systemParamsKey, buf)
}

// SetupParamsAuto stores BLS12-381 setup parameters derived by the chaincode.
// Callers do not pass curve values explicitly.
func (c *SetupContract) SetupParamsAuto(ctx contractapi.TransactionContextInterface) error {
	curveName, generatorHex, orderHex := deriveBLS12381SystemParams()
	return c.SetupParams(ctx, curveName, generatorHex, orderHex)
}

// GetSystemParams returns the currently stored setup parameters.
func (c *SetupContract) GetSystemParams(ctx contractapi.TransactionContextInterface) (string, error) {
	buf, err := ctx.GetStub().GetState(systemParamsKey)
	if err != nil {
		return "", fmt.Errorf("failed to read system params: %w", err)
	}
	if buf == nil {
		return "", fmt.Errorf("system params not initialized")
	}
	return string(buf), nil
}

// RegisterIssuerKey stores one issuer public key (96-byte compressed G2 hex).
// Only Org1MSP/Org2MSP may write.
func (c *SetupContract) RegisterIssuerKey(ctx contractapi.TransactionContextInterface, issuerID, pubKeyHex string) error {
	if err := ensureIssuerOrg(ctx); err != nil {
		return err
	}
	if strings.TrimSpace(issuerID) == "" {
		return fmt.Errorf("issuerID is required")
	}
	if _, err := parseHexFixed(pubKeyHex, 96, "pubKeyHex"); err != nil {
		return err
	}

	params, err := ctx.GetStub().GetState(systemParamsKey)
	if err != nil {
		return fmt.Errorf("failed to read system params: %w", err)
	}
	if params == nil {
		return fmt.Errorf("system params must be initialized before issuer key registration")
	}

	mspID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return fmt.Errorf("failed to get client MSP ID: %w", err)
	}

	key := issuerStateKey(issuerID)
	existing, err := ctx.GetStub().GetState(key)
	if err != nil {
		return fmt.Errorf("failed to read issuer key: %w", err)
	}
	if existing != nil {
		return fmt.Errorf("issuer key already exists for issuerID: %s", issuerID)
	}

	rec := IssuerKey{
		IssuerID:  issuerID,
		PubKeyHex: strings.ToLower(pubKeyHex),
		CreatedBy: mspID,
		CreatedTx: ctx.GetStub().GetTxID(),
	}
	buf, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("failed to marshal issuer key: %w", err)
	}

	return ctx.GetStub().PutState(key, buf)
}

// GetIssuerKey returns one issuer key record by issuerID.
func (c *SetupContract) GetIssuerKey(ctx contractapi.TransactionContextInterface, issuerID string) (string, error) {
	if strings.TrimSpace(issuerID) == "" {
		return "", fmt.Errorf("issuerID is required")
	}

	buf, err := ctx.GetStub().GetState(issuerStateKey(issuerID))
	if err != nil {
		return "", fmt.Errorf("failed to read issuer key: %w", err)
	}
	if buf == nil {
		return "", fmt.Errorf("issuer key not found for issuerID: %s", issuerID)
	}
	return string(buf), nil
}

// Ping is a simple readiness check.
func (c *SetupContract) Ping(ctx contractapi.TransactionContextInterface) (string, error) {
	return "setupcc:ok", nil
}

func main() {
	cc, err := contractapi.NewChaincode(new(SetupContract))
	if err != nil {
		panic(err.Error())
	}
	if err := cc.Start(); err != nil {
		panic(err.Error())
	}
}

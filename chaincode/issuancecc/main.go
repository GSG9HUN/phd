package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

type IssuanceContract struct {
	contractapi.Contract
}

// CredentialRecord is the on-chain representation of one issued credential.
type CredentialRecord struct {
	UserID        string   `json:"userId"`
	IssuerID      string   `json:"issuerId"`
	TUHex         string   `json:"tuHex"`
	// TUCommHex = TU + xu·G̅  (G1 pont, 48 byte hex)
	// Ezt a ComputeCommitment-be kell átadni (nem a sima TU-t).
	// A felhasználó ebből számolja újra a commitmentHex-et presentationkor.
	TUCommHex     string   `json:"tuCommHex"`
	ComponentsHex []string `json:"componentsHex"`
	CommitmentHex string   `json:"commitmentHex"`
	IntervalID    string   `json:"intervalId"`
	CreatedByMSP  string   `json:"createdByMsp"`
	CreatedTx     string   `json:"createdTx"`
}

// CommitmentEntry is one element of the public commitment list.
type CommitmentEntry struct {
	Index         int    `json:"index"`
	CommitmentHex string `json:"commitmentHex"`
}

const (
	credPrefix    = "issuance:cred:"
	commitListKey = "issuance:commitlist"
)

// IssueCredential stores a user credential and publishes its commitment.
// The commitment must be pre-computed on the rand-channel (randomcc.ComputeCommitment)
// and passed in as commitmentHex.
//
// Parameters:
//   - userID         – unique user identifier
//   - issuerID       – issuer identifier (must match a registered issuer key)
//   - intervalID     – randomization interval identifier from rand-channel
//   - tuHex          – T_U = Σ Cᵢ as compressed G1 hex (48 bytes)
//   - tuCommHex      – T_U + xu·G̅ as compressed G1 hex (48 bytes); ez kerül a ComputeCommitment-be
//   - componentsJSON – JSON array of compressed G1 hex strings (one per attribute)
//   - commitmentHex  – (rₜ·sₜ)·(Tᵤ+xu·G̅) computed on rand-channel, compressed G1 hex (48 bytes)
func (c *IssuanceContract) IssueCredential(
	ctx contractapi.TransactionContextInterface,
	userID, issuerID, intervalID, tuHex, tuCommHex, componentsJSON, commitmentHex string,
) error {
	if err := ensureIssuerOrg(ctx); err != nil {
		return err
	}
	if strings.TrimSpace(userID) == "" {
		return fmt.Errorf("userID is required")
	}
	if strings.TrimSpace(issuerID) == "" {
		return fmt.Errorf("issuerID is required")
	}
	if strings.TrimSpace(intervalID) == "" {
		return fmt.Errorf("intervalID is required")
	}

	// Validate TU as a well-formed G1 point.
	if _, err := parseG1Point(tuHex, "tuHex"); err != nil {
		return err
	}

	// Validate TU_comm = TU + xu·G̅ as a well-formed G1 point.
	if strings.TrimSpace(tuCommHex) == "" {
		return fmt.Errorf("tuCommHex is required")
	}
	if _, err := parseG1Point(tuCommHex, "tuCommHex"); err != nil {
		return err
	}

	// Validate and normalize the per-attribute components.
	var components []string
	if err := json.Unmarshal([]byte(componentsJSON), &components); err != nil {
		return fmt.Errorf("componentsJSON is not a valid JSON array: %w", err)
	}
	if len(components) == 0 {
		return fmt.Errorf("at least one credential component is required")
	}
	for i, comp := range components {
		if _, err := parseG1Point(comp, fmt.Sprintf("components[%d]", i)); err != nil {
			return err
		}
		components[i] = strings.ToLower(strings.TrimSpace(comp))
	}

	// Reject duplicate issuance for the same user.
	credKey := credPrefix + userID
	existing, err := ctx.GetStub().GetState(credKey)
	if err != nil {
		return fmt.Errorf("failed to check existing credential: %w", err)
	}
	if existing != nil {
		return fmt.Errorf("credential already issued for userID: %s", userID)
	}

	// Validate the pre-computed commitment (must be a valid G1 point, 48 bytes).
	commitmentHex = strings.ToLower(strings.TrimSpace(commitmentHex))
	if _, err := parseG1Point(commitmentHex, "commitmentHex"); err != nil {
		return fmt.Errorf("invalid commitmentHex: %w", err)
	}

	mspID, _ := ctx.GetClientIdentity().GetMSPID()
	rec := CredentialRecord{
		UserID:        userID,
		IssuerID:      issuerID,
		TUHex:         strings.ToLower(strings.TrimSpace(tuHex)),
		TUCommHex:     strings.ToLower(strings.TrimSpace(tuCommHex)),
		ComponentsHex: components,
		CommitmentHex: commitmentHex,
		IntervalID:    strings.TrimSpace(intervalID),
		CreatedByMSP:  mspID,
		CreatedTx:     ctx.GetStub().GetTxID(),
	}
	buf, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("failed to marshal credential: %w", err)
	}
	if err := ctx.GetStub().PutState(credKey, buf); err != nil {
		return fmt.Errorf("failed to store credential: %w", err)
	}

	// Append to the public commitment list (commitment only, no userID).
	return appendToCommitmentList(ctx, commitmentHex)
}

// GetCommitmentList returns the public, permuted list of commitments (no userIDs exposed).
func (c *IssuanceContract) GetCommitmentList(
	ctx contractapi.TransactionContextInterface,
) (string, error) {
	buf, err := ctx.GetStub().GetState(commitListKey)
	if err != nil {
		return "", fmt.Errorf("failed to read commitment list: %w", err)
	}
	if buf == nil {
		return "[]", nil
	}
	return string(buf), nil
}

// GetCredential returns the full credential record for a given userID.
func (c *IssuanceContract) GetCredential(
	ctx contractapi.TransactionContextInterface,
	userID string,
) (string, error) {
	if strings.TrimSpace(userID) == "" {
		return "", fmt.Errorf("userID is required")
	}
	buf, err := ctx.GetStub().GetState(credPrefix + userID)
	if err != nil {
		return "", fmt.Errorf("failed to read credential: %w", err)
	}
	if buf == nil {
		return "", fmt.Errorf("credential not found for userID: %s", userID)
	}
	return string(buf), nil
}

// Ping is a simple readiness check.
func (c *IssuanceContract) Ping(
	ctx contractapi.TransactionContextInterface,
) (string, error) {
	return "issuancecc:ok", nil
}

func main() {
	cc, err := contractapi.NewChaincode(new(IssuanceContract))
	if err != nil {
		panic(err.Error())
	}
	if err := cc.Start(); err != nil {
		panic(err.Error())
	}
}

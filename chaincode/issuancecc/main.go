package main

// # Functions
//
//	SetIntervalParams(intervalID, rtHex, stHex) – store rₜ, sₜ for current interval
//	IssueCredential(userID, issuerID, tuHex, componentsJSON) – issue & commit
//	RerandomizeAll(newIntervalID, newRtHex, newStHex)        – re-blind + permute
//	GetCommitmentList()                                       – public list query
//	GetCredential(userID)                                     – full record query
//	GetIntervalParams()                                       – current interval query
//	Ping()                                                    – readiness check

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

type IssuanceContract struct {
	contractapi.Contract
}

// IntervalParams holds the randomization scalars rₜ and sₜ for one time interval.
type IntervalParams struct {
	IntervalID string `json:"intervalId"`
	RtHex      string `json:"rtHex"`
	StHex      string `json:"stHex"`
	SetByMSP   string `json:"setByMsp"`
	TxID       string `json:"txId"`
}

// CredentialRecord is the on-chain representation of one issued credential.
// TUHex and ComponentsHex store the G1 points computed by the issuer.
// CommitmentHex = (rₜ·sₜ)·TU is the blinded, chain-published commitment.
type CredentialRecord struct {
	UserID        string   `json:"userId"`
	IssuerID      string   `json:"issuerId"`
	TUHex         string   `json:"tuHex"`         //(compressed G1, 48 bytes)
	ComponentsHex []string `json:"componentsHex"` //(compressed G1 each)
	CommitmentHex string   `json:"commitmentHex"` //(compressed G1, 48 bytes)
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
	intervalParamsKey = "issuance:interval"
	credPrefix        = "issuance:cred:"
	commitListKey     = "issuance:commitlist"
)

// ── Write functions ──────────────────────────────────────────────────────────

// SetIntervalParams stores rₜ and sₜ for the current randomization interval.
// Only principals with the "issuer" attribute may call this.
func (c *IssuanceContract) SetIntervalParams(
	ctx contractapi.TransactionContextInterface,
	intervalID, rtHex, stHex string,
) error {
	if err := ensureIssuerOrg(ctx); err != nil {
		return err
	}
	if strings.TrimSpace(intervalID) == "" {
		return fmt.Errorf("intervalID is required")
	}
	if _, err := parseScalar(rtHex, "rtHex"); err != nil {
		return err
	}
	if _, err := parseScalar(stHex, "stHex"); err != nil {
		return err
	}

	mspID, _ := ctx.GetClientIdentity().GetMSPID()
	params := IntervalParams{
		IntervalID: intervalID,
		RtHex:      strings.ToLower(rtHex),
		StHex:      strings.ToLower(stHex),
		SetByMSP:   mspID,
		TxID:       ctx.GetStub().GetTxID(),
	}
	buf, err := json.Marshal(params)
	if err != nil {
		return fmt.Errorf("failed to marshal interval params: %w", err)
	}
	return ctx.GetStub().PutState(intervalParamsKey, buf)
}

// IssueCredential stores a user credential and publishes its commitment.
//
// Parameters:
//   - userID       – unique user identifier
//   - issuerID     – issuer identifier (must match a registered issuer key)
//   - tuHex        – T_U = Σ Cᵢ as compressed G1 hex (48 bytes)
//   - componentsJSON – JSON array of compressed G1 hex strings (one per attribute)
func (c *IssuanceContract) IssueCredential(
	ctx contractapi.TransactionContextInterface,
	userID, issuerID, tuHex, componentsJSON string,
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

	// Validate TU as a well-formed G1 point.
	TU, err := parseG1Point(tuHex, "tuHex")
	if err != nil {
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

	// Load current interval parameters.
	intervalBuf, err := ctx.GetStub().GetState(intervalParamsKey)
	if err != nil {
		return fmt.Errorf("failed to read interval params: %w", err)
	}
	if intervalBuf == nil {
		return fmt.Errorf("interval params not set; call SetIntervalParams first")
	}
	var interval IntervalParams
	if err := json.Unmarshal(intervalBuf, &interval); err != nil {
		return fmt.Errorf("failed to unmarshal interval params: %w", err)
	}

	// commitment = (rₜ · sₜ) · TU
	commitmentHex, err := computeCommitment(TU, interval.RtHex, interval.StHex)
	if err != nil {
		return fmt.Errorf("failed to compute commitment: %w", err)
	}

	mspID, _ := ctx.GetClientIdentity().GetMSPID()
	rec := CredentialRecord{
		UserID:        userID,
		IssuerID:      issuerID,
		TUHex:         strings.ToLower(strings.TrimSpace(tuHex)),
		ComponentsHex: components,
		CommitmentHex: commitmentHex,
		IntervalID:    interval.IntervalID,
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

// RerandomizeAll recomputes every commitment using new interval scalars,
// permutes the public list deterministically using the transaction ID, and
// updates the stored interval parameters.
func (c *IssuanceContract) RerandomizeAll(
	ctx contractapi.TransactionContextInterface,
	newIntervalID, newRtHex, newStHex string,
) error {
	if err := ensureIssuerOrg(ctx); err != nil {
		return err
	}
	if strings.TrimSpace(newIntervalID) == "" {
		return fmt.Errorf("newIntervalID is required")
	}
	if _, err := parseScalar(newRtHex, "newRtHex"); err != nil {
		return err
	}
	if _, err := parseScalar(newStHex, "newStHex"); err != nil {
		return err
	}

	// Iterate all stored credentials.
	iter, err := ctx.GetStub().GetStateByRange(credPrefix, credPrefix+"~")
	if err != nil {
		return fmt.Errorf("failed to query credentials: %w", err)
	}
	defer iter.Close()

	newCommitments := make([]CommitmentEntry, 0)
	idx := 0

	for iter.HasNext() {
		kv, err := iter.Next()
		if err != nil {
			return fmt.Errorf("iterator error: %w", err)
		}

		var rec CredentialRecord
		if err := json.Unmarshal(kv.Value, &rec); err != nil {
			return fmt.Errorf("failed to unmarshal credential for key %s: %w", kv.Key, err)
		}

		TU, err := parseG1Point(rec.TUHex, "stored TU for "+rec.UserID)
		if err != nil {
			return err
		}

		// Recompute commitment from the stored raw TU and new scalars.
		newCommitmentHex, err := computeCommitment(TU, newRtHex, newStHex)
		if err != nil {
			return fmt.Errorf("rerandomization failed for userID %s: %w", rec.UserID, err)
		}

		rec.CommitmentHex = newCommitmentHex
		rec.IntervalID = newIntervalID

		updated, err := json.Marshal(rec)
		if err != nil {
			return fmt.Errorf("failed to marshal updated credential: %w", err)
		}
		if err := ctx.GetStub().PutState(kv.Key, updated); err != nil {
			return fmt.Errorf("failed to update credential %s: %w", kv.Key, err)
		}

		newCommitments = append(newCommitments, CommitmentEntry{
			Index:         idx,
			CommitmentHex: newCommitmentHex,
		})
		idx++
	}

	// Deterministic permutation based on the transaction ID.
	permuted := deterministicPermute(newCommitments, ctx.GetStub().GetTxID())
	listBuf, err := json.Marshal(permuted)
	if err != nil {
		return fmt.Errorf("failed to marshal commitment list: %w", err)
	}
	if err := ctx.GetStub().PutState(commitListKey, listBuf); err != nil {
		return fmt.Errorf("failed to update commitment list: %w", err)
	}

	// Persist new interval params.
	mspID, _ := ctx.GetClientIdentity().GetMSPID()
	params := IntervalParams{
		IntervalID: newIntervalID,
		RtHex:      strings.ToLower(newRtHex),
		StHex:      strings.ToLower(newStHex),
		SetByMSP:   mspID,
		TxID:       ctx.GetStub().GetTxID(),
	}
	paramsBuf, err := json.Marshal(params)
	if err != nil {
		return fmt.Errorf("failed to marshal interval params: %w", err)
	}
	return ctx.GetStub().PutState(intervalParamsKey, paramsBuf)
}

// ── Query functions ──────────────────────────────────────────────────────────

// GetCommitmentList returns the public, permuted list of commitments.
// The list contains only commitment hex values; no userIDs are exposed.
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

// GetIntervalParams returns the current randomization interval parameters.
func (c *IssuanceContract) GetIntervalParams(
	ctx contractapi.TransactionContextInterface,
) (string, error) {
	buf, err := ctx.GetStub().GetState(intervalParamsKey)
	if err != nil {
		return "", fmt.Errorf("failed to read interval params: %w", err)
	}
	if buf == nil {
		return "", fmt.Errorf("interval params not set")
	}
	return string(buf), nil
}

// Ping is a simple readiness check.
func (c *IssuanceContract) Ping(
	ctx contractapi.TransactionContextInterface,
) (string, error) {
	return "issuancecc:ok", nil
}

// ── Cryptographic helpers ────────────────────────────────────────────────────

// computeCommitment calculates (rₜ · sₜ mod q) · TU and returns the
// compressed G1 point as a lowercase hex string.
func computeCommitment(TU bls12381.G1Affine, rtHex, stHex string) (string, error) {
	rtBig, err := parseScalar(rtHex, "rtHex")
	if err != nil {
		return "", err
	}
	stBig, err := parseScalar(stHex, "stHex")
	if err != nil {
		return "", err
	}

	// rₜ · sₜ mod q  (using fr.Element for field-correct reduction)
	var rtFr, stFr, prod fr.Element
	rtFr.SetBigInt(rtBig)
	stFr.SetBigInt(stBig)
	prod.Mul(&rtFr, &stFr)

	var prodBig big.Int
	prod.BigInt(&prodBig)

	// (rₜ·sₜ) · TU
	var commitment bls12381.G1Affine
	commitment.ScalarMultiplication(&TU, &prodBig)

	compBytes := commitment.Bytes() // [48]byte compressed
	return hex.EncodeToString(compBytes[:]), nil
}

// ── List helpers ─────────────────────────────────────────────────────────────

// appendToCommitmentList adds one new commitment to the on-chain list.
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

// deterministicPermute shuffles a CommitmentEntry slice using the first 8
// bytes of txID as an LCG seed (Fisher-Yates). This ensures all peers
// arrive at the same permutation deterministically.
func deterministicPermute(entries []CommitmentEntry, txID string) []CommitmentEntry {
	n := len(entries)
	if n <= 1 {
		return entries
	}
	txBytes, err := hex.DecodeString(txID)
	if err != nil || len(txBytes) < 8 {
		return entries
	}

	seed := int64(txBytes[0])<<56 | int64(txBytes[1])<<48 |
		int64(txBytes[2])<<40 | int64(txBytes[3])<<32 |
		int64(txBytes[4])<<24 | int64(txBytes[5])<<16 |
		int64(txBytes[6])<<8 | int64(txBytes[7])

	result := make([]CommitmentEntry, n)
	copy(result, entries)

	// Linear congruential generator (Numerical Recipes parameters)
	const lcgA = int64(1664525)
	const lcgC = int64(1013904223)
	state := seed
	for i := n - 1; i > 0; i-- {
		state = lcgA*state + lcgC
		j := int((state>>33)&0x7fffffff) % (i + 1)
		result[i], result[j] = result[j], result[i]
	}
	return result
}

// ── Validation helpers ───────────────────────────────────────────────────────

// parseG1Point decodes a lowercase hex string into a BLS12-381 G1Affine point.
// The input must be exactly 48 bytes (compressed form).
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

// parseScalar decodes a 32-byte big-endian hex string into a *big.Int.
func parseScalar(hexStr, field string) (*big.Int, error) {
	clean := strings.TrimSpace(hexStr)
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("%s is not valid hex: %w", field, err)
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("%s must be 32 bytes, got %d", field, len(b))
	}
	return new(big.Int).SetBytes(b), nil
}

// ensureIssuerOrg verifies that the calling client has the "issuer" role attribute.
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

func main() {
	cc, err := contractapi.NewChaincode(new(IssuanceContract))
	if err != nil {
		panic(err.Error())
	}
	if err := cc.Start(); err != nil {
		panic(err.Error())
	}
}

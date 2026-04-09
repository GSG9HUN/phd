package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// bls12381FrOrder is the BLS12-381 scalar field modulus.
var bls12381FrOrder, _ = new(big.Int).SetString("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)

// KeyContract only stores public keys on the ledger.
type KeyContract struct {
	contractapi.Contract
}

// RoundStep stores one public transition in the round history.
// Each step records which org updated the round and what (X, G) became after that update.
type RoundStep struct {
	OrgMSP string `json:"orgMsp"`
	X      string `json:"x"`
	G      string `json:"g"`
}

// RoundState is the full public state of one round.
// Initial* fields are immutable anchors, Current* fields move at each org step.
// H2 is the G2-side accumulator used for bilinear consistency checks.
type RoundState struct {
	RoundID   string      `json:"roundId"`
	UserID    string      `json:"userId"`
	InitialX  string      `json:"initialX"`
	InitialG  string      `json:"initialG"`
	InitialH2 string      `json:"initialH2"`
	CurrentX  string      `json:"currentX"`
	CurrentG  string      `json:"currentG"`
	CurrentH2 string      `json:"currentH2"`
	Step      int         `json:"step"`
	NextOrg   string      `json:"nextOrg"`
	Completed bool        `json:"completed"`
	History   []RoundStep `json:"history"`
}

var roundOrgs = []string{"Org1MSP", "Org2MSP", "Org3MSP"}

// roundStateKey builds the world-state key for the round's public JSON state.
func roundStateKey(roundID string) string {
	return "round:" + roundID
}

// roundRandomKey builds the private-data key used to store each org's local scalar r.
func roundRandomKey(roundID string) string {
	return "round-r:" + roundID
}

// nextOrgForStep returns which MSP is allowed to run the next step.
// step=0 -> Org1MSP, step=1 -> Org2MSP, step=2 -> Org3MSP.
func nextOrgForStep(step int) string {
	if step < 0 || step >= len(roundOrgs) {
		return ""
	}
	return roundOrgs[step]
}

// generatorPointHex returns compressed hex for the canonical G1 generator.
func generatorPointHex() string {
	var generator bls12381.G1Affine
	generator.ScalarMultiplicationBase(big.NewInt(1))
	compressed := generator.Bytes()
	return hex.EncodeToString(compressed[:])
}

// generatorPointG2Hex returns compressed hex for the canonical G2 generator.
func generatorPointG2Hex() string {
	var generator bls12381.G2Affine
	generator.ScalarMultiplicationBase(big.NewInt(1))
	compressed := generator.Bytes()
	return hex.EncodeToString(compressed[:])
}

// pointFromHex decodes and validates a compressed G1 point.
// Validation path:
// 1) hex decode
// 2) byte-length check
// 3) SetBytes (on-curve + subgroup checks)
// 4) explicit non-infinity guard
func pointFromHex(pointHex string) (*bls12381.G1Affine, error) {
	pointBytes, err := hex.DecodeString(pointHex)
	if err != nil {
		return nil, fmt.Errorf("point hex decoding error: %w", err)
	}
	if len(pointBytes) != 48 {
		return nil, fmt.Errorf("invalid compressed G1 point size: %d", len(pointBytes))
	}

	var point bls12381.G1Affine
	if _, err := point.SetBytes(pointBytes); err != nil {
		return nil, fmt.Errorf("invalid compressed G1 point: %w", err)
	}
	if !point.IsOnCurve() || point.IsInfinity() {
		return nil, fmt.Errorf("point is not a valid non-infinity G1 point")
	}

	return &point, nil
}

// pointToHex encodes a G1 point to compressed hex form (48-byte compressed point).
func pointToHex(point *bls12381.G1Affine) string {
	compressed := point.Bytes()
	return hex.EncodeToString(compressed[:])
}

// pointG2FromHex decodes and validates a compressed G2 point.
// Validation path mirrors G1 decode, but with 96-byte compressed size for G2.
func pointG2FromHex(pointHex string) (*bls12381.G2Affine, error) {
	pointBytes, err := hex.DecodeString(pointHex)
	if err != nil {
		return nil, fmt.Errorf("G2 point hex decoding error: %w", err)
	}
	if len(pointBytes) != 96 {
		return nil, fmt.Errorf("invalid compressed G2 point size: %d", len(pointBytes))
	}

	var point bls12381.G2Affine
	if _, err := point.SetBytes(pointBytes); err != nil {
		return nil, fmt.Errorf("invalid compressed G2 point: %w", err)
	}
	if !point.IsOnCurve() || point.IsInfinity() {
		return nil, fmt.Errorf("G2 point is not a valid non-infinity point")
	}

	return &point, nil
}

// pointG2ToHex encodes a G2 point to compressed hex form (96-byte compressed point).
func pointG2ToHex(point *bls12381.G2Affine) string {
	compressed := point.Bytes()
	return hex.EncodeToString(compressed[:])
}

// randomScalar samples a cryptographically secure scalar in [1, Fr-1].
// Zero is rejected so each step is guaranteed to be a non-trivial multiplication.
func randomScalar() (*big.Int, error) {
	for {
		scalar, err := rand.Int(rand.Reader, bls12381FrOrder)
		if err != nil {
			return nil, err
		}
		if scalar.Sign() != 0 {
			return scalar, nil
		}
	}
}

// scalarToBytes serializes a scalar to 32-byte big-endian form.
// Private data stores this stable representation for each org's secret r.
func scalarToBytes(scalar *big.Int) []byte {
	raw := scalar.Bytes()
	if len(raw) >= 32 {
		return raw
	}
	padded := make([]byte, 32)
	copy(padded[32-len(raw):], raw)
	return padded
}

// loadRoundState loads and decodes one round's public JSON state from world state.
func loadRoundState(ctx contractapi.TransactionContextInterface, roundID string) (*RoundState, error) {
	stateBytes, err := ctx.GetStub().GetState(roundStateKey(roundID))
	if err != nil {
		return nil, fmt.Errorf("failed to read round state: %w", err)
	}
	if stateBytes == nil {
		return nil, fmt.Errorf("round not found: %s", roundID)
	}

	var state RoundState
	if err := json.Unmarshal(stateBytes, &state); err != nil {
		return nil, fmt.Errorf("failed to decode round state: %w", err)
	}
	return &state, nil
}

// storeRoundState encodes and persists one round's public JSON state.
func storeRoundState(ctx contractapi.TransactionContextInterface, state *RoundState) error {
	stateBytes, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("failed to encode round state: %w", err)
	}
	return ctx.GetStub().PutState(roundStateKey(state.RoundID), stateBytes)
}

// implicitCollectionForClient resolves caller's org-private implicit collection name.
// Example: Org1MSP -> _implicit_org_Org1MSP.
func implicitCollectionForClient(ctx contractapi.TransactionContextInterface) (string, error) {
	mspID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return "", fmt.Errorf("failed to get client MSP ID: %w", err)
	}
	return "_implicit_org_" + mspID, nil
}

// RegisterPublicKey validates and stores a BLS12-381 G1 public key for a given userID.
// pubKeyHex: hex-encoded compressed G1 point (48 bytes = 96 hex characters).
// The private key is generated off-chain by the client (client-keygen tool).
func (c *KeyContract) RegisterPublicKey(ctx contractapi.TransactionContextInterface, userID, pubKeyHex string) error {
	if len(userID) == 0 {
		return fmt.Errorf("userID cannot be empty")
	}

	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return fmt.Errorf("public key hex decoding error: %w", err)
	}
	if len(pubKeyBytes) != 48 {
		return fmt.Errorf("invalid public key size: %d bytes (48 required)", len(pubKeyBytes))
	}

	// Validity check: ensure it points to a valid G1 curve point
	var pk bls12381.G1Affine
	if _, err := pk.SetBytes(pubKeyBytes); err != nil {
		return fmt.Errorf("invalid public key point: %w", err)
	}
	if !pk.IsOnCurve() || pk.IsInfinity() {
		return fmt.Errorf("public key is not a valid curve point")
	}

	// Only the public key is stored on the ledger
	return ctx.GetStub().PutState("pk:"+userID, pubKeyBytes)
}

// GetPublicKey returns the specific public key for a given userID. If not found, returns an error.
func (c *KeyContract) GetPublicKey(ctx contractapi.TransactionContextInterface, userID string) (string, error) {
	data, err := ctx.GetStub().GetState("pk:" + userID)
	if err != nil {
		return "", fmt.Errorf("ledger read error: %w", err)
	}
	if data == nil {
		return "", fmt.Errorf("public key not found for userID: %s", userID)
	}
	return hex.EncodeToString(data), nil
}

// StartRound creates the initial public round state from a previously registered public key.
// The round starts from (X, G), where X is the registered public key and G is the BLS12-381 generator.
func (c *KeyContract) StartRound(ctx contractapi.TransactionContextInterface, roundID, userID string) error {
	// 1) Validate inputs and enforce unique roundID.
	if len(roundID) == 0 || len(userID) == 0 {
		return fmt.Errorf("roundID and userID are required")
	}

	existing, err := ctx.GetStub().GetState(roundStateKey(roundID))
	if err != nil {
		return fmt.Errorf("failed to check round existence: %w", err)
	}
	if existing != nil {
		return fmt.Errorf("round already exists: %s", roundID)
	}

	// 2) Load and validate the registered public key X for this user.
	pkBytes, err := ctx.GetStub().GetState("pk:" + userID)
	if err != nil {
		return fmt.Errorf("failed to read registered public key: %w", err)
	}
	if pkBytes == nil {
		return fmt.Errorf("public key not found for userID: %s", userID)
	}

	var pk bls12381.G1Affine
	if _, err := pk.SetBytes(pkBytes); err != nil {
		return fmt.Errorf("stored public key is invalid: %w", err)
	}
	if !pk.IsOnCurve() || pk.IsInfinity() {
		return fmt.Errorf("stored public key is not a valid curve point")
	}

	// 3) Initialize anchors and current accumulators.
	//    InitialH2/CurrentH2 are the G2-side accumulators used in bilinear checks.
	publicKeyHex := hex.EncodeToString(pkBytes)
	generatorHex := generatorPointHex()
	generatorG2Hex := generatorPointG2Hex()
	state := &RoundState{
		RoundID:   roundID,
		UserID:    userID,
		InitialX:  publicKeyHex,
		InitialG:  generatorHex,
		InitialH2: generatorG2Hex,
		CurrentX:  publicKeyHex,
		CurrentG:  generatorHex,
		CurrentH2: generatorG2Hex,
		Step:      0,
		NextOrg:   nextOrgForStep(0),
		Completed: false,
		History:   []RoundStep{},
	}

	// 4) Persist round state.
	return storeRoundState(ctx, state)
}

// GetRound returns the full round state as JSON.
func (c *KeyContract) GetRound(ctx contractapi.TransactionContextInterface, roundID string) (string, error) {
	if len(roundID) == 0 {
		return "", fmt.Errorf("roundID is required")
	}

	state, err := loadRoundState(ctx, roundID)
	if err != nil {
		return "", err
	}

	stateBytes, err := json.Marshal(state)
	if err != nil {
		return "", fmt.Errorf("failed to encode round state: %w", err)
	}
	return string(stateBytes), nil
}

// ApplyOrgRandom enforces the Org1 -> Org2 -> Org3 order, generates an org-local scalar r,
// stores r in the caller's implicit private collection, and updates the public pair (X, G)
// to (r·X, r·G) on the ledger.
func (c *KeyContract) ApplyOrgRandom(ctx contractapi.TransactionContextInterface, roundID string) (string, error) {
	// 1) Load round and enforce sequence/order guards.
	if len(roundID) == 0 {
		return "", fmt.Errorf("roundID is required")
	}

	state, err := loadRoundState(ctx, roundID)
	if err != nil {
		return "", err
	}
	if state.Completed {
		return "", fmt.Errorf("round already completed: %s", roundID)
	}

	clientMSP, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return "", fmt.Errorf("failed to get client MSP ID: %w", err)
	}
	if clientMSP != state.NextOrg {
		return "", fmt.Errorf("round %s expects %s, got %s", roundID, state.NextOrg, clientMSP)
	}

	// 2) Decode current public accumulators from state.
	currentX, err := pointFromHex(state.CurrentX)
	if err != nil {
		return "", fmt.Errorf("invalid current X in round state: %w", err)
	}
	currentG, err := pointFromHex(state.CurrentG)
	if err != nil {
		return "", fmt.Errorf("invalid current G in round state: %w", err)
	}
	currentH2, err := pointG2FromHex(state.CurrentH2)
	if err != nil {
		return "", fmt.Errorf("invalid current H2 in round state: %w", err)
	}

	// 3) Generate fresh local random scalar r for this org.
	random, err := randomScalar()
	if err != nil {
		return "", fmt.Errorf("failed to generate random scalar: %w", err)
	}

	// 4) Public update with same r on both G1 and G2 accumulators.
	//    This shared-r update is what the bilinear check later verifies.
	var nextX bls12381.G1Affine
	nextX.ScalarMultiplication(currentX, random)

	var nextG bls12381.G1Affine
	nextG.ScalarMultiplication(currentG, random)

	var nextH2 bls12381.G2Affine
	nextH2.ScalarMultiplication(currentH2, random)

	// 5) Store this org's private r in its own implicit private collection.
	collection, err := implicitCollectionForClient(ctx)
	if err != nil {
		return "", err
	}
	if err := ctx.GetStub().PutPrivateData(collection, roundRandomKey(roundID), scalarToBytes(random)); err != nil {
		return "", fmt.Errorf("failed to store round random in private collection: %w", err)
	}

	// 6) Advance round state and append audit history entry.
	state.CurrentX = pointToHex(&nextX)
	state.CurrentG = pointToHex(&nextG)
	state.CurrentH2 = pointG2ToHex(&nextH2)
	state.Step++
	state.History = append(state.History, RoundStep{
		OrgMSP: clientMSP,
		X:      state.CurrentX,
		G:      state.CurrentG,
	})
	state.NextOrg = nextOrgForStep(state.Step)
	state.Completed = state.Step >= len(roundOrgs)
	if state.Completed {
		state.NextOrg = ""
	}

	// 7) Persist and return updated state snapshot.
	if err := storeRoundState(ctx, state); err != nil {
		return "", err
	}

	stateBytes, err := json.Marshal(state)
	if err != nil {
		return "", fmt.Errorf("failed to encode round state: %w", err)
	}
	return string(stateBytes), nil
}

// GetOrgRandom returns the caller org's random scalar for a round as hex.
func (c *KeyContract) GetOrgRandom(ctx contractapi.TransactionContextInterface, roundID string) (string, error) {
	// Reads only caller org's implicit collection, so each org can read only its own r.
	if len(roundID) == 0 {
		return "", fmt.Errorf("roundID is required")
	}

	collection, err := implicitCollectionForClient(ctx)
	if err != nil {
		return "", err
	}

	randomBytes, err := ctx.GetStub().GetPrivateData(collection, roundRandomKey(roundID))
	if err != nil {
		return "", fmt.Errorf("failed to read private round random: %w", err)
	}
	if randomBytes == nil {
		return "", fmt.Errorf("private round random not found for roundID: %s", roundID)
	}

	return hex.EncodeToString(randomBytes), nil
}

// GetOrgRandomHash returns the hash of an org's private round random.
func (c *KeyContract) GetOrgRandomHash(ctx contractapi.TransactionContextInterface, roundID, mspID string) (string, error) {
	// Hash is world-state visible and can be used for cross-org audit without revealing r.
	if len(roundID) == 0 || len(mspID) == 0 {
		return "", fmt.Errorf("roundID and mspID are required")
	}

	hash, err := ctx.GetStub().GetPrivateDataHash("_implicit_org_"+mspID, roundRandomKey(roundID))
	if err != nil {
		return "", fmt.Errorf("failed to read round random hash: %w", err)
	}
	if hash == nil {
		return "", fmt.Errorf("round random hash not found for roundID: %s and mspID: %s", roundID, mspID)
	}

	return hex.EncodeToString(hash), nil
}

// VerifyRoundBilinear verifies the chained multiplications with pairings.
// It checks both equalities:
//
//	e(CurrentX, InitialH2) == e(InitialX, CurrentH2)
//	e(CurrentG, InitialH2) == e(InitialG, CurrentH2)
//
// If both are true, CurrentX and CurrentG were multiplied by the same aggregate scalar.
func (c *KeyContract) VerifyRoundBilinear(ctx contractapi.TransactionContextInterface, roundID string) (string, error) {
	// 1) Load round and decode validated points from hex.
	if len(roundID) == 0 {
		return "", fmt.Errorf("roundID is required")
	}

	state, err := loadRoundState(ctx, roundID)
	if err != nil {
		return "", err
	}

	initialX, err := pointFromHex(state.InitialX)
	if err != nil {
		return "", fmt.Errorf("invalid initial X in round state: %w", err)
	}
	currentX, err := pointFromHex(state.CurrentX)
	if err != nil {
		return "", fmt.Errorf("invalid current X in round state: %w", err)
	}
	initialG, err := pointFromHex(state.InitialG)
	if err != nil {
		return "", fmt.Errorf("invalid initial G in round state: %w", err)
	}
	currentG, err := pointFromHex(state.CurrentG)
	if err != nil {
		return "", fmt.Errorf("invalid current G in round state: %w", err)
	}
	initialH2, err := pointG2FromHex(state.InitialH2)
	if err != nil {
		return "", fmt.Errorf("invalid initial H2 in round state: %w", err)
	}
	currentH2, err := pointG2FromHex(state.CurrentH2)
	if err != nil {
		return "", fmt.Errorf("invalid current H2 in round state: %w", err)
	}

	// 2) Compute both sides for X relation in GT and compare.
	leftX, err := bls12381.Pair([]bls12381.G1Affine{*currentX}, []bls12381.G2Affine{*initialH2})
	if err != nil {
		return "", fmt.Errorf("pairing error for currentX/initialH2: %w", err)
	}
	rightX, err := bls12381.Pair([]bls12381.G1Affine{*initialX}, []bls12381.G2Affine{*currentH2})
	if err != nil {
		return "", fmt.Errorf("pairing error for initialX/currentH2: %w", err)
	}

	// 3) Compute both sides for G relation in GT and compare.
	leftG, err := bls12381.Pair([]bls12381.G1Affine{*currentG}, []bls12381.G2Affine{*initialH2})
	if err != nil {
		return "", fmt.Errorf("pairing error for currentG/initialH2: %w", err)
	}
	rightG, err := bls12381.Pair([]bls12381.G1Affine{*initialG}, []bls12381.G2Affine{*currentH2})
	if err != nil {
		return "", fmt.Errorf("pairing error for initialG/currentH2: %w", err)
	}

	// 4) Report both checks and combined status.
	checkX := leftX.Equal(&rightX)
	checkG := leftG.Equal(&rightG)

	result := map[string]interface{}{
		"roundId":                roundID,
		"step":                   state.Step,
		"completed":              state.Completed,
		"xBilinearCheck":         checkX,
		"generatorBilinearCheck": checkG,
		"ok":                     checkX && checkG,
	}

	resultBytes, err := json.Marshal(result)
	if err != nil {
		return "", fmt.Errorf("failed to encode verification result: %w", err)
	}
	return string(resultBytes), nil
}

func main() {
	chaincode, err := contractapi.NewChaincode(&KeyContract{})
	if err != nil {
		panic(fmt.Sprintf("chaincode creation error: %v", err))
	}
	if err := chaincode.Start(); err != nil {
		panic(fmt.Sprintf("chaincode start error: %v", err))
	}
}

# BLS Round Chaincode

This chaincode implements a three-org round protocol on BLS12-381 points.

## Goal

The protocol starts from a registered public key `X` and the canonical generator `G`.
Each org generates a private scalar `r` inside its own endorsing peer, stores `r` in its implicit private collection, and publicly updates the round state:

- Org1: `X -> r1*X`, `G -> r1*G`
- Org2: `r1*X -> r2*r1*X`, `r1*G -> r2*r1*G`
- Org3: `r2*r1*X -> r3*r2*r1*X`, `r2*r1*G -> r3*r2*r1*G`

The chaincode also keeps a G2-side accumulator so the final result can be checked with a bilinear pairing.

## Main Data Model

`RoundState` stores the public state of one round:

- `InitialX`: starting public key
- `InitialG`: starting G1 generator
- `InitialH2`: starting G2 generator
- `CurrentX`: current public key accumulator in G1
- `CurrentG`: current generator accumulator in G1
- `CurrentH2`: current accumulator in G2
- `Step`: current step index
- `NextOrg`: which MSP may execute the next step
- `Completed`: whether all three orgs already updated the round
- `History`: public audit log of `(X, G)` after each org update

Private per-org random values are stored under the implicit collection key:

- `round-r:<roundID>`

World-state public round JSON is stored under:

- `round:<roundID>`

## Public Functions

### RegisterPublicKey

Stores a compressed G1 public key for a user.

Steps:

1. Decode hex input.
2. Validate byte length.
3. Validate curve and subgroup membership via `SetBytes`.
4. Store under `pk:<userID>`.

### GetPublicKey

Returns the stored public key for a user as hex.

### StartRound

Initializes a new round from an already registered public key.

Steps:

1. Ensure the round does not already exist.
2. Load the user's registered public key.
3. Set `InitialX`, `InitialG`, `InitialH2`.
4. Copy them into the `Current*` fields.
5. Set `NextOrg = Org1MSP`.
6. Persist the public round state.

### GetRound

Returns the full public JSON state of the round.

### ApplyOrgRandom

Runs one org step.

Steps:

1. Load the round.
2. Verify the caller MSP matches `NextOrg`.
3. Decode `CurrentX`, `CurrentG`, `CurrentH2`.
4. Generate a random scalar `r` using `crypto/rand`.
5. Compute:
   - `CurrentX = r * CurrentX`
   - `CurrentG = r * CurrentG`
   - `CurrentH2 = r * CurrentH2`
6. Store `r` in the caller org's implicit private collection.
7. Append a public history entry.
8. Advance `Step` and `NextOrg`.

### GetOrgRandom

Returns the caller org's own private scalar `r` for a given round as hex.

### GetOrgRandomHash

Returns the hash of an org's private scalar without revealing the scalar itself.

### VerifyRoundBilinear

Performs a deterministic pairing-based consistency check.

The function checks:

- `e(CurrentX, InitialH2) == e(InitialX, CurrentH2)`
- `e(CurrentG, InitialH2) == e(InitialG, CurrentH2)`

If both are true, then the same aggregate scalar acted on both public G1 accumulators.

## Why G2 Is Stored

The G2 accumulator is needed because the pairing maps:

- `e: G1 x G2 -> GT`

Without `CurrentH2`, the chaincode could not verify with pairings that the public updates on `X` and `G` are consistent with one shared aggregate scalar.

## Security Notes

- Public keys and public round state live in world state.
- Each org's random scalar stays in that org's implicit private collection.
- Point decoding uses `SetBytes`, which performs subgroup validation.
- The pairing function itself does not perform subgroup checks, so validating points before pairing is important.

## Typical Flow

1. Register a public key with `RegisterPublicKey`.
2. Start a round with `StartRound`.
3. Run `ApplyOrgRandom` as Org1.
4. Run `ApplyOrgRandom` as Org2.
5. Run `ApplyOrgRandom` as Org3.
6. Inspect the result with `GetRound`.
7. Audit randoms with `GetOrgRandom` / `GetOrgRandomHash`.
8. Verify consistency with `VerifyRoundBilinear`.
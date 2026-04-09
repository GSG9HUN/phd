# run-round.sh

This script runs the full three-org round protocol end to end against the deployed `keygen` chaincode.

File:

- `scripts/run-round.sh`

## What It Does

The script performs these steps in order:

1. Loads the Fabric test-network environment.
2. Checks that the selected user already has a registered public key on-chain.
3. Starts a new round with `StartRound`.
4. Runs `ApplyOrgRandom` as Org1.
5. Runs `ApplyOrgRandom` as Org2.
6. Runs `ApplyOrgRandom` as Org3.
7. Queries the final round state.
8. Queries each org's private random.
9. Queries the hashes of the private randoms.
10. Runs bilinear verification.

## Defaults

- Channel: `channel2`
- Chaincode: `keygen`
- User: `alice`
- Round ID: auto-generated as `round-<unix-timestamp>`

The auto-generated round ID makes repeated runs safe without manually changing the ID each time.

## Usage

From `test-network`:

```bash
./scripts/run-round.sh
```

Custom values:

```bash
./scripts/run-round.sh -r my-round -u alice -c channel2 -n keygen
```

Help:

```bash
./scripts/run-round.sh --help
```

## Arguments

- `-r`, `--round`: explicit round ID
- `-u`, `--user`: registered user ID
- `-c`, `--channel`: Fabric channel
- `-n`, `--cc`: chaincode name

## Requirements

Before running the script:

1. The Fabric test network must be running.
2. The `keygen` chaincode must already be deployed.
3. The selected user must already have a public key registered with `RegisterPublicKey`.
4. Org1, Org2, and Org3 peers must be available.

## Why `--waitForEvent` Is Used

Each org step updates public chain state.
The script uses `--waitForEvent` on invokes so the next step only starts after the previous transaction is committed.

Without this, Org2 or Org3 could read stale state and fail with an order-check error.

## Output Sections

The script prints these sections:

- registered public key check
- round start
- Org1 update
- Org2 update
- Org3 update
- final round state
- Org1 private random
- Org2 private random
- Org3 private random
- private random hashes
- bilinear verification result

## Notes

- The script reads each org's private random by switching peer context with `setGlobals`.
- Hash queries are done from Org1 context, because private-data hashes are publicly queryable from world state.
- The bilinear verification is also a public query and should return the same result on every endorser.
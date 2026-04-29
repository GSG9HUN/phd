# setupcc - Setup Phase Chaincode

This chaincode implements the on-chain part of the setup phase on the `verify-channel`.

## Setup Phase → Function Mapping

| Setup Phase Element | Implemented By | Notes |
|---|---|---|
| Select pairing-friendly curve, publish order q and base point | `SetupParams(curveName, generatorHex, orderHex)` | Write-once. Validates generator size (48 bytes) and order size (32 bytes). |
| Same, but auto-derived (no manual arguments) | `SetupParamsAuto()` | Chaincode derives BLS12-381 canonical parameters and stores them. |
| Read system parameters for verification | `GetSystemParams()` | Returns stored setup parameters as JSON. |
| Publish issuer public key `X = x * G` | `RegisterIssuerKey(issuerID, pubKeyHex)` | Each issuer key can be registered once. Requires setup to be initialized first. |
| Read back issuer public key | `GetIssuerKey(issuerID)` | Returns the issuer key record for the given ID. |
| Health check | `Ping()` | Returns `setupcc:ok`. |

## Function Reference

| Function | Arguments | Access | Description |
|---|---|---|---|
| `SetupParams` | `curveName`, `generatorHex`, `orderHex` | `role=issuer` | Validates and stores system parameters. Write-once. |
| `SetupParamsAuto` | — | `role=issuer` | Derives BLS12-381 parameters on-chain and calls `SetupParams` internally. |
| `GetSystemParams` | — | public | Returns stored system parameters as a JSON string. |
| `RegisterIssuerKey` | `issuerID`, `pubKeyHex` | `role=issuer` | Validates and stores an issuer public key (96-byte G2 hex). Duplicate-safe. |
| `GetIssuerKey` | `issuerID` | public | Returns the issuer key record for the given issuer ID as JSON. |
| `Ping` | — | public | Returns `setupcc:ok`. Used for liveness checks. |

## Ledger Keys

| Key | Content |
|---|---|
| `setup:system-params` | `SystemParams` JSON |
| `setup:issuer:<issuerID>` | `IssuerKey` JSON |

## Access Control

- **Write** (`SetupParams`, `SetupParamsAuto`, `RegisterIssuerKey`): requires `role=issuer` CA attribute
- **Read** (`GetSystemParams`, `GetIssuerKey`, `Ping`): public

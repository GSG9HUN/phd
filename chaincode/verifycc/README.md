# verifycc – Verification Chaincode

Implements the verification phase (paper §3.4).  
Runs on `verify-channel` and checks two things:

1. **Pairing equation** (paper Eq. 2) – that the credential attributes were signed with the issuer's secret key
2. **Commitment list membership** – that the user's commitment is present in the issuancecc public list

---

## Files

| File | Contents |
|---|---|
| `main.go` | `VerifyContract` and all chaincode methods |
| `helpers.go` | Shared types (`SystemParams`, `IssuerKey`) and helper functions |

---

## Pairing Equation (paper Eq. 2)

The statement to verify:

$$e(r_t \cdot s_t \cdot \sum x H(m_{i_j}),\; s_t^{-1} \cdot G_2) = e(\sum H(m_{i_j}),\; r_t \cdot X)$$

Where:
- $x$ – issuer secret key (known only to the issuer)
- $X = x \cdot G$ – issuer public key (stored on-chain in setupcc)
- $H(m)$ – attribute hash to G1
- $r_t$, $s_t$ – interval randomization scalars for the current time period
- $G_2$ – BLS12-381 G2 generator

The chaincode verifies this as:

```
e(leftG1, leftG2) · e(-rightG1, rightG2) == 1
```

Where:
- `leftG1`  = $r_t \cdot s_t \cdot \sum x H(m_{i_j})$  (G1, 48 bytes)
- `leftG2`  = $s_t^{-1} \cdot G_2$                     (G2, 96 bytes)
- `rightG1` = $\sum H(m_{i_j})$                         (G1, 48 bytes)
- `rightG2` = $r_t \cdot X$                             (G2, 96 bytes)

---

## Function Reference

| Function | Arguments | Access | Description |
|---|---|---|---|
| `VerifyPresentation` | `verifyInputJSON`, `setupCCName`, `issueCCName` | `verifier` or `issuer` | Main verification method. Checks pairing equation and commitment membership. |
| `Ping` | — | public | Returns `verifycc:ok`. Used for liveness checks. |

---

## `VerifyPresentation` Details

**Input JSON (`verifyInputJSON`):**

```json
{
  "issuerId":      "issuer-org1",
  "commitmentHex": "<48-byte G1 hex>",
  "leftG1Hex":     "<48-byte G1 hex>",
  "leftG2Hex":     "<96-byte G2 hex>",
  "rightG1Hex":    "<48-byte G1 hex>",
  "rightG2Hex":    "<96-byte G2 hex>"
}
```

**Return value (success):**

```json
{
  "valid": true,
  "txId": "abc123...",
  "issuerId": "issuer-org1"
}
```

**Return value (failure):**

```json
{
  "valid": false,
  "txId": "abc123...",
  "issuerId": "issuer-org1",
  "failReason": "pairing equation not satisfied"
}
```

**Example call:**

```bash
INPUT='{"issuerId":"issuer-org1","commitmentHex":"...","leftG1Hex":"...","leftG2Hex":"...","rightG1Hex":"...","rightG2Hex":"..."}'

peer chaincode invoke ... -c "{\"function\":\"VerifyPresentation\",\"Args\":[
  \"$INPUT\",
  \"setupcc\",
  \"issuancecc\"
]}"
```

**Internal flow:**

```
1. ensureVerifierRole()              – access control check
2. JSON unmarshal + hex validation   – parse input
3. Unmarshal G1/G2 points           – via gnark-crypto bls12-381
4. PairingCheck(leftG1, leftG2,     – pairing equation check
              -rightG1, rightG2)
5. InvokeChaincode("issuancecc",    – fetch commitment list
                  GetCommitmentList)
6. Search commitment in list        – membership check
7. Return VerifyResult JSON
```

---

## Deploy

```bash
./network.sh deployCC \
  -c verify-channel \
  -ccn verifycc \
  -ccp ./chaincode/verifycc \
  -ccl go \
  -ccv 1.0 \
  -ccs 1
```

> **Note:** `issuancecc` must also be running on `verify-channel`, otherwise the commitment list lookup will fail.

---

## Dependencies (same channel)

| Chaincode | Purpose | Called Method |
|---|---|---|
| `setupcc` | Retrieve issuer public key ($X$) | *(currently provided in input, not called directly)* |
| `issuancecc` | Retrieve commitment list | `GetCommitmentList` |

Both are reachable via `InvokeChaincode(..., "")` — the empty channel string refers to the same channel.

---

## Ledger Keys

verifycc does not write to the ledger. It reads from `issuancecc` via cross-chaincode invocation.

---

## Access Control

| Method | Required Role |
|---|---|
| `VerifyPresentation` | `verifier` or `issuer` |
| `Ping` | public |

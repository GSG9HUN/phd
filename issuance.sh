#!/usr/bin/env bash
# issuance.sh - Full issuance phase
#
# Expects the following to be already done (e.g. by init.sh or scenario_rand_to_verify.sh):
#   - randomcc deployed on rand-channel with a finalized interval
#   - issuancecc deployed on verify-channel
#   - INTERVAL_ID env var set (or passed as $1)
#
# Steps:
#   1. Build credential-gen (if missing)
#   2. Sign Alice attributes with issuer-org1 secret key
#   3. Compute commitment on rand-channel (randomcc.ComputeCommitment)
#   4. IssueCredential on verify-channel (issuancecc.IssueCredential)
#   5. Repeat for Bob (issuer-org2)
#   6. Query commitment list + individual credentials

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

export PATH="$SCRIPT_DIR/../bin:$PATH"
export FABRIC_CFG_PATH="$SCRIPT_DIR/../config"
export TEST_NETWORK_HOME="$SCRIPT_DIR"

RAND_CHANNEL="rand-channel"
RAND_CC="randomcc"
CHANNEL="verify-channel"
CHAINCODE_ISSUANCE="issuancecc"
KEYS_DIR="$SCRIPT_DIR/chaincode/issuer-keygen/keys"
CREDGEN_DIR="$SCRIPT_DIR/chaincode/credential-gen"

USER1_ID="alice"
USER1_ISSUER="issuer-org1"
USER1_ATTRS="name:Alice,age:30,role:student"

USER2_ID="bob"
USER2_ISSUER="issuer-org2"
USER2_ATTRS="name:Bob,age:25,role:employee"

log()  { echo -e "\n\033[1;34m>>> $*\033[0m"; }
ok()   { echo -e "\033[1;32m    OK: $*\033[0m"; }
fail() { echo -e "\033[1;31m    ERROR: $*\033[0m"; exit 1; }
need_cmd() { command -v "$1" >/dev/null 2>&1 || fail "Missing command: $1"; }

need_cmd peer
need_cmd go
need_cmd python3

: "${OVERRIDE_ORG:=}"
: "${VERBOSE:=false}"
source scripts/envVar.sh
setGlobals 1
ok "Org1 peer context set"

# Resolve interval ID: env var > first arg > read from rand-channel
if [[ -z "${INTERVAL_ID:-}" ]]; then
  if [[ -n "${1:-}" ]]; then
    INTERVAL_ID="$1"
  else
    INTERVAL_ID=$(peer chaincode query -C "$RAND_CHANNEL" -n "$RAND_CC" \
      -c '{"function":"GetCurrentInterval","Args":[]}' | tr -d '"[:space:]')
    [[ -n "$INTERVAL_ID" ]] || fail "Could not determine INTERVAL_ID from rand-channel"
  fi
fi
echo "    Using interval: $INTERVAL_ID"

invoke_rand() {
  peer chaincode invoke \
    -o localhost:7050 \
    --ordererTLSHostnameOverride orderer.example.com \
    --tls --cafile "$ORDERER_CA" \
    -C "$RAND_CHANNEL" -n "$RAND_CC" \
    --peerAddresses localhost:7051 --tlsRootCertFiles "$PEER0_ORG1_CA" \
    --peerAddresses localhost:9051 --tlsRootCertFiles "$PEER0_ORG2_CA" \
    -c "$1"
  sleep 2
}

query_rand() {
  peer chaincode query -C "$RAND_CHANNEL" -n "$RAND_CC" -c "$1"
}

invoke_issuance() {
  peer chaincode invoke \
    -o localhost:7050 \
    --ordererTLSHostnameOverride orderer.example.com \
    --tls --cafile "$ORDERER_CA" \
    -C "$CHANNEL" -n "$CHAINCODE_ISSUANCE" \
    --peerAddresses localhost:7051 --tlsRootCertFiles "$PEER0_ORG1_CA" \
    --peerAddresses localhost:9051 --tlsRootCertFiles "$PEER0_ORG2_CA" \
    -c "$1"
  sleep 2
}

query_issuance() {
  peer chaincode query -C "$CHANNEL" -n "$CHAINCODE_ISSUANCE" -c "$1"
}

# ─── 1. credential-gen build ─────────────────────────────────────────────────
log "1. credential-gen build (if missing)"
if [[ ! -f "$CREDGEN_DIR/credential-gen" ]]; then
  (cd "$CREDGEN_DIR" && go build -o credential-gen .)
  ok "credential-gen built"
else
  ok "credential-gen already exists"
fi

# ─── Helper: issue one credential ────────────────────────────────────────────
issue_credential() {
  local USER_ID="$1"
  local ISSUER_ID="$2"
  local ATTRS="$3"
  local ORG_NUM="$4"

  log "Signing $USER_ID attributes ($ISSUER_ID)"
  local SECRET_KEY="$KEYS_DIR/${ISSUER_ID}-secret.key"
  [[ -f "$SECRET_KEY" ]] || fail "Missing secret key: $SECRET_KEY (run init.sh first)"

  echo "    User:       $USER_ID"
  echo "    Issuer:     $ISSUER_ID"
  echo "    Attributes: $ATTRS"

  local CREDGEN_OUTPUT
  CREDGEN_OUTPUT=$("$CREDGEN_DIR/credential-gen" \
    --issuer "$ISSUER_ID" \
    --user   "$USER_ID" \
    --attrs  "$ATTRS" \
    --key    "$SECRET_KEY")
  echo "$CREDGEN_OUTPUT"

  local TU_HEX TU_COMM_HEX UG_BAR_HEX COMPONENTS
  TU_HEX=$(echo "$CREDGEN_OUTPUT"      | grep "^T_U (tuHex):"         | awk '{print $NF}')
  TU_COMM_HEX=$(echo "$CREDGEN_OUTPUT" | grep "^T_U+xuG̅ (tuCommHex):" | awk '{print $NF}')
  UG_BAR_HEX=$(echo "$CREDGEN_OUTPUT"  | grep "^u·G̅  (uGBarHex):"     | awk '{print $NF}')
  COMPONENTS=$(echo "$CREDGEN_OUTPUT"  | grep "^Components JSON:"      | sed 's/^Components JSON:       //')
  echo "    → tuHex:      $TU_HEX"
  echo "    → tuCommHex:  $TU_COMM_HEX"
  echo "    → uGBarHex:   $UG_BAR_HEX"

  # u·G̅ off-chain mentése (a felhasználó tárolja, presentation phase-hez kell)
  local UGBAR_FILE="$KEYS_DIR/${USER_ID}-ugbar.hex"
  echo "$UG_BAR_HEX" > "$UGBAR_FILE"
  ok "u·G̅ elmentve: $UGBAR_FILE"

  # ComputeCommitment: tuCommHex-et kell átadni (nem a sima tuHex-et)!
  local COMMITMENT_HEX
  COMMITMENT_HEX=$(query_rand \
    "{\"function\":\"ComputeCommitment\",\"Args\":[\"$INTERVAL_ID\",\"$TU_COMM_HEX\"]}" \
    | tr -d '"[:space:]')
  [[ -n "$COMMITMENT_HEX" ]] || fail "ComputeCommitment returned empty for $USER_ID"
  echo "    → commitment: $COMMITMENT_HEX"

  local COMPONENTS_STR
  COMPONENTS_STR=$(python3 -c "import sys,json; print(json.dumps(sys.stdin.read().strip()))" <<< "$COMPONENTS")

  setGlobals "$ORG_NUM"
  invoke_issuance "{\"function\":\"IssueCredential\",\"Args\":[\"$USER_ID\",\"$ISSUER_ID\",\"$INTERVAL_ID\",\"$TU_HEX\",\"$TU_COMM_HEX\",$COMPONENTS_STR,\"$COMMITMENT_HEX\"]}"
  setGlobals 1
  ok "$USER_ID credential issued ($ISSUER_ID)"
}

# ─── 2. Alice ────────────────────────────────────────────────────────────────
issue_credential "$USER1_ID" "$USER1_ISSUER" "$USER1_ATTRS" 1

# ─── 3. Bob ──────────────────────────────────────────────────────────────────
issue_credential "$USER2_ID" "$USER2_ISSUER" "$USER2_ATTRS" 2

# ─── 4. Commitment list ──────────────────────────────────────────────────────
log "4. Querying commitment list"
COMMITLIST=$(query_issuance '{"function":"GetCommitmentList","Args":[]}')
echo "    $COMMITLIST"
ok "Commitment list retrieved"

# ─── 5. Individual credentials ───────────────────────────────────────────────
log "5. Query Alice credential"
CRED_ALICE=$(query_issuance "{\"function\":\"GetCredential\",\"Args\":[\"$USER1_ID\"]}")
echo "    $CRED_ALICE"

log "5. Query Bob credential"
CRED_BOB=$(query_issuance "{\"function\":\"GetCredential\",\"Args\":[\"$USER2_ID\"]}")
echo "    $CRED_BOB"

ok "Issuance phase complete!"
echo ""
echo "Summary:"
echo "  Alice (issuer-org1) - commitmentHex: $(echo "$CRED_ALICE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('commitmentHex','n/a'))" 2>/dev/null || echo '(see above)')"
echo "  Bob   (issuer-org2) - commitmentHex: $(echo "$CRED_BOB"   | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('commitmentHex','n/a'))" 2>/dev/null || echo '(see above)')"

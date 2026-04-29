#!/usr/bin/env bash
# issuance.sh - Full issuance phase
#
# Steps:
#   1. Set interval parameters (r_t, s_t)
#   2. Build credential-gen (if missing)
#   3. Sign Alice attributes with issuer-org1 secret key -> IssueCredential
#   4. Sign Bob attributes with issuer-org2 secret key -> IssueCredential
#   5. Query commitment list
#   6. Query individual credentials

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

export PATH="$SCRIPT_DIR/../bin:$PATH"
export FABRIC_CFG_PATH="$SCRIPT_DIR/../config"
export TEST_NETWORK_HOME="$SCRIPT_DIR"

CHANNEL="verify-channel"
CHAINCODE_ISSUANCE="issuancecc"
KEYS_DIR="$SCRIPT_DIR/chaincode/issuer-keygen/keys"
CREDGEN_DIR="$SCRIPT_DIR/chaincode/credential-gen"

# ─── Users and their attributes ──────────────────────────────────────────────
USER1_ID="alice"
USER1_ISSUER="issuer-org1"
USER1_ATTRS="name:Alice,age:30,role:student"

USER2_ID="bob"
USER2_ISSUER="issuer-org2"
USER2_ATTRS="name:Bob,age:25,role:employee"

# ─── Helper functions ────────────────────────────────────────────────────────
log()  { echo -e "\n\033[1;34m>>> $*\033[0m"; }
ok()   { echo -e "\033[1;32m    OK: $*\033[0m"; }
fail() { echo -e "\033[1;31m    ERROR: $*\033[0m"; exit 1; }
need_cmd() { command -v "$1" >/dev/null 2>&1 || fail "Missing command: $1"; }

need_cmd peer
need_cmd go
need_cmd python3
need_cmd openssl

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

# ─── Environment setup ───────────────────────────────────────────────────────
log "Environment setup (Org1)"
: "${OVERRIDE_ORG:=}"
: "${VERBOSE:=false}"
source scripts/envVar.sh
setGlobals 1
ok "Org1 peer context set"

# ─── 1. Interval parameters ──────────────────────────────────────────────────
log "1. Setting interval parameters"

# TODO: In the final architecture, r_t and s_t should come from rand-channel:
#   RT_HEX = peer chaincode query -C rand-channel -n randcc -c '{"function":"GetRt","Args":["$INTERVAL_ID"]}'
#   ST_HEX = peer chaincode query -C rand-channel -n randcc -c '{"function":"GetSt","Args":["$INTERVAL_ID"]}'
#
# For now: local openssl rand placeholder (< q ensured: high byte = 00 -> < 2^248 < q)
INTERVAL_ID="interval-$(date +%s)"
RT_HEX="00$(openssl rand -hex 31)"
ST_HEX="00$(openssl rand -hex 31)"

echo "    Interval ID: $INTERVAL_ID"
echo "    r_t: $RT_HEX"
echo "    s_t: $ST_HEX"

invoke_issuance "{\"function\":\"SetIntervalParams\",\"Args\":[\"$INTERVAL_ID\",\"$RT_HEX\",\"$ST_HEX\"]}"
ok "Interval parameters set"

# Verification
INTERVAL=$(query_issuance '{"function":"GetIntervalParams","Args":[]}')
echo "    $INTERVAL"

# ─── 2. credential-gen build ──────────────────────────────────────────────────
log "2. credential-gen build (if missing)"
if [[ ! -f "$CREDGEN_DIR/credential-gen" ]]; then
  log "   Building credential-gen..."
  (cd "$CREDGEN_DIR" && go build -o credential-gen .)
  ok "   credential-gen built"
else
  ok "   credential-gen already exists"
fi

# ─── 3. Alice - issuer-org1 signing ──────────────────────────────────────────
log "3. Signing Alice attributes ($USER1_ISSUER)"

SECRET_KEY1="$KEYS_DIR/${USER1_ISSUER}-secret.key"
if [[ ! -f "$SECRET_KEY1" ]]; then
  fail "Missing secret key: $SECRET_KEY1 (run init.sh first)"
fi

echo "    User:          $USER1_ID"
echo "    Issuer:        $USER1_ISSUER"
echo "    Attributes:    $USER1_ATTRS"

# Parse credential-gen output
CREDGEN_OUTPUT1=$("$CREDGEN_DIR/credential-gen" \
  --issuer "$USER1_ISSUER" \
  --user   "$USER1_ID" \
  --attrs  "$USER1_ATTRS" \
  --key    "$SECRET_KEY1")

echo "$CREDGEN_OUTPUT1"

# Extract T_U and components from output
TU_HEX1=$(echo "$CREDGEN_OUTPUT1" | grep "^T_U (tuHex):" | awk '{print $NF}')
COMPONENTS1=$(echo "$CREDGEN_OUTPUT1" | grep "^Components JSON:" | sed 's/^Components JSON:   //')

echo "    → tuHex:      $TU_HEX1"
echo "    → components: $COMPONENTS1"

# componentsJSON must be passed as a string argument (chaincode unmarshals internally)
# Convert the JSON array to a JSON string (escape inner quotes)
COMPONENTS1_STR=$(python3 -c "import sys,json; print(json.dumps(sys.stdin.read().strip()))" <<< "$COMPONENTS1")

invoke_issuance "{\"function\":\"IssueCredential\",\"Args\":[\"$USER1_ID\",\"$USER1_ISSUER\",\"$TU_HEX1\",$COMPONENTS1_STR]}"
ok "Alice credential issued (issuer-org1)"

# ─── 4. Bob - issuer-org2 signing ────────────────────────────────────────────
log "4. Signing Bob attributes ($USER2_ISSUER)"

SECRET_KEY2="$KEYS_DIR/${USER2_ISSUER}-secret.key"
if [[ ! -f "$SECRET_KEY2" ]]; then
  fail "Missing secret key: $SECRET_KEY2 (run init.sh first)"
fi

echo "    User:          $USER2_ID"
echo "    Issuer:        $USER2_ISSUER"
echo "    Attributes:    $USER2_ATTRS"

CREDGEN_OUTPUT2=$("$CREDGEN_DIR/credential-gen" \
  --issuer "$USER2_ISSUER" \
  --user   "$USER2_ID" \
  --attrs  "$USER2_ATTRS" \
  --key    "$SECRET_KEY2")

echo "$CREDGEN_OUTPUT2"

TU_HEX2=$(echo "$CREDGEN_OUTPUT2" | grep "^T_U (tuHex):" | awk '{print $NF}')
COMPONENTS2=$(echo "$CREDGEN_OUTPUT2" | grep "^Components JSON:" | sed 's/^Components JSON:   //')

echo "    → tuHex:      $TU_HEX2"
echo "    → components: $COMPONENTS2"

COMPONENTS2_STR=$(python3 -c "import sys,json; print(json.dumps(sys.stdin.read().strip()))" <<< "$COMPONENTS2")

# Switch to Org2 context (same channel/chaincode for Alice and Bob,
# but Org2 endorsement requires Org2 peer; --peerAddresses already includes both)
setGlobals 2
invoke_issuance "{\"function\":\"IssueCredential\",\"Args\":[\"$USER2_ID\",\"$USER2_ISSUER\",\"$TU_HEX2\",$COMPONENTS2_STR]}"
setGlobals 1
ok "Bob credential issued (issuer-org2)"

# ─── 5. Commitment list ──────────────────────────────────────────────────────
log "5. Querying commitment list"
COMMITLIST=$(query_issuance '{"function":"GetCommitmentList","Args":[]}')
echo "    $COMMITLIST"
ok "Commitment list retrieved"

# ─── 6. Individual credential queries ────────────────────────────────────────
log "6. Query Alice credential"
CRED_ALICE=$(query_issuance "{\"function\":\"GetCredential\",\"Args\":[\"$USER1_ID\"]}")
echo "    $CRED_ALICE"

log "6. Query Bob credential"
CRED_BOB=$(query_issuance "{\"function\":\"GetCredential\",\"Args\":[\"$USER2_ID\"]}")
echo "    $CRED_BOB"

ok "Issuance phase complete!"
echo ""
echo "Summary:"
echo "  Alice (issuer-org1) - commitmentHex: $(echo "$CRED_ALICE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('commitmentHex','n/a'))" 2>/dev/null || echo '(see above)')"
echo "  Bob   (issuer-org2) - commitmentHex: $(echo "$CRED_BOB"   | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('commitmentHex','n/a'))" 2>/dev/null || echo '(see above)')"

#!/usr/bin/env bash
# init.sh - Full setup phase initialization
# Run from: ~/fabric-samples/test-network/
#
# Steps:
#   1. network up (with -ca flag)
#   2. deploy setupcc to verify-channel
#   3. environment setup
#   4. chaincode ping check
#   5. auto-initialize system params
#   6. query system params
#   7. generate issuer keypairs for all orgs + register on-chain
#   8. query all issuer keys

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

export PATH="$SCRIPT_DIR/../bin:$PATH"
export FABRIC_CFG_PATH="$SCRIPT_DIR/../config"
export TEST_NETWORK_HOME="$SCRIPT_DIR"

# ─── Issuer org list ─────────────────────────────────────────────────────────
# Generate and register keys for every org in this list.
ISSUERS=("issuer-org1" "issuer-org2")

CHANNEL="verify-channel"
CHAINCODE="setupcc"
CHAINCODE_VERIFY="verifycc"
CHAINCODE_ISSUANCE="issuancecc"
KEYGEN_DIR="$SCRIPT_DIR/chaincode/issuer-keygen"
KEYS_DIR="$KEYGEN_DIR/keys"

# ─── Helper functions ────────────────────────────────────────────────────────
log()  { echo -e "\n\033[1;34m>>> $*\033[0m"; }
ok()   { echo -e "\033[1;32m    OK: $*\033[0m"; }
fail() { echo -e "\033[1;31m    ERROR: $*\033[0m"; exit 1; }

invoke() {
  peer chaincode invoke \
    -o localhost:7050 \
    --ordererTLSHostnameOverride orderer.example.com \
    --tls --cafile "$ORDERER_CA" \
    -C "$CHANNEL" -n "$CHAINCODE" \
    --peerAddresses localhost:7051 --tlsRootCertFiles "$PEER0_ORG1_CA" \
    --peerAddresses localhost:9051 --tlsRootCertFiles "$PEER0_ORG2_CA" \
    -c "$1"
  sleep 2
}

query() {
  peer chaincode query -C "$CHANNEL" -n "$CHAINCODE" -c "$1"
}

# ─── 1. Bring up network ─────────────────────────────────────────────────────
log "1. Bring up network (with -ca flag)"

# Idempotent run: if previous network/channel state exists, clean it up first.
if docker ps --format '{{.Names}}' | grep -q '^peer0\.org1\.example\.com$'; then
  log "   Existing network detected, shutting down..."
  ./network.sh down -ca || true
fi

./network.sh up -ca
ok "Network and channel are ready"

# ─── 2. Setupcc deploy ───────────────────────────────────────────────────────
log "2. setupcc deploy → $CHANNEL"
./network.sh deployCC \
  -c "$CHANNEL" \
  -ccn "$CHAINCODE" \
  -ccp ./chaincode/setupcc \
  -ccl go \
  -ccv 1.0 \
  -ccs 1
ok "setupcc deployed"

# ─── 3. verifycc deploy ─────────────────────────────────────────────────────
log "3. verifycc deploy → $CHANNEL"
./network.sh deployCC \
  -c "$CHANNEL" \
  -ccn "$CHAINCODE_VERIFY" \
  -ccp ./chaincode/verifycc \
  -ccl go \
  -ccv 1.0 \
  -ccs 1
ok "verifycc deployed"

# ─── 4. issuancecc deploy ─────────────────────────────────────────────────────
log "4. issuancecc deploy → $CHANNEL"
./network.sh deployCC \
  -c "$CHANNEL" \
  -ccn "$CHAINCODE_ISSUANCE" \
  -ccp ./chaincode/issuancecc \
  -ccl go \
  -ccv 1.0 \
  -ccs 1
ok "issuancecc deployed"

source scripts/envVar.sh
setGlobals 1

# ─── 5. Environment setup ────────────────────────────────────────────────────
log "5. Environment setup (Org1)"
source scripts/envVar.sh
setGlobals 1
ok "Org1 peer context set"

# ─── 6. Chaincode ping ───────────────────────────────────────────────────────
log "6. Chaincode ping"
PONG=$(query '{"function":"Ping","Args":[]}')
if [[ "$PONG" == *"setupcc:ok"* ]]; then
  ok "Ping response: $PONG"
else
  fail "Ping failed: $PONG"
fi

# ─── 7. Auto-initialize system params ────────────────────────────────────────
log "7. Auto-initialize system params (SetupParamsAuto)"
invoke '{"function":"SetupParamsAuto","Args":[]}'
ok "SetupParamsAuto invoked"

# ─── 8. Query system params ──────────────────────────────────────────────────
log "8. Query system params"
PARAMS=$(query '{"function":"GetSystemParams","Args":[]}')
echo "    $PARAMS"
ok "System params retrieved"

# ─── 9. Generate and register issuer keypairs ────────────────────────────────
log "9. Generate and register issuer keypairs"

# Build keygen binary (if missing)
if [[ ! -f "$KEYGEN_DIR/issuer-keygen" ]]; then
  log "   Building issuer-keygen binary..."
  (cd "$KEYGEN_DIR" && go build -o issuer-keygen . )
  ok "   issuer-keygen built"
fi

for ISSUER_ID in "${ISSUERS[@]}"; do
  log "   Issuer: $ISSUER_ID"

  PUBLIC_KEY_FILE="$KEYS_DIR/${ISSUER_ID}-public.key"

  # Key generation (overwrites if already exists)
  "$KEYGEN_DIR/issuer-keygen" --issuer "$ISSUER_ID" --out "$KEYS_DIR"

  if [[ ! -f "$PUBLIC_KEY_FILE" ]]; then
    fail "Public key file was not created: $PUBLIC_KEY_FILE"
  fi

  PUB_KEY=$(tr -d '[:space:]' < "$PUBLIC_KEY_FILE")
  echo "    Public key ($ISSUER_ID): $PUB_KEY"

  invoke "{\"function\":\"RegisterIssuerKey\",\"Args\":[\"$ISSUER_ID\",\"$PUB_KEY\"]}"
  ok "   $ISSUER_ID registered"
done

# ─── 10. Query all issuer keys ───────────────────────────────────────────────
log "10. Query issuer keys"

for ISSUER_ID in "${ISSUERS[@]}"; do
  echo "    --- $ISSUER_ID ---"
  query "{\"function\":\"GetIssuerKey\",\"Args\":[\"$ISSUER_ID\"]}"
  echo
done

ok "Init phase complete"

# ─── 11-12. Run issuance phase ───────────────────────────────────────────────
log "11-12. Issuance phase (Alice + Bob) - issuance.sh"
"$SCRIPT_DIR/issuance.sh"
ok "Issuance phase complete"

# ─── 13. Presentation + Verification (Alice / org1) ──────────────────────────
log "13. Presentation + Verification – Alice / issuer-org1"
"$SCRIPT_DIR/presentation.sh" alice issuer-org1 "name:Alice,age:30,role:student" "name:Alice,role:student"
ok "Alice verification complete"

# ─── 14. Presentation + Verification (Bob / org2) ────────────────────────────
log "14. Presentation + Verification – Bob / issuer-org2"
"$SCRIPT_DIR/presentation.sh" bob issuer-org2 "name:Bob,age:25,role:employee" "name:Bob,age:25"
ok "Bob verification complete"

# ─── 15. Presentation + Verification (Alice / org1) ──────────────────────────
log "15. Presentation + Verification – Alice / issuer-org1"
"$SCRIPT_DIR/presentation.sh" alice issuer-org1 "name:Alice,age:30,role:student" "name:Alice,role:employee"
ok "Alice verification with invalid attributes complete"

# ─── 16. Presentation + Verification (Bob / org2) ────────────────────────────
log "16. Presentation + Verification – Bob / issuer-org2"
"$SCRIPT_DIR/presentation.sh" bob issuer-org2 "name:Bob,age:25,role:employee" "name:Bob,age:15"
ok "Bob verification with invalid attributes complete"


ok "Full protocol run complete (Setup -> Issuance -> Presentation -> Verification)"
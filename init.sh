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
RAND_CHANNEL="rand-channel"
CHAINCODE="setupcc"
CHAINCODE_RAND="randomcc"
CHAINCODE_VERIFY="verifycc"
CHAINCODE_ISSUANCE="issuancecc"
KEYGEN_DIR="$SCRIPT_DIR/chaincode/issuer-keygen"
KEYS_DIR="$KEYGEN_DIR/keys"

# ─── Helper functions ────────────────────────────────────────────────────────
log()  { echo -e "\n\033[1;34m>>> $*\033[0m"; }
ok()   { echo -e "\033[1;32m    OK: $*\033[0m"; }
fail() { echo -e "\033[1;31m    ERROR: $*\033[0m"; exit 1; }

declare -A PHASE_TIMINGS_MS=()

now_ms() {
  date +%s%3N
}

measure_phase() {
  local label=$1
  shift
  local start_ms end_ms
  start_ms="$(now_ms)"
  "$@"
  end_ms="$(now_ms)"
  PHASE_TIMINGS_MS["$label"]=$((end_ms - start_ms))
}

format_duration() {
  local total_ms=$1
  local seconds=$((total_ms / 1000))
  local millis=$((total_ms % 1000))
  printf '%ds %03dms' "$seconds" "$millis"
}

print_final_timings() {
  echo
  log "Final timing summary"
  printf '    %-24s %s\n' "Setup phase" "$(format_duration "${PHASE_TIMINGS_MS[setup]:-0}")"
  printf '    %-24s %s\n' "Issuance phase" "$(format_duration "${PHASE_TIMINGS_MS[issuance]:-0}")"
  printf '    %-24s %s\n' "Presentation true" "$(format_duration "${PHASE_TIMINGS_MS[presentation_true]:-0}")"
  printf '    %-24s %s\n' "Presentation false" "$(format_duration "${PHASE_TIMINGS_MS[presentation_false]:-0}")"
}

invoke_rand() {
  peer chaincode invoke \
    -o localhost:7050 \
    --ordererTLSHostnameOverride orderer.example.com \
    --tls --cafile "$ORDERER_CA" \
    -C "$RAND_CHANNEL" -n "$CHAINCODE_RAND" \
    --peerAddresses localhost:7051 --tlsRootCertFiles "$PEER0_ORG1_CA" \
    --peerAddresses localhost:9051 --tlsRootCertFiles "$PEER0_ORG2_CA" \
    -c "$1"
  sleep 2
}

query_rand() {
  peer chaincode query -C "$RAND_CHANNEL" -n "$CHAINCODE_RAND" -c "$1"
}

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

run_issuance_phase() {
  "$SCRIPT_DIR/issuance.sh"
}

run_true_presentation() {
  "$SCRIPT_DIR/presentation.sh" alice issuer-org1 "name:Alice,age:30,role:student" "name:Alice,role:student"
}

run_false_presentation() {
  "$SCRIPT_DIR/presentation.sh" alice issuer-org1 "name:Alice,age:30,role:student" "name:Alice,role:employee"
}

SETUP_START_MS="$(now_ms)"

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

# ─── 3. randomcc deploy ─────────────────────────────────────────────────────
log "3. randomcc deploy → $RAND_CHANNEL"
./network.sh deployCC \
  -c "$RAND_CHANNEL" \
  -ccn "$CHAINCODE_RAND" \
  -ccp ./chaincode/randomcc \
  -ccl go \
  -ccv 1.0 \
  -ccs 1
ok "randomcc deployed"

# ─── 4. verifycc deploy ─────────────────────────────────────────────────────
log "4. verifycc deploy → $CHANNEL"
./network.sh deployCC \
  -c "$CHANNEL" \
  -ccn "$CHAINCODE_VERIFY" \
  -ccp ./chaincode/verifycc \
  -ccl go \
  -ccv 1.0 \
  -ccs 1
ok "verifycc deployed"

# ─── 5. issuancecc deploy ────────────────────────────────────────────────────
log "5. issuancecc deploy → $CHANNEL"
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

if [[ ! -f "$KEYGEN_DIR/issuer-keygen" ]]; then
  log "   Building issuer-keygen binary..."
  (cd "$KEYGEN_DIR" && go build -o issuer-keygen .)
  ok "   issuer-keygen built"
fi

for ISSUER_ID in "${ISSUERS[@]}"; do
  log "   Issuer: $ISSUER_ID"
  PUBLIC_KEY_FILE="$KEYS_DIR/${ISSUER_ID}-public.key"
  "$KEYGEN_DIR/issuer-keygen" --issuer "$ISSUER_ID" --out "$KEYS_DIR"
  [[ -f "$PUBLIC_KEY_FILE" ]] || fail "Public key file was not created: $PUBLIC_KEY_FILE"
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

# ─── 11. Randomization interval setup (rand-channel) ─────────────────────────
log "11. Initialize randomization interval on rand-channel"
export INTERVAL_ID="interval-$(date +%s)"
ORG1_RI="00$(openssl rand -hex 31)"
ORG1_SI="00$(openssl rand -hex 31)"
ORG2_RI="00$(openssl rand -hex 31)"
ORG2_SI="00$(openssl rand -hex 31)"

invoke_rand "{\"function\":\"SetIntervalRandoms\",\"Args\":[\"$INTERVAL_ID\"]}"
ok "Interval initialized: $INTERVAL_ID"

invoke_rand "{\"function\":\"ContributeRandom\",\"Args\":[\"$INTERVAL_ID\",\"$ORG1_RI\",\"$ORG1_SI\"]}"
ok "Org1 random contributed"

setGlobals 2
invoke_rand "{\"function\":\"ContributeRandom\",\"Args\":[\"$INTERVAL_ID\",\"$ORG2_RI\",\"$ORG2_SI\"]}"
ok "Org2 random contributed"

setGlobals 1
invoke_rand "{\"function\":\"FinalizeInterval\",\"Args\":[\"$INTERVAL_ID\"]}"
ok "Interval finalized"

ST_INV_G2_HEX=$(query_rand "{\"function\":\"GetStInvG2\",\"Args\":[\"$INTERVAL_ID\"]}" | tr -d '"[:space:]')
[[ -n "$ST_INV_G2_HEX" ]] || fail "GetStInvG2 returned empty"
echo "    intervalID: $INTERVAL_ID"
echo "    stInvG2Hex: $ST_INV_G2_HEX"

PHASE_TIMINGS_MS[setup]=$(( $(now_ms) - SETUP_START_MS ))
ok "Setup phase complete"

# ─── 12. Issuance phase ──────────────────────────────────────────────────────
log "12. Issuance phase (Alice + Bob)"
measure_phase issuance run_issuance_phase
ok "Issuance phase complete"

# ─── 13. Presentation + Verification (true case) ─────────────────────────────
log "13. Presentation + Verification – true case"
measure_phase presentation_true run_true_presentation
ok "True presentation verification complete"

# ─── 14. Presentation + Verification (false case) ────────────────────────────
log "14. Presentation + Verification – false case"
measure_phase presentation_false run_false_presentation
ok "False presentation verification complete"

print_final_timings

ok "Full protocol run complete (Setup → Randomization → Issuance → Presentation → Verification)"
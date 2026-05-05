#!/usr/bin/env bash
# scenario_rand_to_verify.sh
# End-to-end scenario demonstrating the full protocol:
# 1) Bring network up
# 2) Deploy all chaincodes
# 3) Setup phase: system params + issuer keys
# 4) Randomization phase (rand-channel): SetIntervalRandoms -> ContributeRandom x2 -> FinalizeInterval
# 5) Issuance phase: ComputeCommitment on rand-channel -> IssueCredential on verify-channel

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

export PATH="$SCRIPT_DIR/../bin:$PATH"
export FABRIC_CFG_PATH="$SCRIPT_DIR/../config"
export TEST_NETWORK_HOME="$SCRIPT_DIR"
export DOCKER_SOCK="${DOCKER_SOCK:-/var/run/docker.sock}"

RAND_CHANNEL="rand-channel"
VERIFY_CHANNEL="verify-channel"
RAND_CC="randomcc"
ISSUANCE_CC="issuancecc"
SETUP_CC="setupcc"

log()  { echo -e "\n\033[1;34m>>> $*\033[0m"; }
ok()   { echo -e "\033[1;32m    OK: $*\033[0m"; }
fail() { echo -e "\033[1;31m    ERROR: $*\033[0m"; exit 1; }

need_cmd() { command -v "$1" >/dev/null 2>&1 || fail "Missing command: $1"; }
need_cmd peer
need_cmd openssl
need_cmd python3

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

# ─── 1. Network up ───────────────────────────────────────────────────────────
log "1. Bring up network"
if docker ps --format '{{.Names}}' | grep -q '^peer0\.org1\.example\.com$'; then
  log "   Existing network detected, shutting down first"
  ./network.sh down -ca || true
fi
./network.sh up -ca
ok "Network is up"

# ─── 2. Deploy chaincodes ────────────────────────────────────────────────────
log "2. Deploy issuancecc → $VERIFY_CHANNEL"
./network.sh deployCC -c "$VERIFY_CHANNEL" -ccn "$ISSUANCE_CC" -ccp ./chaincode/issuancecc -ccl go -ccv 1.0 -ccs 1
ok "issuancecc deployed"

log "3. Deploy setupcc → $VERIFY_CHANNEL"
./network.sh deployCC -c "$VERIFY_CHANNEL" -ccn "$SETUP_CC" -ccp ./chaincode/setupcc -ccl go -ccv 1.0 -ccs 1
ok "setupcc deployed"

log "4. Deploy randomcc → $RAND_CHANNEL"
./network.sh deployCC -c "$RAND_CHANNEL" -ccn "$RAND_CC" -ccp ./chaincode/randomcc -ccl go -ccv 1.0 -ccs 1
ok "randomcc deployed"

source scripts/envVar.sh
setGlobals 1
ok "Org1 context set"

# ─── 3. Setup phase (verify-channel) ─────────────────────────────────────────
log "5. Setup: system params + issuer keys"
peer chaincode invoke \
  -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com \
  --tls --cafile "$ORDERER_CA" \
  -C "$VERIFY_CHANNEL" -n "$SETUP_CC" \
  --peerAddresses localhost:7051 --tlsRootCertFiles "$PEER0_ORG1_CA" \
  --peerAddresses localhost:9051 --tlsRootCertFiles "$PEER0_ORG2_CA" \
  -c '{"function":"SetupParamsAuto","Args":[]}' ; sleep 2
ok "SetupParamsAuto done"

KEYGEN_DIR="$SCRIPT_DIR/chaincode/issuer-keygen"
KEYS_DIR="$KEYGEN_DIR/keys"
if [[ ! -f "$KEYGEN_DIR/issuer-keygen" ]]; then
  (cd "$KEYGEN_DIR" && go build -o issuer-keygen .)
fi
for ISSUER_ID in issuer-org1 issuer-org2; do
  "$KEYGEN_DIR/issuer-keygen" --issuer "$ISSUER_ID" --out "$KEYS_DIR"
  PUB_KEY=$(tr -d '[:space:]' < "$KEYS_DIR/${ISSUER_ID}-public.key")
  peer chaincode invoke \
    -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com \
    --tls --cafile "$ORDERER_CA" \
    -C "$VERIFY_CHANNEL" -n "$SETUP_CC" \
    --peerAddresses localhost:7051 --tlsRootCertFiles "$PEER0_ORG1_CA" \
    --peerAddresses localhost:9051 --tlsRootCertFiles "$PEER0_ORG2_CA" \
    -c "{\"function\":\"RegisterIssuerKey\",\"Args\":[\"$ISSUER_ID\",\"$PUB_KEY\"]}" ; sleep 2
  ok "$ISSUER_ID key registered"
done

# ─── 4. Randomization phase (rand-channel) ───────────────────────────────────
INTERVAL_ID="interval-$(date +%s)"
ORG1_RI="00$(openssl rand -hex 31)"
ORG1_SI="00$(openssl rand -hex 31)"
ORG2_RI="00$(openssl rand -hex 31)"
ORG2_SI="00$(openssl rand -hex 31)"

log "6. Initialize interval on rand-channel: $INTERVAL_ID"
invoke_rand "{\"function\":\"SetIntervalRandoms\",\"Args\":[\"$INTERVAL_ID\"]}"
ok "Interval initialized"

log "7. Contribute random (Org1)"
invoke_rand "{\"function\":\"ContributeRandom\",\"Args\":[\"$INTERVAL_ID\",\"$ORG1_RI\",\"$ORG1_SI\"]}"
ok "Org1 contribution submitted"

log "8. Contribute random (Org2)"
setGlobals 2
invoke_rand "{\"function\":\"ContributeRandom\",\"Args\":[\"$INTERVAL_ID\",\"$ORG2_RI\",\"$ORG2_SI\"]}"
ok "Org2 contribution submitted"

log "9. Finalize interval"
setGlobals 1
invoke_rand "{\"function\":\"FinalizeInterval\",\"Args\":[\"$INTERVAL_ID\"]}"
ok "Interval finalized"

ST_INV_G2_HEX=$(query_rand "{\"function\":\"GetStInvG2\",\"Args\":[\"$INTERVAL_ID\"]}" | tr -d '"[:space:]')
[[ -n "$ST_INV_G2_HEX" ]] || fail "GetStInvG2 returned empty"
echo "    intervalID: $INTERVAL_ID"
echo "    stInvG2Hex: $ST_INV_G2_HEX"

# ─── 5. Issuance phase ───────────────────────────────────────────────────────
log "10. Issuance phase (commitment computed on rand-channel)"
export INTERVAL_ID
"$SCRIPT_DIR/issuance.sh"

ok "Scenario complete: rand-channel randomization → verify-channel issuance succeeded"

#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

export PATH="$SCRIPT_DIR/../bin:$PATH"
export FABRIC_CFG_PATH="$SCRIPT_DIR/../config"
export TEST_NETWORK_HOME="$SCRIPT_DIR"

CHANNEL="verify-channel"
RAND_CHANNEL="rand-channel"
RAND_CC="randomcc"
CREDGEN_DIR="$SCRIPT_DIR/chaincode/presentation-gen"

USER_ID="${1:-alice}"
ISSUER_ID="${2:-issuer-org1}"
ATTRS="${3:-name:Alice,age:30,role:student}"
# 4th arg: which attrs to disclose (empty = all)
SHOW_ATTRS="${4:-}"

log()  { echo -e "\n\033[1;34m>>> $*\033[0m"; }
ok()   { echo -e "\033[1;32m    OK: $*\033[0m"; }
need_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "ERROR: missing command: $1"; exit 1; }; }

need_cmd peer
need_cmd go
need_cmd python3

: "${OVERRIDE_ORG:=}"
: "${VERBOSE:=false}"
source scripts/envVar.sh
setGlobals 1

query_cc() {
  peer chaincode query -C "$CHANNEL" -n "$1" -c "$2"
}

query_rand() {
  peer chaincode query -C "$RAND_CHANNEL" -n "$RAND_CC" -c "$1"
}

invoke_rand() {
  peer chaincode invoke \
    -o localhost:7050 \
    --ordererTLSHostnameOverride orderer.example.com \
    --tls --cafile "$ORDERER_CA" \
    -C "$RAND_CHANNEL" -n "$RAND_CC" \
    --peerAddresses localhost:7051 --tlsRootCertFiles "$PEER0_ORG1_CA" \
    --peerAddresses localhost:9051 --tlsRootCertFiles "$PEER0_ORG2_CA" \
    -c "$1" 2>&1
}

log "1. Query credential ($USER_ID)"
CRED_JSON=$(query_cc issuancecc "{\"function\":\"GetCredential\",\"Args\":[\"$USER_ID\"]}")
echo "    $CRED_JSON"
TU_COMM_HEX=$(echo "$CRED_JSON"  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['tuCommHex'])")
COMPONENTS_JSON=$(echo "$CRED_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(json.dumps(d['componentsHex']))")
INTERVAL_ID=$(echo "$CRED_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['intervalId'])")
COMMITMENT_HEX=$(echo "$CRED_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['commitmentHex'])")
echo "    tuCommHex: $TU_COMM_HEX"
echo "    intervalId: $INTERVAL_ID"
echo "    commitmentHex: $COMMITMENT_HEX"

log "2. Query left/right G2 randomization points from rand-channel"
LEFT_G2_HEX=$(query_rand "{\"function\":\"GetStInvG2\",\"Args\":[\"$INTERVAL_ID\"]}" | tr -d '"[:space:]')
[[ -n "$LEFT_G2_HEX" ]] || { echo "ERROR: GetStInvG2 returned empty"; exit 1; }
echo "    leftG2 (st^-1·G2): $LEFT_G2_HEX"

log "3. Query issuer public key ($ISSUER_ID)"
ISSUER_JSON=$(query_cc setupcc "{\"function\":\"GetIssuerKey\",\"Args\":[\"$ISSUER_ID\"]}")
echo "    $ISSUER_JSON"
PUBKEY_HEX=$(echo "$ISSUER_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['pubKeyHex'])")
echo "    X: $PUBKEY_HEX"

RIGHT_G2_HEX=$(query_rand "{\"function\":\"ApplyRtToG2\",\"Args\":[\"$INTERVAL_ID\",\"$PUBKEY_HEX\"]}" | tr -d '"[:space:]')
[[ -n "$RIGHT_G2_HEX" ]] || { echo "ERROR: ApplyRtToG2 returned empty"; exit 1; }
echo "    rightG2 (rt·X): $RIGHT_G2_HEX"

log "4. Load u·G̅ (off-chain user file)"
UGBAR_FILE="$SCRIPT_DIR/chaincode/issuer-keygen/keys/${USER_ID}-ugbar.hex"
if [[ -f "$UGBAR_FILE" ]]; then
  UGBAR_HEX=$(cat "$UGBAR_FILE" | tr -d '[:space:]')
  echo "    u·G̅: $UGBAR_HEX"
else
  echo "    FIGYELMEZTETÉS: $UGBAR_FILE nem található → --u-g-bar nélkül futtatjuk (cikkel ellentétes)"
  UGBAR_HEX=""
fi

log "5. presentation-gen build (if missing)"
if [[ ! -f "$CREDGEN_DIR/presentation-gen" ]]; then
  (cd "$CREDGEN_DIR" && go build -o presentation-gen .)
  ok "presentation-gen built"
fi

log "6. Presentation prepare — vakított összegek generálása (ℓ, ℓ' blinding)"
SHOW_ARGS=()
if [[ -n "$SHOW_ATTRS" ]]; then
  SHOW_ARGS=(--show "$SHOW_ATTRS")
fi
UGBAR_ARGS=()
if [[ -n "$UGBAR_HEX" ]]; then
  UGBAR_ARGS=(--u-g-bar "$UGBAR_HEX")
fi

PREPARE_JSON=$("$CREDGEN_DIR/presentation-gen" \
  --mode        prepare \
  --issuer      "$ISSUER_ID" \
  --user        "$USER_ID" \
  --attrs       "$ATTRS" \
  "${SHOW_ARGS[@]}" \
  --components  "$COMPONENTS_JSON" \
  --left-g2     "$LEFT_G2_HEX" \
  --right-g2    "$RIGHT_G2_HEX" \
  --commitment  "$COMMITMENT_HEX" \
  "${UGBAR_ARGS[@]}" 2>&1 | tail -1)
echo "    PrepareJSON: $PREPARE_JSON"

BLINDED_SEL=$(echo "$PREPARE_JSON"  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['blindedSelHex'])")
BLINDED_MISS=$(echo "$PREPARE_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['blindedMissHex'])")
L_INV=$(echo "$PREPARE_JSON"        | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['lInvHex'])")
L_PRIME_INV=$(echo "$PREPARE_JSON"  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['lPrimeInvHex'])")

log "7. Randomize on rand-channel (randomcc.RandomizePresentation) — vakított összegekkel"
RAND_TX_OUT=$(invoke_rand "{\"function\":\"RandomizePresentation\",\"Args\":[\"$INTERVAL_ID\",\"$BLINDED_SEL\",\"$BLINDED_MISS\"]}")

RAND_JSON=$(echo "$RAND_TX_OUT" \
  | sed -n 's/.*payload:"\(.*\)".*/\1/p' \
  | python3 -c 'import sys; s=sys.stdin.read().strip(); print(bytes(s, "utf-8").decode("unicode_escape") if s else "")')
[[ -n "$RAND_JSON" ]] || { echo "ERROR: Could not parse RandomizePresentation payload"; echo "$RAND_TX_OUT"; exit 1; }

RAND_LEFT_HEX=$(echo "$RAND_JSON"  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['leftG1Hex'])")
RAND_MISS_HEX=$(echo "$RAND_JSON"  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['missingG1Hex'])")
echo "    Randomized left (rts·ℓ·selSum): $RAND_LEFT_HEX"
echo "    Randomized miss (rts·ℓ'·missSum): $RAND_MISS_HEX"

log "8. Presentation finalize — unblinding (ℓ⁻¹, ℓ'⁻¹ alkalmazása)"
VERIFY_INPUT_JSON=$("$CREDGEN_DIR/presentation-gen" \
  --mode        finalize \
  --rand-left   "$RAND_LEFT_HEX" \
  --rand-miss   "$RAND_MISS_HEX" \
  --l-inv       "$L_INV" \
  --l-prime-inv "$L_PRIME_INV" \
  --base-input  "$PREPARE_JSON")
echo "    VerifyInput JSON: $VERIFY_INPUT_JSON"

log "9. Invoke VerifyPresentation (verifycc)"
VERIFY_INPUT_STR=$(python3 -c "import sys,json; print(json.dumps(sys.stdin.read().strip()))" <<< "$VERIFY_INPUT_JSON")

VERIFY_RESULT=$(query_cc verifycc "{\"function\":\"VerifyPresentation\",\"Args\":[$VERIFY_INPUT_STR,\"setupcc\",\"issuancecc\"]}")
echo "    VerifyResult: $VERIFY_RESULT"

ok "Presentation phase complete ($USER_ID / $ISSUER_ID)"

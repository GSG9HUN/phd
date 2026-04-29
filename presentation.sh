#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

export PATH="$SCRIPT_DIR/../bin:$PATH"
export FABRIC_CFG_PATH="$SCRIPT_DIR/../config"
export TEST_NETWORK_HOME="$SCRIPT_DIR"

CHANNEL="verify-channel"
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

log "1. Query interval parameters (issuancecc)"
INTERVAL_JSON=$(query_cc issuancecc '{"function":"GetIntervalParams","Args":[]}')
echo "    $INTERVAL_JSON"
RT_HEX=$(echo "$INTERVAL_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['rtHex'])")
ST_HEX=$(echo "$INTERVAL_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['stHex'])")
echo "    r_t: $RT_HEX"
echo "    s_t: $ST_HEX"

log "2. Query credential ($USER_ID)"
CRED_JSON=$(query_cc issuancecc "{\"function\":\"GetCredential\",\"Args\":[\"$USER_ID\"]}")
echo "    $CRED_JSON"
TU_HEX=$(echo "$CRED_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['tuHex'])")
COMPONENTS_JSON=$(echo "$CRED_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(json.dumps(d['componentsHex']))")
echo "    T_U: $TU_HEX"

log "3. Query issuer public key ($ISSUER_ID)"
ISSUER_JSON=$(query_cc setupcc "{\"function\":\"GetIssuerKey\",\"Args\":[\"$ISSUER_ID\"]}")
echo "    $ISSUER_JSON"
PUBKEY_HEX=$(echo "$ISSUER_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['pubKeyHex'])")
echo "    X: $PUBKEY_HEX"

log "4. presentation-gen build (if missing)"
if [[ ! -f "$CREDGEN_DIR/presentation-gen" ]]; then
  (cd "$CREDGEN_DIR" && go build -o presentation-gen .)
  ok "presentation-gen built"
fi

log "5. Compute proof (presentation-gen)"
SHOW_ARGS=()
if [[ -n "$SHOW_ATTRS" ]]; then
  SHOW_ARGS=(--show "$SHOW_ATTRS")
fi

VERIFY_INPUT_JSON=$("$CREDGEN_DIR/presentation-gen" \
  --issuer      "$ISSUER_ID" \
  --user        "$USER_ID" \
  --attrs       "$ATTRS" \
  "${SHOW_ARGS[@]}" \
  --components  "$COMPONENTS_JSON" \
  --tu          "$TU_HEX" \
  --rt          "$RT_HEX" \
  --st          "$ST_HEX" \
  --pubkey      "$PUBKEY_HEX")

echo "    VerifyInput JSON: $VERIFY_INPUT_JSON"

log "6. Invoke VerifyPresentation (verifycc)"
VERIFY_INPUT_STR=$(python3 -c "import sys,json; print(json.dumps(sys.stdin.read().strip()))" <<< "$VERIFY_INPUT_JSON")

VERIFY_RESULT=$(query_cc verifycc "{\"function\":\"VerifyPresentation\",\"Args\":[$VERIFY_INPUT_STR,\"setupcc\",\"issuancecc\"]}")
echo "    VerifyResult: $VERIFY_RESULT"

ok "Presentation phase complete ($USER_ID / $ISSUER_ID)"

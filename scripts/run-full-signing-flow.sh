#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
TEST_NETWORK_HOME=$(cd "$SCRIPT_DIR/.." && pwd)

export PATH="$TEST_NETWORK_HOME/../bin:$PATH"
export FABRIC_CFG_PATH="$TEST_NETWORK_HOME/../config"
export TEST_NETWORK_HOME
export CORE_PEER_TLS_ENABLED=true
export OVERRIDE_ORG="${OVERRIDE_ORG:-}"
export VERBOSE="${VERBOSE:-false}"

. "$TEST_NETWORK_HOME/scripts/envVar.sh"

CHANNEL_NAME="channel2"
CHAINCODE_NAME="keygen"
USER_ID="alice"
KEYFILE="alice.key"
ROUND_ID="round-$(date +%s)"
MESSAGE="hello-from-alice"

usage() {
	cat <<EOF
Usage: $(basename "$0") [options]

Options:
	-u, --user <user-id>        Base user ID (default: alice)
	-k, --keyfile <path>        Base private key file (default: alice.key)
	-r, --round <round-id>      Round ID (default: auto-generated)
	-m, --message <text>        Message to sign (default: hello-from-alice)
	-c, --channel <channel>     Channel name (default: channel2)
	-n, --cc <chaincode>        Chaincode name (default: keygen)
	-h, --help                  Show this help
EOF
}

while [[ $# -gt 0 ]]; do
	case "$1" in
		-u|--user)
			USER_ID="$2"
			shift 2
			;;
		-k|--keyfile)
			KEYFILE="$2"
			shift 2
			;;
		-r|--round)
			ROUND_ID="$2"
			shift 2
			;;
		-m|--message)
			MESSAGE="$2"
			shift 2
			;;
		-c|--channel)
			CHANNEL_NAME="$2"
			shift 2
			;;
		-n|--cc)
			CHAINCODE_NAME="$2"
			shift 2
			;;
		-h|--help)
			usage
			exit 0
			;;
		*)
			echo "Unknown argument: $1" >&2
			usage >&2
			exit 1
			;;
	esac
done

section() {
	echo
	echo "=== $1 ==="
}

invoke_json() {
	local org="$1"
	local payload="$2"

	setGlobals "$org"
	peer chaincode invoke \
		--waitForEvent \
		-o localhost:7050 \
		--ordererTLSHostnameOverride orderer.example.com \
		--tls \
		--cafile "$ORDERER_CA" \
		-C "$CHANNEL_NAME" \
		-n "$CHAINCODE_NAME" \
		--peerAddresses "$CORE_PEER_ADDRESS" \
		--tlsRootCertFiles "$CORE_PEER_TLS_ROOTCERT_FILE" \
		-c "$payload"
}

query_json() {
	local org="$1"
	local payload="$2"

	setGlobals "$org"
	peer chaincode query -C "$CHANNEL_NAME" -n "$CHAINCODE_NAME" -c "$payload"
}

section "1) Generate Alice key and register base public key"
setGlobals 1
"$TEST_NETWORK_HOME/client-keygen/keygen" -user "$USER_ID" -keyfile "$KEYFILE" -channel "$CHANNEL_NAME" -cc "$CHAINCODE_NAME"

section "2) Run 3-org round"
"$TEST_NETWORK_HOME/scripts/run-round.sh" -u "$USER_ID" -r "$ROUND_ID" -c "$CHANNEL_NAME" -n "$CHAINCODE_NAME"

section "3) Read round state and register forwarded public keys"
ROUND_JSON=$(query_json 1 "{\"function\":\"GetRound\",\"Args\":[\"$ROUND_ID\"]}")
X1=$(echo "$ROUND_JSON" | jq -r '.history[0].x')
X2=$(echo "$ROUND_JSON" | jq -r '.history[1].x')
X3=$(echo "$ROUND_JSON" | jq -r '.history[2].x')

USER1="${USER_ID}-step1"
USER2="${USER_ID}-step2"
USER3="${USER_ID}-step3"

invoke_json 1 "{\"function\":\"RegisterPublicKey\",\"Args\":[\"$USER1\",\"$X1\"]}"
invoke_json 1 "{\"function\":\"RegisterPublicKey\",\"Args\":[\"$USER2\",\"$X2\"]}"
invoke_json 1 "{\"function\":\"RegisterPublicKey\",\"Args\":[\"$USER3\",\"$X3\"]}"

section "4) Read org randoms and derive 3 private keys"
R1=$(query_json 1 "{\"function\":\"GetOrgRandom\",\"Args\":[\"$ROUND_ID\"]}")
R2=$(query_json 2 "{\"function\":\"GetOrgRandom\",\"Args\":[\"$ROUND_ID\"]}")
R3=$(query_json 3 "{\"function\":\"GetOrgRandom\",\"Args\":[\"$ROUND_ID\"]}")

SK1=$("$TEST_NETWORK_HOME/client-keygen/keygen" -derive -keyfile "$KEYFILE" -factor "$R1")
SK2=$("$TEST_NETWORK_HOME/client-keygen/keygen" -derive -sk "$SK1" -factor "$R2")
SK3=$("$TEST_NETWORK_HOME/client-keygen/keygen" -derive -sk "$SK2" -factor "$R3")

section "5) Sign the same message with each forwarded key"
SIG1=$("$TEST_NETWORK_HOME/client-keygen/keygen" -sign -sk "$SK1" -msg "$MESSAGE" -raw)
SIG2=$("$TEST_NETWORK_HOME/client-keygen/keygen" -sign -sk "$SK2" -msg "$MESSAGE" -raw)
SIG3=$("$TEST_NETWORK_HOME/client-keygen/keygen" -sign -sk "$SK3" -msg "$MESSAGE" -raw)

MID1="${ROUND_ID}-sig1"
MID2="${ROUND_ID}-sig2"
MID3="${ROUND_ID}-sig3"

section "6) Store signed messages on-chain"
invoke_json 1 "{\"function\":\"SubmitSignedMessage\",\"Args\":[\"$MID1\",\"$USER1\",\"$MESSAGE\",\"$SIG1\"]}"
invoke_json 1 "{\"function\":\"SubmitSignedMessage\",\"Args\":[\"$MID2\",\"$USER2\",\"$MESSAGE\",\"$SIG2\"]}"
invoke_json 1 "{\"function\":\"SubmitSignedMessage\",\"Args\":[\"$MID3\",\"$USER3\",\"$MESSAGE\",\"$SIG3\"]}"

section "7) Fetch stored messages"
query_json 1 "{\"function\":\"GetSignedMessage\",\"Args\":[\"$MID1\"]}"
query_json 1 "{\"function\":\"GetSignedMessage\",\"Args\":[\"$MID2\"]}"
query_json 1 "{\"function\":\"GetSignedMessage\",\"Args\":[\"$MID3\"]}"

section "8) Verify stored signatures"
query_json 1 "{\"function\":\"VerifyStoredSignature\",\"Args\":[\"$MID1\"]}"
query_json 1 "{\"function\":\"VerifyStoredSignature\",\"Args\":[\"$MID2\"]}"
query_json 1 "{\"function\":\"VerifyStoredSignature\",\"Args\":[\"$MID3\"]}"

section "Done"
echo "roundId=$ROUND_ID"
echo "message=$MESSAGE"
echo "stored IDs: $MID1 $MID2 $MID3"

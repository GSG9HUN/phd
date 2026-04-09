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
ROUND_ID="round-$(date +%s)"
USER_ID="alice"

usage() {
	cat <<EOF
Usage: $(basename "$0") [options]

Options:
	-r, --round <round-id>      Round identifier (default: auto-generated)
	-u, --user <user-id>        Registered user ID (default: alice)
	-c, --channel <channel>     Channel name (default: channel2)
	-n, --cc <chaincode>        Chaincode name (default: keygen)
	-h, --help                  Show this help
EOF
}

while [[ $# -gt 0 ]]; do
	case "$1" in
		-r|--round)
			ROUND_ID="$2"
			shift 2
			;;
		-u|--user)
			USER_ID="$2"
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

section() {
	echo
	echo "=== $1 ==="
}

section "Checking registered public key for user '$USER_ID'"
query_json 1 "{\"function\":\"GetPublicKey\",\"Args\":[\"$USER_ID\"]}"

section "Starting round '$ROUND_ID' from user '$USER_ID'"
invoke_json 1 "{\"function\":\"StartRound\",\"Args\":[\"$ROUND_ID\",\"$USER_ID\"]}"

section "Applying Org1 random"
invoke_json 1 "{\"function\":\"ApplyOrgRandom\",\"Args\":[\"$ROUND_ID\"]}"

section "Applying Org2 random"
invoke_json 2 "{\"function\":\"ApplyOrgRandom\",\"Args\":[\"$ROUND_ID\"]}"

section "Applying Org3 random"
invoke_json 3 "{\"function\":\"ApplyOrgRandom\",\"Args\":[\"$ROUND_ID\"]}"

section "Final round state"
query_json 1 "{\"function\":\"GetRound\",\"Args\":[\"$ROUND_ID\"]}"

section "Org1 private random"
query_json 1 "{\"function\":\"GetOrgRandom\",\"Args\":[\"$ROUND_ID\"]}"

section "Org2 private random"
query_json 2 "{\"function\":\"GetOrgRandom\",\"Args\":[\"$ROUND_ID\"]}"

section "Org3 private random"
query_json 3 "{\"function\":\"GetOrgRandom\",\"Args\":[\"$ROUND_ID\"]}"

section "Private random hashes"
query_json 1 "{\"function\":\"GetOrgRandomHash\",\"Args\":[\"$ROUND_ID\",\"Org1MSP\"]}"
query_json 1 "{\"function\":\"GetOrgRandomHash\",\"Args\":[\"$ROUND_ID\",\"Org2MSP\"]}"
query_json 1 "{\"function\":\"GetOrgRandomHash\",\"Args\":[\"$ROUND_ID\",\"Org3MSP\"]}"

section "Bilinear verification"
query_json 1 "{\"function\":\"VerifyRoundBilinear\",\"Args\":[\"$ROUND_ID\"]}"
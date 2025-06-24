#!/bin/bash

set -e

# ==== CONFIGURABLE VARIABLES ====
NUM_CLIENTS=4
PASSPHRASE="testpass"
WALLET_PREFIX="test/wallet"
CLIENT_ID_PREFIX="ID100"
# ================================

echo "=== Initializing $NUM_CLIENTS wallets ==="
for i in $(seq 1 $NUM_CLIENTS); do
    WALLET="${WALLET_PREFIX}${i}.json"
    echo "Initializing $WALLET"
    python3 -m client.tools.votemanager "$WALLET" init --passphrase "$PASSPHRASE"
done

echo
echo "=== Requesting eligibility for each wallet ==="
for i in $(seq 1 $NUM_CLIENTS); do
    WALLET="${WALLET_PREFIX}${i}.json"
    CLIENT_ID="${CLIENT_ID_PREFIX}${i}"
    echo "Requesting eligibility for $WALLET (ID: $CLIENT_ID)"
    python3 -m client.main "$WALLET" eligibility --id "$CLIENT_ID"
done

echo
echo "--- Eligibility phase complete ---"
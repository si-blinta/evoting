#!/bin/bash

set -e

# ==== CONFIGURABLE VARIABLES ====
NUM_CLIENTS=4
WALLET_PREFIX="test/wallet"
# ================================

echo "=== Revealing for each client ==="
for i in $(seq 1 $NUM_CLIENTS); do
    WALLET="${WALLET_PREFIX}${i}.json"
    echo "Revealing for $WALLET"
    python3 -m client.main "$WALLET" reveal
done

echo
echo "--- Reveal phase complete ---"
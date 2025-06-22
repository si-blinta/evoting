#!/bin/bash

set -e

# ==== CONFIGURABLE VARIABLES ====
NUM_CLIENTS=9
NUM_VOTES=10
CAND_MIN=1
CAND_MAX=5
PASSPHRASE="testpass"
WALLET_PREFIX="test/wallet"
# ================================

echo "=== Each client makes $NUM_VOTES votes with random candidates ($CAND_MIN-$CAND_MAX) ==="
for i in $(seq 1 $NUM_CLIENTS); do
    WALLET="${WALLET_PREFIX}${i}.json"
    echo "Voting for $WALLET"
    for v in $(seq 1 $NUM_VOTES); do
        CANDIDATE=$(( RANDOM % (CAND_MAX - CAND_MIN + 1) + CAND_MIN ))
        echo "  Commit #$v: candidate $CANDIDATE"
        python3 -m client.tools.votemanager "$WALLET" commit --candidate $CANDIDATE --passphrase "$PASSPHRASE"
        python3 -m client.main "$WALLET" commit
    done
done

echo
echo "--- Commit phase complete ---"
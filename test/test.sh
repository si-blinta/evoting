#!/bin/bash

set -e

# ==== CONFIGURABLE VARIABLES ====
NUM_CLIENTS=9
NUM_VOTES=10
CAND_MIN=1
CAND_MAX=5
PASSPHRASE="testpass"
WAIT_BEFORE_REVEAL=60  # seconds
WAIT_BEFORE_COUNT=1     # seconds
WALLET_PREFIX="test/wallet"
CLIENT_ID_PREFIX="ID100"
# ================================

declare -A FINAL_VOTE

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
    python3 -m client.main "$WALLET" elligibility --id "$CLIENT_ID"
done

echo
echo "=== Each client makes $NUM_VOTES votes with random candidates ($CAND_MIN-$CAND_MAX) ==="
for i in $(seq 1 $NUM_CLIENTS); do
    WALLET="${WALLET_PREFIX}${i}.json"
    echo "Voting for $WALLET"
    for v in $(seq 1 $NUM_VOTES); do
        CANDIDATE=$(( RANDOM % (CAND_MAX - CAND_MIN + 1) + CAND_MIN ))
        FINAL_VOTE[$i]=$CANDIDATE
        echo "  Commit #$v: candidate $CANDIDATE"
        python3 -m client.tools.votemanager "$WALLET" commit --candidate $CANDIDATE --passphrase "$PASSPHRASE"
        python3 -m client.main "$WALLET" commit
    done
done

echo
echo "Waiting $WAIT_BEFORE_REVEAL seconds before reveal..."
sleep $WAIT_BEFORE_REVEAL

echo
echo "=== Revealing for each client ==="
for i in $(seq 1 $NUM_CLIENTS); do
    WALLET="${WALLET_PREFIX}${i}.json"
    echo "Revealing for $WALLET"
    python3 -m client.main "$WALLET" reveal
done

echo
echo "Waiting $WAIT_BEFORE_COUNT seconds before count..."
sleep $WAIT_BEFORE_COUNT

echo
echo "=== Counting votes... ==="
python3 -m client.main "${WALLET_PREFIX}1.json" count

echo
echo "==== SUMMARY ===="
for i in $(seq 1 $NUM_CLIENTS); do
    echo "Client $i (${WALLET_PREFIX}${i}.json) final vote: candidate ${FINAL_VOTE[$i]}"
done
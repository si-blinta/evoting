import logging
from .data import candidates, voters, eligibility_requests, commits, confidential_voters, reveals
from .state import ServerState, COMMIT, REVEAL, ENDED,ELLIGIBILITY
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from collections import OrderedDict 
# --- Logging setup ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)
logger = logging.getLogger("server")

PRIVATE_KEY_PATH = "server/key.pem"

def load_server_pubkey(cert_path):
    with open(cert_path, "rb") as f:
        cert_data = f.read()
    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    pubkey = cert.public_key()
    numbers = pubkey.public_numbers()
    return numbers.n, numbers.e

def load_private_numbers(path):
    with open(path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )
    numbers = private_key.private_numbers()
    d = numbers.d
    n = numbers.public_numbers.n
    return d, n

d, n = load_private_numbers(PRIVATE_KEY_PATH)

def rsa_sign_raw(blinded_bytes, d, n):
    blinded_int = int.from_bytes(blinded_bytes, byteorder='big')
    signature_int = pow(blinded_int, d, n)
    key_size_bytes = (n.bit_length() + 7) // 8
    return signature_int.to_bytes(key_size_bytes, byteorder='big')

def handle_client(conn, addr, server_state: ServerState):
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            packet = data.decode().strip()
            logger.info(f"[client {addr[0]}:{addr[1]}] {packet}")

            response = None  # Default to None, set below

            # List requests (work in all states)
            if packet == "LC":
                response = f"Candidates: {candidates}\n"
            elif packet == "LV":
                response = f"Voters: {voters}\n"
            elif packet == "LE":
                response = f"Eligibility Requests: {eligibility_requests}\n"
            elif packet == "LM":
                response = f"Commits: {commits}\n"
            elif packet == "LR":
                response = f"Reveals: {reveals}\n"
            else:
                state = server_state.get_state()

                if packet.startswith("E|"):
                    if state != ELLIGIBILITY:
                        response = "ERROR|Eligibility requests are only allowed in ELLIGIBILITY state.\n"
                    else:
                        response = handle_eligibility_state(packet)
                elif packet.startswith("C|"):
                    if state != COMMIT:
                        response = "ERROR|Commit requests are only allowed in COMMIT state.\n"
                    else:
                        response = handle_commit_state(packet)
                elif packet.startswith("R|"):
                    if state != REVEAL:
                        response = "ERROR|Reveal requests are only allowed in REVEAL state.\n"
                    else:
                        response = handle_reveal_state(packet)
                elif state == ENDED:
                    response = "ERROR|Voting session ended. No further requests accepted.\n"
                else:
                    response = "ERROR|Unknown command or not allowed in current state.\n"

            if response is None:
                response = "ERROR|Malformed packet or unknown request.\n"

            conn.sendall(response.encode())
    finally:
        logger.info(f"Connection with {addr[0]}:{addr[1]} closed.")
        conn.close()

def handle_eligibility_state(packet):
    
    try:
        _, user_id, blinded_pubkey = packet.split('|', 2)
        voter_info = confidential_voters.get(user_id)
        if not voter_info:
            logger.warning(f"Eligibility request for unauthorized ID: {user_id}")
            return "ERROR|Non authorized ID\n"
        blinded_bytes = bytes.fromhex(blinded_pubkey)
        signature = rsa_sign_raw(blinded_bytes, d, n)
        eligibility_requests.append({
            'name': voter_info['name'],
            'lastname': voter_info['lastname'],
            'birthdate': voter_info['birthdate']
        })
        logger.info(f"Eligibility granted for ID: {user_id}")
        return f"OK|{signature.hex()}\n"
    except Exception as e:
        logger.error(f"Eligibility request failed: {e}")
        return f"ERROR|Malformed packet or signing failed: {e}\n"
    return "Command not allowed in ELIGIBILITY state.\n"

def handle_commit_state(packet):
    commits.append(packet)
    logger.info("Commit received and stored.")
    return f"OK\n"

def handle_reveal_state(packet):
    reveals.append(packet)
    logger.info("Reveal received and stored.")
    return f"OK\n"

def verify_server_signature_from_packet(packet, cert_server_path):
    try:
        fields = packet.split("|")
        if len(fields) < 2:
            return False
        pubkey_hex = fields[0]
        signedpubkey_hex = fields[1]
        pubkey_bytes = bytes.fromhex(pubkey_hex)
        h_int = int.from_bytes(SHA256.new(pubkey_bytes).digest(), 'big')
        n, e = load_server_pubkey(cert_server_path)
        signature_int = int(signedpubkey_hex, 16)
        m = pow(signature_int, e, n)
        return m == h_int
    except (ValueError, TypeError):
        return False

def verify_commit_signature_from_packet(packet):
    try:
        fields = packet.split("|")
        if len(fields) < 6:
            return False
        pubkey_hex = fields[0]
        commit_hash_hex = fields[4]
        signedhash_hex = fields[5]
        modulus = int(pubkey_hex, 16)
        exponent = 65537
        public_key = RSA.construct((modulus, exponent))
        signature_int = int(signedhash_hex, 16)
        recovered_int = pow(signature_int, public_key.e, public_key.n)
        expected_int = int(commit_hash_hex, 16)
        return recovered_int == expected_int
    except (ValueError, TypeError):
        return False

def verify_sequence_signature_from_packet(packet):
    try:
        fields = packet.split("|")
        if len(fields) < 4:
            return False
        pubkey_hex = fields[0]
        seq_bytes_hex = fields[2]
        signedseq_hex = fields[3]
        modulus = int(pubkey_hex, 16)
        exponent = 65537
        public_key = RSA.construct((modulus, exponent))
        signature_int = int(signedseq_hex, 16)
        recovered_int = pow(signature_int, public_key.e, public_key.n)
        seq_bytes = bytes.fromhex(seq_bytes_hex)
        seq_hash = SHA256.new(seq_bytes).digest()
        expected_int = int.from_bytes(seq_hash, 'big')
        return recovered_int == expected_int
    except (ValueError, TypeError):
        return False

def verify_reveal_signature_from_packet(packet):
    fields = packet.split("|")
    if len(fields) < 5:
        return False
    pubkey_hex = fields[0]
    candidate_bytes_hex = fields[2]
    salt_hex = fields[3]
    signed_data_hex = fields[4]
    candidate_bytes = bytes.fromhex(candidate_bytes_hex)
    salt_bytes = bytes.fromhex(salt_hex)
    data_hash = hashlib.sha256(candidate_bytes + salt_bytes).digest()
    expected_int = int.from_bytes(data_hash, 'big')
    modulus = int(pubkey_hex, 16)
    exponent = 65537
    public_key = RSA.construct((modulus, exponent))
    signature_int = int(signed_data_hex, 16)
    recovered_int = pow(signature_int, public_key.e, public_key.n)
    return recovered_int == expected_int

def count_votes(commits_list, reveal_list, cert_server_path):
    logger.info("Starting vote counting process.")
    if not commits_list or not reveal_list:
        candidate_id_to_name = {c['id']: f"{c['name']} {c['lastname']}" for c in candidates}
        # Option 1: Return all candidates with 0 votes
        return {name: 0 for name in candidate_id_to_name.values()}
    valid_commits = {}  # Mapping: voter (pubkey_hex) -> (sequence, commit_packet)
    for idx, original_packet in enumerate(commits_list):
        logger.debug(f"Processing commit packet #{idx + 1}: {original_packet}")
        packet = original_packet[2:]  # Remove header
        logger.debug(f"Commit packet after header removal: {packet}")
        if not verify_server_signature_from_packet(packet, cert_server_path):
            logger.warning(f"Commit packet #{idx + 1}: Server signature verification failed.")
            continue
        if not verify_commit_signature_from_packet(packet):
            logger.warning(f"Commit packet #{idx + 1}: Commit signature verification failed.")
            continue
        if not verify_sequence_signature_from_packet(packet):
            logger.warning(f"Commit packet #{idx + 1}: Sequence signature verification failed.")
            continue
        fields = packet.split("|")
        if len(fields) < 6:
            logger.warning(f"Commit packet #{idx + 1}: Insufficient fields ({len(fields)}). Skipping.")
            continue
        voter = fields[0]
        try:
            seq = int(fields[2], 16)
            logger.debug(f"Commit packet #{idx + 1}: Voter: {voter}, Sequence: {seq}.")
        except ValueError:
            logger.warning(f"Commit packet #{idx + 1}: Invalid sequence value. Skipping.")
            continue
        if voter not in valid_commits or seq > valid_commits[voter][0]:
            logger.debug(f"Commit packet #{idx + 1}: Updating valid commit for voter {voter}.")
            valid_commits[voter] = (seq, packet)
        else:
            logger.debug(f"Commit packet #{idx + 1}: Not the highest sequence for voter {voter}.")
    vote_counts = {}
    valid_candidate_ids = {candidate['id'] for candidate in candidates}
    logger.debug(f"Valid candidate IDs: {valid_candidate_ids}")
    revealed_voters = set()  # Track voters who have already had a valid reveal counted
    for idx, original_packet in enumerate(reveal_list):
        logger.debug(f"Processing reveal packet #{idx + 1}: {original_packet}")
        packet = original_packet[2:]  # Remove header
        logger.debug(f"Reveal packet after header removal: {packet}")
        fields = packet.split("|")
        if len(fields) < 5:
            logger.warning(f"Reveal packet #{idx + 1}: Insufficient fields ({len(fields)}). Skipping.")
            continue
        voter = fields[0]
        if voter in revealed_voters:
            logger.info(f"Reveal packet #{idx + 1}: Voter {voter} already had a valid reveal counted. Skipping.")
            continue
        candidate_bytes_hex = fields[2]
        salt_hex = fields[3]
        logger.debug(f"Reveal packet #{idx + 1}: Voter: {voter}, Candidate Hex: {candidate_bytes_hex}, Salt Hex: {salt_hex}.")
        if not verify_reveal_signature_from_packet(packet):
            logger.warning(f"Reveal packet #{idx + 1}: Reveal signature verification failed.")
            continue
        if voter not in valid_commits:
            logger.warning(f"Reveal packet #{idx + 1}: No valid commit found for voter {voter}.")
            continue
        try:
            candidate_bytes = bytes.fromhex(candidate_bytes_hex)
            salt_bytes = bytes.fromhex(salt_hex)
            logger.debug(f"Reveal packet #{idx + 1}: Converted candidate bytes and salt bytes successfully.")
        except Exception as e:
            logger.warning(f"Reveal packet #{idx + 1}: Conversion error: {e}. Skipping.")
            continue
        computed_hash = hashlib.sha256(candidate_bytes + salt_bytes).hexdigest()
        logger.debug(f"Reveal packet #{idx + 1}: Computed hash: {computed_hash}")
        commit_fields = valid_commits[voter][1].split("|")
        if len(commit_fields) < 6:
            logger.warning(f"Reveal packet #{idx + 1}: Valid commit for voter {voter} has insufficient fields. Skipping.")
            continue
        commit_hash_hex = commit_fields[4]
        logger.debug(f"Reveal packet #{idx + 1}: Commit hash from commit packet: {commit_hash_hex}")
        if computed_hash != commit_hash_hex:
            logger.warning(f"Reveal packet #{idx + 1}: Hash mismatch. Computed: {computed_hash}, Expected: {commit_hash_hex}. Skipping.")
            continue
        try:
            candidate_id = int(candidate_bytes_hex, 16)
            logger.debug(f"Reveal packet #{idx + 1}: Candidate ID (integer): {candidate_id}")
        except ValueError:
            logger.warning(f"Reveal packet #{idx + 1}: Invalid candidate_id value. Skipping.")
            continue
        if candidate_id not in valid_candidate_ids:
            logger.warning(f"Reveal packet #{idx + 1}: Candidate ID {candidate_id} not in valid candidates. Skipping.")
            continue
        vote_counts[candidate_id] = vote_counts.get(candidate_id, 0) + 1
        revealed_voters.add(voter)
        logger.info(f"Reveal packet #{idx + 1}: Vote counted for candidate {candidate_id}. Total now: {vote_counts[candidate_id]}")
    logger.info(f"Final vote counts: {vote_counts}")
    candidate_id_to_name = {c['id']: f"{c['name']} {c['lastname']}" for c in candidates}
    sorted_items = sorted(
        ((candidate_id_to_name.get(cid, str(cid)), count) for cid, count in vote_counts.items()),
        key=lambda item: item[1],
        reverse=True
    )
    result_with_names = {name: count for name, count in sorted_items}
    return result_with_names
    
from .data import candidates, voters, eligibility_requests, commits, confidential_voters, reveals
from .state import ServerState, COMMIT, REVEAL, ENDED
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
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
            print(f"[client {addr[0]}:{addr[1]}] {packet}")

            response = "Unknown or malformed request.\n"  # Default response

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
            elif packet == "COUNT":
                results = count_votes(commits, reveals, "server/cert.pem")
                print(results)
            else:
                state = server_state.get_state()
                if state == ENDED:
                    response = "Voting session ended. No further requests accepted.\n"
                elif state == COMMIT:
                    if packet.startswith("E|"):
                        response = handle_eligibility_state(packet)
                    elif packet.startswith("C|"):
                        response = handle_commit_state(packet)
                elif state == REVEAL:
                    if packet.startswith("R|"):
                        response = handle_reveal_state(packet)

            conn.sendall(response.encode())
    finally:
        conn.close()

def handle_eligibility_state(packet):
    try:
        _, user_id, blinded_pubkey= packet.split('|', 2)
        voter_info = confidential_voters.get(user_id)
        if not voter_info:
            return "ERROR|Non authorized ID\n"
        blinded_bytes = bytes.fromhex(blinded_pubkey)
        signature = rsa_sign_raw(blinded_bytes, d, n)
        eligibility_requests.append({
            'name': voter_info['name'],
            'lastname': voter_info['lastname'],
            'birthdate': voter_info['birthdate']
        })
        return f"OK|{signature.hex()}\n"
    except Exception as e:
        return f"ERROR|Malformed packet or signing failed: {e}\n"
    return "Command not allowed in ELIGIBILITY state.\n"

def handle_commit_state(packet):
    commits.append(packet)
    return f"OK\n"

def handle_reveal_state(packet):
    reveals.append(packet)
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
        # Compute the hash of the sequence bytes.
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

    # Recompute the hash of candidate_bytes + salt_bytes
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

import hashlib
import logging

def count_votes(commits_list, reveal_list, cert_server_path):
    logging.debug("Starting count_votes")
    valid_commits = {}  # Mapping: voter (pubkey_hex) -> (sequence, commit_packet)
    
    # Process commit packets.
    for idx, original_packet in enumerate(commits_list):
        logging.debug(f"Processing commit packet #{idx + 1}: {original_packet}")
        packet = original_packet[2:]  # Remove header
        logging.debug(f"Commit packet after header removal: {packet}")
            
        # Verify all signatures.
        if not verify_server_signature_from_packet(packet, cert_server_path):
            logging.debug(f"Commit packet #{idx + 1}: Server signature verification failed.")
            continue
        else:
            logging.debug(f"Commit packet #{idx + 1}: Server signature verified.")
            
        if not verify_commit_signature_from_packet(packet):
            logging.debug(f"Commit packet #{idx + 1}: Commit signature verification failed.")
            continue
        else:
            logging.debug(f"Commit packet #{idx + 1}: Commit signature verified.")
            
        if not verify_sequence_signature_from_packet(packet):
            logging.debug(f"Commit packet #{idx + 1}: Sequence signature verification failed.")
            continue
        else:
            logging.debug(f"Commit packet #{idx + 1}: Sequence signature verified.")
        fields = packet.split("|")
        if len(fields) < 6:
            logging.debug(f"Commit packet #{idx + 1}: Insufficient fields ({len(fields)}). Skipping.")
            continue
        
        voter = fields[0]
        try:
            seq = int(fields[2], 16)
            logging.debug(f"Commit packet #{idx + 1}: Voter: {voter}, Sequence: {seq}.")
        except ValueError:
            logging.debug(f"Commit packet #{idx + 1}: Invalid sequence value. Skipping.")
            continue
        
        # For each voter, keep the commit with the highest sequence.
        if voter not in valid_commits or seq > valid_commits[voter][0]:
            logging.debug(f"Commit packet #{idx + 1}: Updating valid commit for voter {voter}.")
            valid_commits[voter] = (seq, packet)
        else:
            logging.debug(f"Commit packet #{idx + 1}: Not the highest sequence for voter {voter}.")
    
    vote_counts = {}
    # Build a set of valid candidate ids from the candidate table.
    valid_candidate_ids = {candidate['id'] for candidate in candidates}
    logging.debug(f"Valid candidate IDs: {valid_candidate_ids}")
    
    # Process reveal packets.
    for idx, original_packet in enumerate(reveal_list):
        logging.debug(f"Processing reveal packet #{idx + 1}: {original_packet}")
        packet = original_packet[2:]  # Remove header
        logging.debug(f"Reveal packet after header removal: {packet}")
        
        fields = packet.split("|")
        if len(fields) < 5:
            logging.debug(f"Reveal packet #{idx + 1}: Insufficient fields ({len(fields)}). Skipping.")
            continue
        
        voter = fields[0]
        candidate_bytes_hex = fields[2]
        salt_hex = fields[3]
        logging.debug(f"Reveal packet #{idx + 1}: Voter: {voter}, Candidate Hex: {candidate_bytes_hex}, Salt Hex: {salt_hex}.")
        
        if not verify_reveal_signature_from_packet(packet):
            logging.debug(f"Reveal packet #{idx + 1}: Reveal signature verification failed.")
            continue
        else:
            logging.debug(f"Reveal packet #{idx + 1}: Reveal signature verified.")
        
        # Only process if there is a valid commit for this voter.
        if voter not in valid_commits:
            logging.debug(f"Reveal packet #{idx + 1}: No valid commit found for voter {voter}.")
            continue
        
        # For the commit hash verification, we need to recompute the hash.
        try:
            candidate_bytes = bytes.fromhex(candidate_bytes_hex)
            salt_bytes = bytes.fromhex(salt_hex)
            logging.debug(f"Reveal packet #{idx + 1}: Converted candidate bytes and salt bytes successfully.")
        except Exception as e:
            logging.debug(f"Reveal packet #{idx + 1}: Conversion error: {e}. Skipping.")
            continue
        
        # Recompute the commit hash.
        computed_hash = hashlib.sha256(candidate_bytes + salt_bytes).hexdigest()
        logging.debug(f"Reveal packet #{idx + 1}: Computed hash: {computed_hash}")
        
        # Retrieve the commit hash from the valid commit packet.
        commit_fields = valid_commits[voter][1].split("|")
        if len(commit_fields) < 6:
            logging.debug(f"Reveal packet #{idx + 1}: Valid commit for voter {voter} has insufficient fields. Skipping.")
            continue
        commit_hash_hex = commit_fields[4]
        logging.debug(f"Reveal packet #{idx + 1}: Commit hash from commit packet: {commit_hash_hex}")
        
        # Only count this reveal if the computed hash equals the commit hash.
        if computed_hash != commit_hash_hex:
            logging.debug(f"Reveal packet #{idx + 1}: Hash mismatch. Computed: {computed_hash}, Expected: {commit_hash_hex}. Skipping.")
            continue
        
        try:
            # Convert the candidate id from hex to integer.
            candidate_id = int(candidate_bytes_hex, 16)
            logging.debug(f"Reveal packet #{idx + 1}: Candidate ID (integer): {candidate_id}")
        except ValueError:
            logging.debug(f"Reveal packet #{idx + 1}: Invalid candidate_id value. Skipping.")
            continue
        
        # Count the vote only if the candidate id exists in the candidate table.
        if candidate_id not in valid_candidate_ids:
            logging.debug(f"Reveal packet #{idx + 1}: Candidate ID {candidate_id} not in valid candidates. Skipping.")
            continue
        
        vote_counts[candidate_id] = vote_counts.get(candidate_id, 0) + 1
        logging.debug(f"Reveal packet #{idx + 1}: Vote counted for candidate {candidate_id}. Total now: {vote_counts[candidate_id]}")
    
    logging.debug(f"Final vote counts: {vote_counts}")
    return vote_counts
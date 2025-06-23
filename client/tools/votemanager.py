import os
import json
import base64
import getpass
import hashlib
import logging
from Crypto.PublicKey import RSA
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from Crypto.Hash import SHA256
import requests

# --- Logging setup ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)
logger = logging.getLogger("votemanager")

def load_server_pubkey(cert_path):
    with open(cert_path, "rb") as f:
        cert_data = f.read()
    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    pubkey = cert.public_key()
    numbers = pubkey.public_numbers()
    return numbers.n, numbers.e

def generate_r_from_passphrase(passphrase, n):
    pass_bytes = passphrase.encode()
    r = int.from_bytes(pass_bytes.ljust(256, b'\x00'), 'big') % n
    while r < 2 or r >= n or gcd(r, n) != 1:
        r = (r + 1) % n
    return r

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def sign_with_private_key(data_bytes, privkey_bytes):
    key = RSA.import_key(privkey_bytes)
    h_int = int.from_bytes(data_bytes, 'big')
    signature_int = pow(h_int, key.d, key.n)
    key_length = (key.n.bit_length() + 7) // 8
    signature_bytes = signature_int.to_bytes(key_length, byteorder='big')
    return signature_bytes.hex()

def verify_signature(data_bytes, signature_hex, pubkey_n, pubkey_e=65537):
    try:
        signature_int = int(signature_hex, 16)
        key_length = (pubkey_n.bit_length() + 7) // 8
        recovered = pow(signature_int, pubkey_e, pubkey_n)
        expected = int.from_bytes(data_bytes, 'big')
        return recovered == expected
    except Exception as e:
        logger.error(f"Signature verification failed: {e}")
        return False

def get_salt_from_passphrase(passphrase):
    pbkdf2_salt = b"evoting-static-salt"
    salt_bytes = hashlib.pbkdf2_hmac(
        'sha256',
        passphrase.encode('utf-8'),
        pbkdf2_salt,
        100_000,
        dklen=16
    )
    return salt_bytes

class Wallet:
    def __init__(self, path):
        self.path = path
        self.data = {}

    def save(self):
        with open(self.path, "w") as f:
            json.dump(self.data, f, indent=2)

    def load(self):
        if os.path.exists(self.path):
            with open(self.path, "r") as f:
                self.data = json.load(f)

    def set(self, key, value):
        self.data[key] = value

    def get(self, key):
        return self.data.get(key, None)

    def set_private_key(self, privkey_bytes):
        self.set("private_key", base64.b64encode(privkey_bytes).decode())

    def get_private_key_bytes(self):
        return base64.b64decode(self.get("private_key"))

    def set_public_key(self, pubkey_hex):
        self.set("public_key", pubkey_hex)

    def get_public_key(self):
        return self.get("public_key")

    def set_signed_pubkey(self, signed_hex):
        self.set("signed_pubkey", signed_hex)

    def get_signed_pubkey(self):
        return self.get("signed_pubkey")

    def set_salt(self, salt_hex):
        self.set("salt", salt_hex)

    def get_salt(self):
        return self.get("salt")

    def set_candidate(self, candidate):
        self.set("candidate", candidate)

    def get_candidate(self):
        return self.get("candidate")

    def set_sequence(self, seq):
        self.set("sequence", seq)

    def get_sequence(self):
        return self.data.get("sequence", None)

    def get_signed_commit_sequence_hash(self):
        return self.get("signed_commit_sequence_hash")

    def set_commit_hash(self, hash_hex):
        self.set("commit_hash", hash_hex)

    def get_commit_hash(self):
        return self.get("commit_hash")

    def set_signed_commit_sequence_hash(self, sig_hex):
        self.set("signed_commit_sequence_hash", sig_hex)

    # For blinding/unblinding
    def set_blinding_factor(self, r):
        self.set("blinding_factor", str(r))

    def get_blinding_factor(self):
        r = self.get("blinding_factor")
        return int(r) if r is not None else None

    def set_blinded_hash(self, blinded_hex):
        self.set("blinded_hash", blinded_hex)

    def get_blinded_hash(self):
        return self.get("blinded_hash")

def build_reveal_packet(wallet):
    pubkey_hex = wallet.get_public_key()
    signedpubkey_hex = wallet.get_signed_pubkey()
    candidate = wallet.get_candidate()
    salt_hex = wallet.get_salt()
    privkey_bytes = wallet.get_private_key_bytes()
    candidate_bytes = candidate.to_bytes((candidate.bit_length() + 7) // 8 or 1, 'big')
    salt_bytes = bytes.fromhex(salt_hex)
    data_bytes = candidate_bytes + salt_bytes
    data_hash = hashlib.sha256(data_bytes).digest()
    signed_data_hex = sign_with_private_key(data_hash, privkey_bytes)
    packet = "|".join([
        pubkey_hex,
        signedpubkey_hex,
        candidate_bytes.hex(),
        salt_hex,
        signed_data_hex
    ])
    return packet

def verify_reveal_signature_from_wallet(wallet):
    pubkey_hex = wallet.get_public_key()
    candidate = wallet.get_candidate()
    salt_hex = wallet.get_salt()
    privkey_bytes = wallet.get_private_key_bytes()
    candidate_bytes = candidate.to_bytes((candidate.bit_length() + 7) // 8 or 1, 'big')
    salt_bytes = bytes.fromhex(salt_hex)
    data_bytes = candidate_bytes + salt_bytes
    data_hash = hashlib.sha256(data_bytes).digest()
    signed_data_hex = sign_with_private_key(data_hash, privkey_bytes)
    pubkey_n = int(pubkey_hex, 16)
    valid = verify_signature(data_hash, signed_data_hex, pubkey_n)
    logger.info(f"Reveal signature verification: {valid}")
    return valid

def verify_commit_signature_from_wallet(wallet):
    pubkey_hex = wallet.get_public_key()
    pubkey_n = int(pubkey_hex, 16)
    seq = wallet.get_sequence()
    commit_hash_hex = wallet.get_commit_hash()
    signed_combined_hash_hex = wallet.get('signed_commit_sequence_hash')

    if not all([pubkey_hex, seq is not None, commit_hash_hex, signed_combined_hash_hex]):
        logger.error("Missing data in wallet for commit verification.")
        return False

    # Recreate the combined hash
    commit_hash_bytes = bytes.fromhex(commit_hash_hex)
    seq_bytes = seq.to_bytes((seq.bit_length() + 7) // 8 or 1, 'big')
    combined_hash_bytes = hashlib.sha256(commit_hash_bytes + seq_bytes).digest()

    # Verify the signature
    is_valid = verify_signature(combined_hash_bytes, signed_combined_hash_hex, pubkey_n)
    logger.info(f"Combined commit/sequence signature verification: {is_valid}")
    return is_valid

def verify_signed_pubkey(wallet):
    # This checks the server's signature on the public key hash
    pubkey_hex = wallet.get_public_key()
    pubkey_n = int(pubkey_hex, 16)
    signed_pubkey_hex = wallet.get_signed_pubkey()
    if not signed_pubkey_hex:
        logger.error("No signed_pubkey in wallet.")
        return False
    # Hash the public key modulus
    pubkey_bytes = pubkey_n.to_bytes((pubkey_n.bit_length() + 7) // 8, 'big')
    pubkey_hash = int.from_bytes(hashlib.sha256(pubkey_bytes).digest(), 'big')
    signed_pubkey = int(signed_pubkey_hex, 16)
    # Server's public key
    server_n, server_e = load_server_pubkey("client/cert.pem")
    recovered = pow(signed_pubkey, server_e, server_n)
    valid = recovered == pubkey_hash
    logger.debug(f"Signed public key verification: {valid}")
    return valid

def mode_init(wallet, passphrase=None):
    server_n, server_e = load_server_pubkey("client/cert.pem")
    key = RSA.generate(2048)
    pubkey = key.publickey()
    pubkey_hex = hex(pubkey.n)
    wallet.set_private_key(key.export_key(pkcs=8, protection="scryptAndAES128-CBC"))
    wallet.set_public_key(pubkey_hex)
    if passphrase is None:
        passphrase = getpass.getpass("Enter a passphrase for blinding: ")
    pubkey_bytes = pubkey.n.to_bytes((pubkey.n.bit_length() + 7) // 8, 'big')
    pubkey_hash = int.from_bytes(hashlib.sha256(pubkey_bytes).digest(), 'big')
    r = generate_r_from_passphrase(passphrase, server_n)
    blinded = (pubkey_hash * pow(r, server_e, server_n)) % server_n
    byte_len = (server_n.bit_length() + 7) // 8
    hex_len = byte_len * 2
    blinded_hex = f'{blinded:0{hex_len}x}'
    logger.debug(f"Blinded hash of RSA Public Key (hex): {blinded_hex}")
    wallet.set_blinding_factor(r)
    wallet.set_blinded_hash(blinded_hex)
    wallet.save()
    logger.info(f"Wallet initialized and saved to {wallet.path}")

def mode_sign(wallet, signed_blinded_hex=None):
    wallet.load()
    server_n, _ = load_server_pubkey("client/cert.pem")
    r = wallet.get_blinding_factor()
    if r is None:
        logger.error("No blinding factor in wallet. Already signed?")
        return
    blinded = int(wallet.get_blinded_hash(), 16)
    if signed_blinded_hex is None:
        signed_blinded_hex = input("Paste the server's signature on the blinded hash (hex): ")
    signed_blinded = int(signed_blinded_hex.strip(), 16)
    r_inv = pow(r, -1, server_n)
    signed_unblinded = (signed_blinded * r_inv) % server_n
    logger.debug(f"Unblinded signature (hex): {hex(signed_unblinded)}")
    wallet.set_signed_pubkey(hex(signed_unblinded))
    if "blinding_factor" in wallet.data:
        del wallet.data["blinding_factor"]
    wallet.save()
    # Verify the server's signature on the public key hash
    assert verify_signed_pubkey(wallet), "Server signature on public key is invalid!"
    logger.info("Server signature on public key is valid.")

def mode_commit(wallet, candidate=None, passphrase=None):
    wallet.load()
    if candidate is None:
        candidate = int(input("Enter candidate (integer): ").strip())
    if passphrase is None:
        passphrase = input("Enter passphrase for salt: ").strip()

    # Sequence management
    seq = wallet.get_sequence()
    seq = 1 if seq is None else int(seq) + 1
    logger.info(f"Using sequence number: {seq}")

    salt_bytes = get_salt_from_passphrase(passphrase)
    salt_hex = salt_bytes.hex()
    wallet.set_candidate(candidate)
    wallet.set_sequence(seq)
    wallet.set_salt(salt_hex)

    # Create commit hash
    candidate_bytes = candidate.to_bytes((candidate.bit_length() + 7) // 8 or 1, 'big')
    commit_hash_bytes = hashlib.sha256(candidate_bytes + salt_bytes).digest()
    commit_hash_hex = commit_hash_bytes.hex()

    # Create combined hash of commit and sequence
    seq_bytes = seq.to_bytes((seq.bit_length() + 7) // 8 or 1, 'big')
    combined_hash_bytes = hashlib.sha256(commit_hash_bytes + seq_bytes).digest()

    # Sign the combined hash
    signed_combined_hash_hex = sign_with_private_key(combined_hash_bytes, wallet.get_private_key_bytes())

    # Update wallet
    wallet.set_commit_hash(commit_hash_hex)
    wallet.set_signed_commit_sequence_hash(signed_combined_hash_hex)

    # Remove old fields if they exist to avoid confusion
    if wallet.get('signed_sequence'):
        del wallet.data['signed_sequence']
    if wallet.get('signed_commit_hash'):
        del wallet.data['signed_commit_hash']

    wallet.save()

    # Verify signature
    assert verify_commit_signature_from_wallet(wallet), "Combined commit/sequence signature is invalid!"
    logger.info("Combined commit/sequence signature is valid.")
    logger.info(f"Commit stored in wallet : {wallet.path}")

def verify_server_signature_from_packet(packet, cert_server_path):
    """Verifies the server's signature on a public key."""
    try:
        fields = packet.split("|")
        if len(fields) < 2: return False
        pubkey_hex, signedpubkey_hex = fields[0], fields[1]
        # Use fixed size for consistency
        pubkey_bytes = int(pubkey_hex, 16).to_bytes(256, 'big')
        h_int = int.from_bytes(SHA256.new(pubkey_bytes).digest(), 'big')
        n, e = load_server_pubkey(cert_server_path)
        signature_int = int(signedpubkey_hex, 16)
        m = pow(signature_int, e, n)
        return m == h_int
    except (ValueError, TypeError) as e:
        logger.debug(f"Server signature verification failed: {e}")
        return False

def verify_commit_signature_from_packet(packet):
    """Verifies the voter's signature on the commit packet."""
    try:
        fields = packet.split("|")
        if len(fields) < 5: return False
        pubkey_hex, seq_hex, commit_hash_hex, signed_combined_hash_hex = fields[0], fields[2], fields[3], fields[4]
        commit_hash_bytes = bytes.fromhex(commit_hash_hex)
        seq_bytes = bytes.fromhex(seq_hex)
        combined_hash_bytes = hashlib.sha256(commit_hash_bytes + seq_bytes).digest()
        expected_int = int.from_bytes(combined_hash_bytes, 'big')
        modulus = int(pubkey_hex, 16)
        public_key = RSA.construct((modulus, 65537))
        signature_int = int(signed_combined_hash_hex, 16)
        recovered_int = pow(signature_int, public_key.e, public_key.n)
        return recovered_int == expected_int
    except (ValueError, TypeError, IndexError) as e:
        logger.debug(f"Commit signature verification failed: {e}")
        return False

def verify_reveal_signature_from_packet(packet):
    """Verifies the voter's signature on the reveal packet."""
    try:
        fields = packet.split("|")
        if len(fields) < 5: return False
        pubkey_hex, candidate_bytes_hex, salt_hex, signed_data_hex = fields[0], fields[2], fields[3], fields[4]
        candidate_bytes = bytes.fromhex(candidate_bytes_hex)
        salt_bytes = bytes.fromhex(salt_hex)
        data_hash = hashlib.sha256(candidate_bytes + salt_bytes).digest()
        expected_int = int.from_bytes(data_hash, 'big')
        modulus = int(pubkey_hex, 16)
        public_key = RSA.construct((modulus, 65537))
        signature_int = int(signed_data_hex, 16)
        recovered_int = pow(signature_int, public_key.e, public_key.n)
        return recovered_int == expected_int
    except (ValueError, TypeError) as e:
        logger.debug(f"Reveal signature verification failed: {e}")
        return False

def count_votes(commits_list, reveal_list, candidates, cert_server_path):
    """Counts the votes from the bulletin board data."""
    logger.info("Starting vote counting process.")
    if not all([commits_list, reveal_list, candidates]):
        return {}

    valid_commits = {}
    for packet_str in commits_list:
        packet = packet_str[2:]  # Remove "C|"
        if not verify_server_signature_from_packet(packet, cert_server_path) or \
           not verify_commit_signature_from_packet(packet):
            logger.warning(f"Invalid commit packet skipped: {packet[:30]}...")
            continue
        
        fields = packet.split("|")
        voter, seq_hex = fields[0], fields[2]
        seq = int.from_bytes(bytes.fromhex(seq_hex), 'big')
        
        if voter not in valid_commits or seq > valid_commits[voter][0]:
            valid_commits[voter] = (seq, packet)

    vote_counts = {}
    valid_candidate_ids = {c['id'] for c in candidates}
    revealed_voters = set()

    for packet_str in reveal_list:
        packet = packet_str[2:] # Remove "R|"
        voter = packet.split("|")[0]
        
        if voter in revealed_voters: continue
        if not verify_reveal_signature_from_packet(packet): continue
        if voter not in valid_commits: continue

        _, _, candidate_bytes_hex, salt_hex, _ = packet.split("|")
        candidate_bytes = bytes.fromhex(candidate_bytes_hex)
        salt_bytes = bytes.fromhex(salt_hex)
        computed_hash = hashlib.sha256(candidate_bytes + salt_bytes).hexdigest()

        commit_hash_from_board = valid_commits[voter][1].split("|")[3]
        if computed_hash != commit_hash_from_board: continue

        candidate_id = int(candidate_bytes_hex, 16)
        if candidate_id not in valid_candidate_ids: continue

        vote_counts[candidate_id] = vote_counts.get(candidate_id, 0) + 1
        revealed_voters.add(voter)

    candidate_id_to_name = {c['id']: f"{c['name']} {c['lastname']}" for c in candidates}
    return {candidate_id_to_name.get(cid, str(cid)): count for cid, count in vote_counts.items()}

def mode_count(server_url, cert_path):
    export_url = f"{server_url.rstrip('/')}/api/export"
    logger.info(f"--- Fetching bulletin data from {export_url} ---")
    
    try:
        response = requests.get(export_url)
        response.raise_for_status()
        data = response.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"Could not fetch data from server: {e}")
        return
    except json.JSONDecodeError:
        logger.error("Could not parse JSON response from server. Is the election in the 'ENDED' state?")
        return
    error = data.get("error")
    if error:
        logger.error(f"Server returned an error: {error}")
        return
    results = count_votes(
        data.get("commits", []),
        data.get("reveals", []),
        data.get("candidates", []),
        cert_path
    )
    
    print("\n--- VOTE COUNT RESULTS ---")
    if not results:
        print("No valid votes were counted.")
    else:
        print(f"{'Candidate':<30} | {'Votes'}")
        print("-" * 40)
        sorted_results = sorted(results.items(), key=lambda item: item[1], reverse=True)
        for candidate, count in sorted_results:
            print(f"{candidate:<30} | {count}")
    print("-" * 40)

def main():
    import sys
    import argparse
    if len(sys.argv) > 1 and sys.argv[1] == 'count':
        parser = argparse.ArgumentParser(description="Evoting Vote Counter")
        parser.add_argument("mode", choices=["count"])
        parser.add_argument("--server-url", required=True, help="URL of the bulletin board server (e.g., http://localhost:5000).")
        parser.add_argument("--cert", default="client/cert.pem", help="Path to the server's certificate.")
        args = parser.parse_args()
        mode_count(args.server_url, args.cert)

    else:
        parser = argparse.ArgumentParser(description="Evoting Wallet Manager")
        parser.add_argument("wallet", help="Path to wallet JSON file")
        parser.add_argument("mode", choices=["init", "commit", "sign"])
        parser.add_argument("--passphrase", help="Passphrase for blinding or salt")
        parser.add_argument("--candidate", type=int, help="Candidate (integer, for commit)")
        parser.add_argument("--signed-blinded", help="Server's signature on blinded hash (for sign)")
        args = parser.parse_args()

        wallet = Wallet(args.wallet)
        if args.mode == "init":
            mode_init(wallet, passphrase=args.passphrase)
        elif args.mode == "commit":
            mode_commit(wallet, candidate=args.candidate, passphrase=args.passphrase)
        elif args.mode == "sign":
            wallet.load()
            mode_sign(wallet, signed_blinded_hex=args.signed_blinded)
        else:
            logger.error("Unknown mode.")

if __name__ == "__main__":
    main()
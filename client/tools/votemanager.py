import os
import json
import base64
import getpass
import hashlib
import logging
import argparse
from Crypto.PublicKey import RSA
from cryptography import x509
from cryptography.hazmat.backends import default_backend

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

    def set_signed_sequence(self, sig_hex):
        self.set("signed_sequence", sig_hex)

    def get_signed_sequence(self):
        return self.get("signed_sequence")

    def set_commit_hash(self, hash_hex):
        self.set("commit_hash", hash_hex)

    def get_commit_hash(self):
        return self.get("commit_hash")

    def set_signed_commit_hash(self, sig_hex):
        self.set("signed_commit_hash", sig_hex)

    def get_signed_commit_hash(self):
        return self.get("signed_commit_hash")

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
    # Sequence signature
    seq = wallet.get_sequence()
    seq_bytes = seq.to_bytes((seq.bit_length() + 7) // 8 or 1, 'big')
    seq_hash = hashlib.sha256(seq_bytes).digest()
    signed_seq = wallet.get_signed_sequence()
    valid_seq = verify_signature(seq_hash, signed_seq, pubkey_n)
    # Commit hash signature
    commit_hash = wallet.get_commit_hash()
    signed_commit_hash = wallet.get_signed_commit_hash()
    valid_commit = verify_signature(bytes.fromhex(commit_hash), signed_commit_hash, pubkey_n)
    logger.info(f"Sequence signature verification: {valid_seq}")
    logger.info(f"Commit hash signature verification: {valid_commit}")
    return valid_seq and valid_commit

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
    logger.info(f"Signed public key verification: {valid}")
    return valid

def mode_init(wallet, passphrase=None):
    # Generate keys and blinded pubkey
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
    logger.info(f"Blinded hash of RSA Public Key (hex): {blinded_hex}")
    wallet.set_blinding_factor(r)
    wallet.set_blinded_hash(blinded_hex)
    wallet.save()
    logger.info(f"Wallet initialized and saved to {wallet.path}")

def mode_sign(wallet, signed_blinded_hex=None):
    wallet.load()
    server_n, _ = load_server_pubkey("client/cert.pem")
    r = wallet.get_blinding_factor()
    blinded = int(wallet.get_blinded_hash(), 16)
    if signed_blinded_hex is None:
        signed_blinded_hex = input("Paste the server's signature on the blinded hash (hex): ")
    signed_blinded = int(signed_blinded_hex.strip(), 16)
    r_inv = pow(r, -1, server_n)
    signed_unblinded = (signed_blinded * r_inv) % server_n
    logger.info(f"Unblinded signature (hex): {hex(signed_unblinded)}")
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
    if seq is None:
        seq = 1
    else:
        seq = int(seq) + 1
    logger.info(f"Using sequence number: {seq}")
    salt_bytes = get_salt_from_passphrase(passphrase)
    salt_hex = salt_bytes.hex()
    wallet.set_candidate(candidate)
    wallet.set_sequence(seq)
    wallet.set_salt(salt_hex)

    seq_bytes = seq.to_bytes((seq.bit_length() + 7) // 8 or 1, 'big')
    seq_hash = hashlib.sha256(seq_bytes).digest()
    signedseq_hex = sign_with_private_key(seq_hash, wallet.get_private_key_bytes())

    candidate_bytes = candidate.to_bytes((candidate.bit_length() + 7) // 8 or 1, 'big')
    hash_bytes = hashlib.sha256(candidate_bytes + salt_bytes).digest()
    hash_hex = hash_bytes.hex()
    signedhash_hex = sign_with_private_key(hash_bytes, wallet.get_private_key_bytes())

    wallet.set_signed_sequence(signedseq_hex)
    wallet.set_commit_hash(hash_hex)
    wallet.set_signed_commit_hash(signedhash_hex)
    wallet.save()
    # Verify signatures
    assert verify_commit_signature_from_wallet(wallet), "Commit or sequence signature is invalid!"
    logger.info("Commit and sequence signatures are valid.")
    logger.info(f"Commit stored in wallet : {wallet.path}")

def main():
    import sys
    parser = argparse.ArgumentParser(description="Evoting Wallet Manager")
    parser.add_argument("wallet", help="Path to wallet JSON file")
    parser.add_argument("mode", choices=["init", "commit", "sign"], help="Mode: init | commit | sign")
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
        mode_sign(wallet, signed_blinded_hex=args.signed_blinded)
    else:
        logger.error("Unknown mode.")

if __name__ == "__main__":
    main()
import hashlib
import os
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from cryptography import x509
from cryptography.hazmat.backends import default_backend
def get_next_salt_filename():
    base = "client/tools/salts/salt"
    ext = ".bin"
    i = 0
    while True:
        fname = f"{base}{i if i > 0 else ''}{ext}"
        if not os.path.exists(fname):
            return fname
        i += 1

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

def get_input():
    pubkey_hex = input("Enter RSA public key (hex): ").strip()
    signedpubkey_hex = input("Enter RSA signature of public key (hex): ").strip()
    candidate = int(input("Enter candidate (integer): ").strip())
    seq = int(input("Enter sequence number (integer): ").strip())
    passphrase = input("Enter passphrase for salt: ").strip()
    privkey_path = input("Enter your private key file path (PEM): ").strip() 
    salt_bytes = get_salt_from_passphrase(passphrase)
    salt_filename = get_next_salt_filename()
    with open(salt_filename, "wb") as f:
        f.write(salt_bytes)
    print(f"Generated and stored new salt in {salt_filename}.")
    salt_hex = salt_bytes.hex()
    return pubkey_hex, signedpubkey_hex, candidate, seq, salt_hex, privkey_path

def sign_with_private_key(data_bytes, privkey_path):
    with open(privkey_path, "rb") as f:
        key = RSA.import_key(f.read())
    # Direct raw-signing: interpret data_bytes as an integer (assumed to be the hash already)
    h_int = int.from_bytes(data_bytes, 'big')
    # Raw RSA signing: signature = h_int^d mod n.
    signature_int = pow(h_int, key.d, key.n)
    # Convert signature into bytes of full key length.
    key_length = (key.n.bit_length() + 7) // 8
    signature_bytes = signature_int.to_bytes(key_length, byteorder='big')
    return signature_bytes.hex()

def build_packet(pubkey_hex, signedpubkey_hex, candidate, seq, salt_hex, privkey_path):
    # Sequence number as bytes
    seq_bytes = seq.to_bytes((seq.bit_length() + 7) // 8 or 1, 'big')
    hash_bytes = hashlib.sha256(seq_bytes).digest()
    signedseq_hex = sign_with_private_key(hash_bytes, privkey_path)

    # Candidate as bytes
    candidate_bytes = candidate.to_bytes((candidate.bit_length() + 7) // 8 or 1, 'big')
    salt_bytes = bytes.fromhex(salt_hex)
    hash_bytes = hashlib.sha256(candidate_bytes + salt_bytes).digest()
    hash_hex = hash_bytes.hex()

    # Sign the hash
    signedhash_hex = sign_with_private_key(hash_bytes, privkey_path)

    # Build packet
    packet = "|".join([
        pubkey_hex,
        signedpubkey_hex,
        seq_bytes.hex(),
        signedseq_hex,
        hash_hex,
        signedhash_hex
    ])
    return packet
   
def load_server_pubkey(cert_path):
    with open(cert_path, "rb") as f:
        cert_data = f.read()
    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    pubkey = cert.public_key()
    numbers = pubkey.public_numbers()
    return numbers.n, numbers.e

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

if __name__ == "__main__":

    pubkey_hex, signedpubkey_hex, candidate, seq, salt_hex, privkey_path = get_input()
    packet = build_packet(pubkey_hex, signedpubkey_hex, candidate, seq, salt_hex, privkey_path)
    print("Packet (hex):", packet)
    print(verify_server_signature_from_packet(packet, "client/cert.pem"))
    print(verify_commit_signature_from_packet(packet))
    print(verify_sequence_signature_from_packet(packet))
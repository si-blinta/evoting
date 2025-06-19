import getpass
import hashlib
from Crypto.PublicKey import RSA
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import os
def get_next_filename(base_path, base_name, ext):
    i = 0
    while True:
        fname = f"{base_name}{i if i > 0 else ''}{ext}"
        full_path = os.path.join(base_path, fname)
        if not os.path.exists(full_path):
            return full_path
        i += 1

def get_passphrase():
    return getpass.getpass("Enter a passphrase: ")

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

def load_server_pubkey(cert_path):
    with open(cert_path, "rb") as f:
        cert_data = f.read()
    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    pubkey = cert.public_key()
    numbers = pubkey.public_numbers()
    return numbers.n, numbers.e

def main():
    # Load server's public key (e, n) from cert.pem
    server_n, server_e = load_server_pubkey("client/cert.pem")

    # Generate RSA key pair for the client
    key = RSA.generate(2048)
    pubkey = key.publickey()

    # Print the client's public key modulus before blinding
    print("Client RSA Public Key modulus (n) before blinding (hex):")
    print(hex(pubkey.n))

    # Get passphrase from user
    passphrase = get_passphrase()

    # Hash the public key modulus (as bytes)
    pubkey_bytes = pubkey.n.to_bytes((pubkey.n.bit_length() + 7) // 8, 'big')
    pubkey_hash = int.from_bytes(hashlib.sha256(pubkey_bytes).digest(), 'big')

    # Generate blinding factor r using server's n
    r = generate_r_from_passphrase(passphrase, server_n)

    # Blind the hash of the public key modulus using server's e and n: blinded = H(PUB) * r^e mod n
    blinded = (pubkey_hash * pow(r, server_e, server_n)) % server_n

    print("Blinded hash of RSA Public Key (hex):")
    print(hex(blinded))

    priv_path = get_next_filename("client/tools/keys", "private", ".pem")
    with open(priv_path, "wb") as f:
        f.write(key.export_key(pkcs=8, protection="scryptAndAES128-CBC"))

    # Save the original public key
    pub_path = get_next_filename("client/tools/keys", "public", ".pem")
    with open(pub_path, "wb") as f:
        f.write(pubkey.export_key())

    # Prompt user for the server's signature on the blinded hash (hex)
    signed_blinded_hex = input("Paste the server's signature on the blinded hash (hex): ")
    signed_blinded = int(signed_blinded_hex.strip(), 16)

    # Unblind the signature: s' = s * r^-1 mod n
    r_inv = pow(r, -1, server_n)
    signed_unblinded = (signed_blinded * r_inv) % server_n

    print("Unblinded signature (hex):")
    print(hex(signed_unblinded))

if __name__ == "__main__":
    main()
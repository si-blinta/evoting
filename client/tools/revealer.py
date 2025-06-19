from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import hashlib
def get_input():
    pubkey_hex = input("Enter RSA public key (hex): ").strip()
    signedpubkey_hex = input("Enter RSA signature of public key (hex): ").strip()
    candidate = int(input("Enter candidate (integer): ").strip())
    salt_file = input("Enter salt file path (binary): ").strip()
    privkey_path = input("Enter your private key file path: ").strip()

    # Read salt as bytes from file
    with open(salt_file, "rb") as f:
        salt_bytes = f.read()
    salt_hex = salt_bytes.hex()

    return pubkey_hex, signedpubkey_hex, candidate, salt_hex, privkey_path

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

def build_packet(pubkey_hex, signedpubkey_hex, candidate, salt_hex, privkey_path):
    candidate_bytes = candidate.to_bytes((candidate.bit_length() + 7) // 8 or 1, 'big')
    salt_bytes = bytes.fromhex(salt_hex)
    data_bytes = candidate_bytes + salt_bytes
    data_hash = hashlib.sha256(data_bytes).digest()
    signed_data_hex = sign_with_private_key(data_hash, privkey_path)

    packet = "|".join([
        pubkey_hex,
        signedpubkey_hex,
        candidate_bytes.hex(),
        salt_hex,
        signed_data_hex
    ])
    return packet

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
    import hashlib
    data_hash = hashlib.sha256(candidate_bytes + salt_bytes).digest()
    expected_int = int.from_bytes(data_hash, 'big')

    modulus = int(pubkey_hex, 16)
    exponent = 65537
    public_key = RSA.construct((modulus, exponent))
    signature_int = int(signed_data_hex, 16)
    recovered_int = pow(signature_int, public_key.e, public_key.n)

    return recovered_int == expected_int

    
if __name__ == "__main__":
    pubkey_hex, signedpubkey_hex, candidate, salt_hex, privkey_path = get_input()
    packet = build_packet(pubkey_hex, signedpubkey_hex, candidate, salt_hex, privkey_path)
    print("Packet (hex):", packet)
    print(verify_reveal_signature_from_packet(packet))
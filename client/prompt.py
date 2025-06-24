from client.tools.votemanager import Wallet, build_reveal_packet

def print_help():
    print("""
Available commands:
  help                Show this help message
  eligibility        Request eligibility signature (requires ID and blinded pubkey)
  candidate_list      Request the list of candidates from server
  voters_list         Request the list of voters from server
  eligibility_list    Request the list of eligibility requests from server
  commits_list        Request the list of commits from server
  reveal_list         Request the list of reveals from server
  commit              Send a Commit packet to the server (auto from wallet)
  reveal              Send a Reveal packet to the server (auto from wallet)
  exit                Exit the client
""")

def get_user_message():
    try:
        return input("> ")
    except EOFError:
        print("\nExiting.")
        return None

def strip0x(s):
    return s[2:] if isinstance(s, str) and s.startswith("0x") else s

def get_eligibility_data(wallet_path):
    wallet = Wallet(wallet_path)
    wallet.load()
    user_id = input("Enter your ID: ").strip()
    blinded_pubkey = wallet.get_blinded_hash()
    if not blinded_pubkey:
        print("No blinded pubkey found in wallet. Run 'init' in votemanager first.")
        return None, None
    return user_id, strip0x(blinded_pubkey)

def get_commit_data(wallet_path):
    wallet = Wallet(wallet_path)
    wallet.load()
    try:
        seq = wallet.get_sequence()
        commit_hash = wallet.get_commit_hash()
        signed_hash = wallet.get_signed_commit_sequence_hash()

        if not all([wallet.get_public_key(), wallet.get_signed_pubkey(), seq is not None, commit_hash, signed_hash]):
            print("Wallet is not fully prepared for commit. Please run the commit step.")
            return None

        # The sequence needs to be sent as hex
        seq_hex = seq.to_bytes((seq.bit_length() + 7) // 8 or 1, 'big').hex()

        packet = "|".join([
            strip0x(wallet.get_public_key()),
            strip0x(wallet.get_signed_pubkey()),
            seq_hex,
            strip0x(commit_hash),
            strip0x(signed_hash)
        ])
        return packet
    except Exception as e:
        print("Error building commit packet from wallet:", e)
        return None

def get_reveal_data(wallet_path):
    wallet = Wallet(wallet_path)
    wallet.load()
    try:
        packet = build_reveal_packet(wallet)
        fields = packet.split("|")
        fields = [strip0x(f) for f in fields]
        return "|".join(fields)
    except Exception as e:
        print("Error building reveal packet from wallet:", e)
        return None
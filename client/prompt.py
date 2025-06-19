def print_help():
    print("""
Available commands:
  help                Show this help message
  elligibility        Request eligibility signature (requires ID and blinded pubkey)
  candidate_list      Request the list of candidates from server
  voters_list         Request the list of voters from server
  eligibility_list    Request the list of eligibility requests from server
  commits_list        Request the list of commits from server
  reveal_list         Request the list of reveals from server
  commit              Send a Commit packet to the server (requires Commit packet)
  Reveal              Send a Reveal packet to the server (requires Reveal packet)
  exit                Exit the client
""")

def get_user_message():
    try:
        return input("> ")
    except EOFError:
        print("\nExiting.")
        return None

def get_elligibility_data():
    user_id = input("Enter your ID: ").strip()
    blinded_pubkey = input("Enter your blinded RSA pubkey (Hex): ").strip()
    return user_id, blinded_pubkey

def get_commit_data():
    packet = input("Enter your Commit packet (Hex): ").strip()
    return packet

def get_reveal_data():
    packet = input("Enter your Reveal packet (Hex): ").strip()
    return packet
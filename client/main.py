import socket
import ssl
from .prompt import get_user_message, print_help, get_elligibility_data ,get_commit_data, get_reveal_data

HOST = '127.0.0.1'
PORT = 8443
CA_CERT = 'client/cert.pem'

COMMAND_PACKET_MAP = {
    "candidate_list": "LC",
    "voters_list": "LV",
    "eligibility_list": "LE",
    "commits_list": "LM",
    "reveal_list" : "LR",  
    "count": "COUNT"
}

def main():
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_CERT)
    context.check_hostname = True

    with socket.create_connection((HOST, PORT)) as sock:
        with context.wrap_socket(sock, server_hostname=HOST) as ssock:
            print("TLS established. Type 'help' for commands. Ctrl+D (or Ctrl+Z) to exit.")
            while True:
                message = get_user_message()
                if message is None or message.lower() == "exit":
                    break
                message = message.strip()
                if not message:
                    continue
                if message.lower() == "help":
                    print_help()
                    continue

                if message.lower() == "reveal": 
                    reveal_packet = f"R|{get_reveal_data()}"
                    ssock.sendall(reveal_packet.encode())
                    try:
                        response = ssock.recv(4096)
                        if not response:
                            print("Server closed the connection.")
                            break
                        print(response.decode())
                    except Exception as e:
                        print("Error receiving response:", e)
                        break
                    continue

                if message.lower() == "commit": 
                    commit_packet = f"C|{get_commit_data()}"
                    ssock.sendall(commit_packet.encode())
                    try:
                        response = ssock.recv(4096)
                        if not response:
                            print("Server closed the connection.")
                            break
                        print(response.decode())
                    except Exception as e:
                        print("Error receiving response:", e)
                        break
                    continue
                if message.lower() == "elligibility":
                    user_id, blinded_pubkey = get_elligibility_data()
                    packet = f"E|{user_id}|{blinded_pubkey}"
                    ssock.sendall(packet.encode())
                    try:
                        response = ssock.recv(4096)
                        if not response:
                            print("Server closed the connection.")
                            break
                        print(response.decode())
                    except Exception as e:
                        print("Error receiving response:", e)
                        break
                    continue
                packet = COMMAND_PACKET_MAP.get(message.lower())
                if packet:
                    ssock.sendall(packet.encode())
                    try:
                        response = ssock.recv(4096)
                        if not response:
                            print("Server closed the connection.")
                            break
                        print(response.decode())
                    except Exception as e:
                        print("Error receiving response:", e)
                        break
                else:
                    print("Unknown command. Type 'help' for available commands.")

if __name__ == "__main__":
    main()

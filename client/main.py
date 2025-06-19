import sys
import socket
import ssl
import logging
from .prompt import get_user_message, print_help, get_elligibility_data, get_commit_data, get_reveal_data, strip0x
from client.tools.votemanager import Wallet, mode_sign

# --- Logging setup ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)
logger = logging.getLogger("client.main")

HOST = '127.0.0.1'
PORT = 8443
CA_CERT = 'client/cert.pem'

COMMAND_PACKET_MAP = {
    "candidate_list": "LC",
    "voters_list": "LV",
    "eligibility_list": "LE",
    "commits_list": "LM",
    "reveal_list": "LR",
    "count": "COUNT"
}

def main():
    if len(sys.argv) < 2:
        logger.error("Usage: python3 -m client.main <wallet_path> [command] [options]")
        return
    wallet_path = sys.argv[1]
    command = sys.argv[2] if len(sys.argv) > 2 else None
    options = sys.argv[3:] if len(sys.argv) > 3 else []

    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_CERT)
    context.check_hostname = True

    def run_command(cmd, wallet_path, options):
        if cmd == "reveal":
            reveal_packet = get_reveal_data(wallet_path)
            if not reveal_packet:
                logger.warning("Could not build reveal packet from wallet.")
                return
            packet = f"R|{reveal_packet}"
        elif cmd == "commit":
            commit_packet = get_commit_data(wallet_path)
            if not commit_packet:
                logger.warning("Could not build commit packet from wallet.")
                return
            packet = f"C|{commit_packet}"
        elif cmd == "elligibility":
            # Support --id argument
            user_id = None
            for i, opt in enumerate(options):
                if opt == "--id" and i + 1 < len(options):
                    user_id = options[i + 1]
            if not user_id:
                user_id = input("Enter your ID: ").strip()
            wallet = Wallet(wallet_path)
            wallet.load()
            blinded_pubkey = wallet.get_blinded_hash()
            if not blinded_pubkey:
                logger.warning("No blinded pubkey found in wallet. Run 'init' in votemanager first.")
                return
            packet = f"E|{user_id}|{strip0x(blinded_pubkey)}"
        elif cmd in COMMAND_PACKET_MAP:
            packet = COMMAND_PACKET_MAP[cmd]
        else:
            logger.error(f"Unknown command: {cmd}")
            return

        with socket.create_connection((HOST, PORT)) as sock:
            with context.wrap_socket(sock, server_hostname=HOST) as ssock:
                ssock.sendall(packet.encode())
                try:
                    response = ssock.recv(4096)
                    if not response:
                        logger.warning("Server closed the connection.")
                        return
                    response_text = response.decode().strip()
                    logger.info(f"Server response: {response_text}")
                    # Handle eligibility auto-sign
                    if cmd == "elligibility" and response_text.startswith("OK"):
                        parts = response_text.strip().split("|", 1)
                        if len(parts) == 2:
                            signed_blinded_hex = parts[1].strip()
                            wallet = Wallet(wallet_path)
                            wallet.load()
                            mode_sign(wallet, signed_blinded_hex)
                            logger.info("Wallet updated with signed blinded key.")
                        else:
                            logger.error("Malformed OK response from server.")
                except Exception as e:
                    logger.error(f"Error receiving response: {e}")

    # If a command is given, run it and exit
    if command:
        run_command(command, wallet_path, options)
        return

    # Otherwise, interactive prompt
    try:
        with socket.create_connection((HOST, PORT)) as sock:
            with context.wrap_socket(sock, server_hostname=HOST) as ssock:
                logger.info("TLS established. Type 'help' for commands. Ctrl+D (or Ctrl+Z) to exit.")
                while True:
                    message = get_user_message()
                    if message is None or message.lower() == "exit":
                        logger.info("Exiting client.")
                        break
                    message = message.strip()
                    if not message:
                        continue
                    if message.lower() == "help":
                        print_help()
                        continue

                    if message.lower() == "reveal":
                        reveal_packet = get_reveal_data(wallet_path)
                        if not reveal_packet:
                            logger.warning("Could not build reveal packet from wallet.")
                            continue
                        packet = f"R|{reveal_packet}"
                        ssock.sendall(packet.encode())
                        try:
                            response = ssock.recv(4096)
                            if not response:
                                logger.warning("Server closed the connection.")
                                break
                            logger.info(f"Server response: {response.decode().strip()}")
                        except Exception as e:
                            logger.error(f"Error receiving response: {e}")
                            break
                        continue

                    if message.lower() == "commit":
                        commit_packet = get_commit_data(wallet_path)
                        if not commit_packet:
                            logger.warning("Could not build commit packet from wallet.")
                            continue
                        packet = f"C|{commit_packet}"
                        ssock.sendall(packet.encode())
                        try:
                            response = ssock.recv(4096)
                            if not response:
                                logger.warning("Server closed the connection.")
                                break
                            logger.info(f"Server response: {response.decode().strip()}")
                        except Exception as e:
                            logger.error(f"Error receiving response: {e}")
                            break
                        continue

                    if message.lower() == "elligibility":
                        user_id = input("Enter your ID: ").strip()
                        wallet = Wallet(wallet_path)
                        wallet.load()
                        blinded_pubkey = wallet.get_blinded_hash()
                        if not blinded_pubkey:
                            logger.warning("No blinded pubkey found in wallet. Run 'init' in votemanager first.")
                            continue
                        packet = f"E|{user_id}|{strip0x(blinded_pubkey)}"
                        ssock.sendall(packet.encode())
                        try:
                            response = ssock.recv(4096)
                            if not response:
                                logger.warning("Server closed the connection.")
                                break
                            response_text = response.decode()
                            logger.info(f"Server response: {response_text.strip()}")
                            if response_text.startswith("OK"):
                                parts = response_text.strip().split("|", 1)
                                if len(parts) == 2:
                                    signed_blinded_hex = parts[1].strip()
                                    wallet = Wallet(wallet_path)
                                    wallet.load()
                                    mode_sign(wallet, signed_blinded_hex)
                                    logger.info("Wallet updated with signed blinded key.")
                                else:
                                    logger.error("Malformed OK response from server.")
                        except Exception as e:
                            logger.error(f"Error receiving response: {e}")
                            break
                        continue

                    packet = COMMAND_PACKET_MAP.get(message.lower())
                    if packet:
                        ssock.sendall(packet.encode())
                        try:
                            response = ssock.recv(4096)
                            if not response:
                                logger.warning("Server closed the connection.")
                                break
                            logger.info(f"Server response: {response.decode().strip()}")
                        except Exception as e:
                            logger.error(f"Error receiving response: {e}")
                            break
                    else:
                        logger.warning("Unknown command. Type 'help' for available commands.")
    except Exception as e:
        logger.error(f"Could not connect to server: {e}")

if __name__ == "__main__":
    main()
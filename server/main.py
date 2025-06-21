import eventlet
eventlet.monkey_patch()
from .bulletin import periodic_broadcast
import socket
import ssl
import threading
from .handler import handle_client
from .state import ServerState  
import logging
HOST = '127.0.0.1'
PORT = 8443
CERT = 'server/cert.pem'
KEY = 'server/key.pem'

from .bulletin import socketio, app
def start_bulletin():
    socketio.run(app, host="0.0.0.0", port=5000)

def main():
    threading.Thread(target=periodic_broadcast, daemon=True).start()
    threading.Thread(target=start_bulletin, daemon=True).start()
    print("Bulletin board running at http://localhost:5000")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=CERT, keyfile=KEY)
    server_state = ServerState() 
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((HOST, PORT))
        sock.listen(5)
        print(f"Listening on https://{HOST}:{PORT}")
        with context.wrap_socket(sock, server_side=True) as ssock:
            try:
                while True:
                    try:
                        conn, addr = ssock.accept() 
                        threading.Thread(target=handle_client, args=(conn, addr, server_state), daemon=True).start()
                    except KeyboardInterrupt:
                        print("\nShutting down server.")
                        break
            finally:
                print("Socket closed.")

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
    main()

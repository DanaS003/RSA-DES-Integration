import socket
import threading
from rsa import generate_key_pair, generate_random_prime, encrypt_message, decrypt_message

# Key storage
KEYS = {}

PKA_PRIVATE_KEY = "(44369, 133043)"

def initialize_keys():
    global KEYS
    if not KEYS:
        # Store keys
        KEYS = {
            "SENDER_PUBLIC_KEY": (49281, 77629),
            "RECEIVER_PUBLIC_KEY": (797981, 716113),
        }

def handle_client(client_socket):
    try:
        # Receive role (initiator/responder) from the client
        role = client_socket.recv(1024).decode('utf-8')
        if role in KEYS:
            # Send the public key for the requested role
            public_key = KEYS[role]
            encrypted_des_key = encrypt_message(str(public_key), PKA_PRIVATE_KEY)
            client_socket.sendall(str(encrypted_des_key).encode('utf-8'))
        else:
            client_socket.sendall(b"Invalid role")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        client_socket.close()

def start_server():
    initialize_keys()
    host = "0.0.0.0"
    port = 6000

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"PKA Server started on {host}:{port}")

    while True:
        client_socket, addr = server_socket.accept()
        print(f"Connection from {addr}")
        client_handler = threading.Thread(target=handle_client, args=(client_socket,))
        client_handler.start()

if __name__ == "__main__":
    start_server()

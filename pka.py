import socket
import threading
from rsa import generate_key_pair, generate_random_prime

# Key storage
KEYS = {}

def initialize_keys():
    global KEYS
    if not KEYS:
        # Generate key pairs for initiator and responder
        p1, q1 = generate_random_prime(10, 1000), generate_random_prime(10, 1000)
        initiator_private_key, initiator_public_key = generate_key_pair(p1, q1)
        
        p2, q2 = generate_random_prime(10, 1000), generate_random_prime(10, 1000)
        responder_private_key, responder_public_key = generate_key_pair(p2, q2)

        # Store keys
        KEYS = {
            "initiator_private": initiator_private_key,
            "initiator_public": initiator_public_key,
            "responder_private": responder_private_key,
            "responder_public": responder_public_key,
        }

def handle_client(client_socket):
    try:
        # Receive role (initiator/responder) from the client
        role = client_socket.recv(1024).decode('utf-8')
        if role in KEYS:
            # Send the public key for the requested role
            public_key = KEYS[role]
            client_socket.sendall(str(public_key).encode('utf-8'))
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

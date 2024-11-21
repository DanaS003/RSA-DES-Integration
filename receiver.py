import socket
from DES import DES
from rsa import encrypt_message, decrypt_message
from helper import string_to_list, generate_random_nonce


PKA_HOST = "localhost"  
PKA_PORT = 6000        


def fetch_key_from_pka(role):
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((PKA_HOST, PKA_PORT))
        client_socket.sendall(role.encode('utf-8'))  
        key = client_socket.recv(1024).decode('utf-8')
        return key  
    finally:
        client_socket.close()


def main():
    host = socket.gethostname()
    port = 5000
    
    server_socket = socket.socket()
    server_socket.bind((host, port))
    server_socket.listen(1)

    conn, address = server_socket.accept()
    print("Connection from:", address)

    # Fetch keys from PKA server
    responder_private_key = fetch_key_from_pka("responder_private")
    
    initiator_public_key = fetch_key_from_pka("initiator_public")

    # Receive encrypted n1 message from initiator
    encrypted_n1 = conn.recv(1024)
    encrypted_n1 = encrypted_n1.decode('utf-8')  # Convert string back to list
    encrypted_n1 = string_to_list(encrypted_n1)
    
    decrypted_message = decrypt_message(encrypted_n1, responder_private_key)
    id_a, n1 = decrypted_message.split(',')

    # Send response with N1 and N2
    n2 = generate_random_nonce()
    response_message = f"{n1},{n2}"
    encrypted_response = encrypt_message(response_message, initiator_public_key)
    conn.sendall(str(encrypted_response).encode('utf-8'))

    # Receive confirmation with N2
    encrypted_n2 = conn.recv(1024).decode('utf-8')
    encrypted_n2 = string_to_list(encrypted_n2)
    confirmed_n2 = decrypt_message(encrypted_n2, responder_private_key)
    if confirmed_n2 == n2:
        print("Handshake complete. Secure channel established.")
    else:
        print("Handshake failed.")
        server_socket.close()
        return

    # DES Key Exchange
    encrypted_des_key = conn.recv(1024).decode('utf-8')
    encrypted_des_key = string_to_list(encrypted_des_key)
    des_key = decrypt_message(encrypted_des_key, responder_private_key)
    des_key_hex = str(des_key)
    des = DES(des_key_hex)
    print("DES Key securely received and decrypted.")

    # Secure communication begins
    while True:
        data = conn.recv(1024)
        if not data:
            break
        raw_message = data.decode('utf-8')
        plain_text = des.decryption_cbc(raw_message)
        print("Text received:", plain_text)

        message = input(" -> ")
        cipher_text = des.encryption_cbc(message, output_format="hex")
        conn.sendall(bytes(cipher_text, 'utf-8'))

    conn.close()


if __name__ == "__main__":
    main()

import socket
from DES import DES
from rsa import encrypt_message, decrypt_message
from helper import string_to_list, generate_random_nonce


PKA_HOST = "localhost"
PKA_PORT = 6000
PKA_PUBLIC_KEY = "(155729, 133043)"
RECEIVER_PRIVATE_KEY = "(684821, 716113)"


def fetch_key_from_pka(role):
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((PKA_HOST, PKA_PORT))
        client_socket.sendall(role.encode('utf-8'))  
        encrypted_public_key = client_socket.recv(1024).decode('utf-8')
        encrypted_public_key = string_to_list(encrypted_public_key)
        print(f"Encrypted sender public key: {encrypted_public_key}")
        key = decrypt_message(encrypted_public_key, PKA_PUBLIC_KEY)
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
    SENDER_PULBIC_KEY = fetch_key_from_pka("SENDER_PUBLIC_KEY")
    print(f"Sender public key: {SENDER_PULBIC_KEY}")
    
    print()

    # Receive encrypted n1 message from initiator
    encrypted_n1_msg = conn.recv(1024)
    encrypted_n1_msg = encrypted_n1_msg.decode('utf-8')  # Convert string back to list
    encrypted_n1_msg = string_to_list(encrypted_n1_msg)
    
    print(f"Encrypted nonce 1 message received: {encrypted_n1_msg}")
    
    decrypted_n1_msg = decrypt_message(encrypted_n1_msg, RECEIVER_PRIVATE_KEY)
    id_a, n1 = decrypted_n1_msg.split(',')
    
    print(f"Nonce 1 message: {decrypted_n1_msg}")
    
    print()

    # Send response with N1 and N2
    n2 = generate_random_nonce()
    n1_n2_msg = f"{n1},{n2}"
    print(f"Nonce 1 and 2 message: {n1_n2_msg}")
    encrypted_n1_n2_msg = encrypt_message(n1_n2_msg, SENDER_PULBIC_KEY)
    print(f"Encrypted nonce 1 and 2 message sent: {encrypted_n1_n2_msg}")
    conn.sendall(str(encrypted_n1_n2_msg).encode('utf-8'))
    
    print()

    # Receive confirmation with N2
    encrypted_n2_msg = conn.recv(1024).decode('utf-8')
    encrypted_n2_msg = string_to_list(encrypted_n2_msg)
    n2_msg = decrypt_message(encrypted_n2_msg, RECEIVER_PRIVATE_KEY)
    if n2_msg == n2:
        print("Handshake complete. Secure channel established.")
    else:
        print("Handshake failed.")
        server_socket.close()
        return
    
    print()
    
    # DES Key Exchange
    encrypted_des_key = conn.recv(1024).decode('utf-8')
    print(f"Encrypted DES Key received: {encrypted_des_key}")
    encrypted_des_key = string_to_list(encrypted_des_key)
    des_key = decrypt_message(encrypted_des_key, RECEIVER_PRIVATE_KEY)
    print(f"DES Key: {des_key}")
    des = DES(des_key)
    
    print()

    print("Chat:")
    # Secure communication begins
    while True:
        data = conn.recv(1024)
        if not data:
            break
        
        raw_message = data.decode('utf-8')
        print("Cipher text received:", raw_message)
        
        plain_text = des.decryption_cbc(raw_message)
        print("Plain text:", plain_text)

        message = input(" -> ")
        cipher_text = des.encryption_cbc(message, output_format="hex")
        conn.sendall(bytes(cipher_text, 'utf-8'))

    conn.close()


if __name__ == "__main__":
    main()

import socket
from DES import DES
from rsa import encrypt_message, decrypt_message
from helper import string_to_list, generate_des_key, generate_random_nonce


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

    client_socket = socket.socket()
    client_socket.connect((host, port))

    # Fetch keys from PKA server
    responder_public_key = fetch_key_from_pka("responder_public")
    print(f"Responder public key: {responder_public_key}")

    initiator_private_key = fetch_key_from_pka("initiator_private")
    print(f"Initiator private key: {initiator_private_key}")
    
    print()
        
    # Send encrypted message with ID and N1
    id_a = "InitiatorA"
    n1 = generate_random_nonce()
    n1_msg = f"{id_a},{n1}"

    print(f"Nonce 1 message: {n1_msg}")
    encrypted_n1 = encrypt_message(n1_msg, responder_public_key)
    print(f"Encrypted nonce 1 message sent: {encrypted_n1}")
    client_socket.sendall(bytes(str(encrypted_n1), 'utf-8'))
    
    print()
    
    # Receive response with N1 and N2
    encrypted_n1_n2_msg = client_socket.recv(1024).decode('utf-8')
    encrypted_n1_n2_msg = string_to_list(encrypted_n1_n2_msg)
    
    print(f"Encrypted nonce 1 and 2 message received: {encrypted_n1_n2_msg}")
    n1_n2_msg = decrypt_message(encrypted_n1_n2_msg, initiator_private_key)
    print(f"Nonce 1 and 2 message: {n1_n2_msg}")
    
    n1_received, n2 = n1_n2_msg.split(',')

    print()
    
    if n1_received != n1:
        print("Handshake failed.")
        client_socket.close()
        return

    # Send confirmation with N2
    encrypted_n2 = encrypt_message(n2, responder_public_key)
    client_socket.sendall(str(encrypted_n2).encode('utf-8'))

    print("Handshake complete. Secure channel established.")
    
    print()

    # DES Key Exchange
    des_key = generate_des_key()
    des = DES(des_key)
    print(f"DES Key: {des_key}")
    encrypted_des_key = encrypt_message(str(des_key), responder_public_key)
    print(f"Encrypted DES Key sent: {encrypted_des_key}")
    client_socket.sendall(str(encrypted_des_key).encode('utf-8'))

    print()
    
    print("Chat: ")
    # Secure communication begins
    message = input(" -> ")
    while message.lower().strip() != "stop":
        cipher_text = des.encryption_cbc(message, output_format="hex")
        client_socket.sendall(bytes(cipher_text, 'utf-8'))
        
        data = client_socket.recv(1024)
        raw_message = data.decode('utf-8')
        print("Cipher text received:", raw_message)
        
        plain_text = des.decryption_cbc(raw_message, output_format="text")
        print("Plain text:", plain_text)
        
        message = input(" -> ")

    client_socket.close()


if __name__ == "__main__":
    main()

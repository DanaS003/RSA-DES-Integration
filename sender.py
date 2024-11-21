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
    initiator_private_key = fetch_key_from_pka("initiator_private")
        
    # Send encrypted message with ID and N1
    id_a = "InitiatorA"
    n1 = generate_random_nonce()
    message = f"{id_a},{n1}"

    encrypted_n1 = encrypt_message(message, responder_public_key)
    client_socket.sendall(bytes(str(encrypted_n1), 'utf-8'))
    
    # Receive response with N1 and N2
    encrypted_response_n1_n2 = client_socket.recv(1024).decode('utf-8')
    encrypted_response_n1_n2 = string_to_list(encrypted_response_n1_n2)
    
    response_message = decrypt_message(encrypted_response_n1_n2, initiator_private_key)
    
    n1_received, n2 = response_message.split(',')

    if n1_received != n1:
        print("Handshake failed.")
        client_socket.close()
        return

    # Send confirmation with N2
    encrypted_n2 = encrypt_message(n2, responder_public_key)
    client_socket.sendall(str(encrypted_n2).encode('utf-8'))

    print("Handshake complete. Secure channel established.")

    # DES Key Exchange
    des_key = generate_des_key()
    des = DES(des_key)
    encrypted_des_key = encrypt_message(str(des_key), responder_public_key)
    client_socket.sendall(str(encrypted_des_key).encode('utf-8'))
    print("DES Key sent")

    # Secure communication begins
    message = input(" -> ")
    while message.lower().strip() != "stop":
        cipher_text = des.encryption_cbc(message, output_format="hex")
        client_socket.sendall(bytes(cipher_text, 'utf-8'))
        data = client_socket.recv(1024)
        raw_message = data.decode('utf-8')
        plain_text = des.decryption_cbc(raw_message, output_format="text")
        print("Text received:", plain_text)
        message = input(" -> ")

    client_socket.close()


if __name__ == "__main__":
    main()

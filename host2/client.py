import json
import socket
import logging
import galois
import secrets
import time
import math

# Load configuration from config.json
with open('config.json', 'r') as config_file:
    config = json.load(config_file)

# Configure logging
logging.basicConfig(filename='journal.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Extract configuration values
alice_port = int(config['alice_port'], 10)
bob_port = int(config['bob_port'], 10)
order = int(config['private_key_length'], 10)
field_order = 2**order  # GF(2^256)
message_str = (config['message'])
message = galois.GF(field_order)(int.from_bytes(message_str.encode(), 'big'))

def find_coprime():
    modulus = field_order - 1
    while True:
        e = secrets.randbits(order - 1)
        if math.gcd(e, modulus) == 1:
            return e

def compute_modular_inverse(e):
    modulus = field_order - 1
    d = pow(e, -1, modulus)
    return d

# Generate 256-bit private keys
private_key = find_coprime()
compliment_key = compute_modular_inverse(private_key)

logging.info(f"Private key: {hex(int(private_key))}")
logging.info(f"Message is: {message_str}")

class MasseyOmura:
    def __init__(self, private_key, compliment_key):
        self.private_key = private_key
        self.compliment_key = compliment_key

    def encrypt_stage1(self, message):
        return message ** self.private_key

    def decrypt_stage1(self, ciphertext):
        return ciphertext ** self.compliment_key

    def encrypt_stage2(self, message):
        return message ** self.private_key

    def decrypt_stage2(self, ciphertext):
        return ciphertext ** self.compliment_key

    
def connect_with_retry(host, port, max_retries=5, delay=2):
    retries = 0
    while retries < max_retries:
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((host, port))
            logging.info(f"Connected to {host}:{port}")
            return client_socket
        except socket.error as e:
            retries += 1
            logging.warning(f"Connection attempt {retries} failed: {e}")
            if retries < max_retries:
                logging.info(f"Retrying in {delay} seconds...")
                time.sleep(delay)
            else:
                logging.error(f"Failed to connect after {max_retries} attempts")
                raise e

def send_message(host, port, message, massey_omura):
    try:
        client_socket = connect_with_retry(host, port)
        # Stage 1: Alice encrypts the message with her private key
        encrypted_message_stage1 = massey_omura.encrypt_stage1(message)
        logging.info(f"Stage 1: Encrypted message (Alice -> Bob): {hex(int(encrypted_message_stage1))}")

        # Send the encrypted message
        client_socket.send(str(int(encrypted_message_stage1)).encode())

        # Receive the encrypted message from Bob
        encrypted_message_stage2 = galois.GF(field_order)(int(client_socket.recv(1024).decode()))
        logging.info(f"Stage 2: Received encrypted message (Bob -> Alice): {hex(int(encrypted_message_stage2))}")

        # Stage 3: Alice decrypts the received message with her private key
        decrypted_message_stage3 = massey_omura.decrypt_stage1(encrypted_message_stage2)
        logging.info(f"Stage 3: Decrypted message (Alice -> Bob): {hex(int(decrypted_message_stage3))}")

        # Send the partially decrypted message
        client_socket.send(str(int(decrypted_message_stage3)).encode())

    finally:
        client_socket.close()

def start_server(host, port, massey_omura):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(100)
    logging.info(f"Server listening on {host}:{port}")

    while True:
        client_socket, client_address = server_socket.accept()
        logging.info(f"Connection from {client_address}")

        try:
            # Receive the encrypted message from Alice
            encrypted_message_stage1 = galois.GF(field_order)(int(client_socket.recv(1024).decode()))
            logging.info(f"Stage 1: Received encrypted message (Alice -> Bob): {hex(int(encrypted_message_stage1))}")

            # Stage 2: Bob encrypts the received message with his private key
            encrypted_message_stage2 = massey_omura.encrypt_stage2(encrypted_message_stage1)
            logging.info(f"Stage 2: Encrypted message (Bob -> Alice): {hex(int(encrypted_message_stage2))}")

            # Send the encrypted message
            client_socket.send(str(int(encrypted_message_stage2)).encode())

            # Receive the decrypted message from Alice
            decrypted_message_stage3 = galois.GF(field_order)(int(client_socket.recv(1024).decode()))
            logging.info(f"Stage 3: Received decrypted message (Alice -> Bob): {hex(int(decrypted_message_stage3))}")

            # Final decryption by Bob
            final_message = massey_omura.decrypt_stage2(decrypted_message_stage3)
            integer_value = int(final_message)
            final_message_bytes = integer_value.to_bytes((integer_value.bit_length() + 7) // 8, 'big')
            final_message_str = final_message_bytes.decode()
            logging.info(f"Final Decrypted Message: {final_message_str}")
            print(f"Decrypted Message: {final_message_str}")

        finally:
            client_socket.close()

if __name__ == "__main__":
    massey_omura = MasseyOmura(private_key, compliment_key)

    # Start the server in a separate thread or process if needed
    import threading
    server_thread = threading.Thread(target=start_server, args=('localhost', bob_port, massey_omura))
    server_thread.start()

    # Send a message to the server
    decrypted_message = send_message('localhost', alice_port, message, massey_omura)
    
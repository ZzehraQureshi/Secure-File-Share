import os
import time
import rsa
import socket
import json
import socks
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def load_config():
    with open("config.json", "r") as f:
        config = json.load(f)
    return config

config = load_config()

import rsa
import os

def generate_rsa_keys(username): 
    private_key_file = f"{username}_private.pem"
    public_key_file = f"{username}_public.pem"
    
    if os.path.exists(private_key_file) and os.path.exists(public_key_file):
        with open(private_key_file, "rb") as f:
            private_key = rsa.PrivateKey.load_pkcs1(f.read())
        with open(public_key_file, "rb") as f:
            public_key = rsa.PublicKey.load_pkcs1(f.read())
    else:
        public_key, private_key = rsa.newkeys(2048)
        with open(private_key_file, "wb") as priv_file:
            priv_file.write(private_key.save_pkcs1())
        with open(public_key_file, "wb") as pub_file:
            pub_file.write(public_key.save_pkcs1(format="PEM"))
    
    return private_key, public_key

def send_public_key(username, recipient_ip, port):
    public_key_file = f"{username}_public.pem"
    with open(public_key_file, "rb") as f:
        public_key_data = f.read()
    
    print(f"Connecting to {recipient_ip}:{port} to send public key...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((recipient_ip, port))
        s.sendall(public_key_data)
    print("Public key sent.")

def receive_public_key(sender_username, port):
    public_key_file = f"{sender_username}_public.pem"
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("0.0.0.0", port))
        s.listen(1)
        print(f"Listening on port {port} for public key...")
        conn, addr = s.accept()
        with conn:
            public_key_data = conn.recv(4096)
            with open(public_key_file, "wb") as f:
                f.write(public_key_data)
    print("Public key received.")

def encrypt_file(file_path, recipient_public_key):
    aes_key = get_random_bytes(32)
    iv = get_random_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)

    with open(file_path, "rb") as f:
        plaintext = f.read()
    pad_len = 16 - (len(plaintext) % 16)
    padded_plaintext = plaintext + bytes([pad_len] * pad_len)
    ciphertext = cipher.encrypt(padded_plaintext)

    encrypted_file_path = file_path + ".enc"
    with open(encrypted_file_path, "wb") as f:
        f.write(iv + ciphertext)

    encrypted_aes_key = rsa.encrypt(aes_key, recipient_public_key)
    with open("aes_key.enc", "wb") as f:
        f.write(encrypted_aes_key)

    print("File encrypted.")

def decrypt_file(private_key, encrypted_file_path):
    with open("aes_key.enc", "rb") as f:
        encrypted_key = f.read()
    
    try:
        aes_key = rsa.decrypt(encrypted_key, private_key)
    except rsa.pkcs1.DecryptionError:
        print("Decryption failed! Wrong private key?")
        return

    with open(encrypted_file_path, "rb") as f:
        iv = f.read(16)
        ciphertext = f.read()

    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext).rstrip(b" ")

    decrypted_path = encrypted_file_path.replace(".enc", "_decrypted")
    with open(decrypted_path, "wb") as f:
        f.write(plaintext)

    print(f"File decrypted to {decrypted_path}")

def send_file(file_path, recipient_ip, port):
    with open(file_path, "rb") as f:
        data = f.read()
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((recipient_ip, port))
        s.sendall(data)
    print(f"File {file_path} sent to {recipient_ip}:{port}")

def receive_file(port, save_as):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("0.0.0.0", port))
        s.listen(1)
        print(f"Waiting for file on port {port}...")
        conn, addr = s.accept()
        with conn:
            data = b""
            while True:
                packet = conn.recv(4096)
                if not packet:
                    break
                data += packet
            with open(save_as, "wb") as f:
                f.write(data)
    print(f"File received and saved as {save_as}")

def main():
    role = input("Are you sender or receiver? ").strip().lower()
    username = input("Enter your username: ").strip()
    private_key, public_key = generate_rsa_keys(username)

    if role == "sender":
        recipient = input("Recipient username: ").strip()
        ip = input("Recipient IP (127.0.0.1 for local testing): ").strip()
        port = int(input("Recipient port: ").strip())
        file_path = input("File to send: ").strip()

        send_public_key(username, ip, port)
        
        pub_key_file = f"{recipient}_public.pem"
        while not os.path.exists(pub_key_file):
            print("Waiting for recipient's public key...")
            time.sleep(2)
        
        with open(pub_key_file, "rb") as f:
            recipient_pubkey = rsa.PublicKey.load_pkcs1(f.read())
        
        encrypt_file(file_path, recipient_pubkey)
        send_file(file_path + ".enc", ip, port)
        send_file("aes_key.enc", ip, port)

    elif role == "receiver":
        sender = input("Sender username: ").strip()
        port = int(input("Port to listen on: ").strip())

        receive_public_key(sender, port)
        receive_file(port, "received.enc")
        receive_file(port, "aes_key.enc")
        decrypt_file(private_key, "received.enc")

if __name__ == "__main__":
    main()
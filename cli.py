import argparse
from pqcrypto.kem.kyber import generate_keypair, encrypt, decrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding
import os
from oqs import KeyEncapsulation
# Replace:
# from pqcrypto.kem.kyber import generate_keypair, encrypt, decrypt

# Use liboqs instead:
kem = KeyEncapsulation("Kyber512")
public_key = kem.generate_keypair()
ciphertext, shared_secret = kem.encap_secret(public_key)
# ... (adjust other parts of your code)

def generate_keys():
    public_key, secret_key = generate_keypair()
    with open("public_key.bin", "wb") as f:
        f.write(public_key)
    with open("secret_key.bin", "wb") as f:
        f.write(secret_key)
    print("[+] Quantum-safe keys generated!")

def encrypt_file(filename: str, public_key_path: str):
    with open(public_key_path, "rb") as f:
        public_key = f.read()
    ciphertext, shared_secret = encrypt(public_key)
    aes_key = hashes.Hash(hashes.SHA256()).update(shared_secret).finalize()[:32]
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv)).encryptor()
    with open(filename, "rb") as f:
        plaintext = f.read()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    encrypted_data = cipher.update(padded_data) + cipher.finalize()
    tag = cipher.tag
    with open(f"{filename}.enc", "wb") as f:
        f.write(iv + tag + encrypted_data + ciphertext)
    print(f"[+] Encrypted {filename} to {filename}.enc")

def decrypt_file(filename: str, secret_key_path: str):
    with open(secret_key_path, "rb") as f:
        secret_key = f.read()
    with open(filename, "rb") as f:
        data = f.read()
    iv, tag, rest = data[:12], data[12:28], data[28:]
    aes_ciphertext, kyber_ciphertext = rest[:-1088], rest[-1088:]
    shared_secret = decrypt(kyber_ciphertext, secret_key)
    aes_key = hashes.Hash(hashes.SHA256()).update(shared_secret).finalize()[:32]
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag)).decryptor()
    padded_plaintext = cipher.update(aes_ciphertext) + cipher.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    output_name = filename.replace(".enc", ".dec")
    with open(output_name, "wb") as f:
        f.write(plaintext)
    print(f"[+] Decrypted {filename} to {output_name}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="QuantumLocker CLI")
    parser.add_argument("--generate-keys", action="store_true", help="Generate keys")
    parser.add_argument("--encrypt", type=str, help="File to encrypt")
    parser.add_argument("--decrypt", type=str, help="File to decrypt")
    parser.add_argument("--public-key", type=str, default="public_key.bin")
    parser.add_argument("--secret-key", type=str, default="secret_key.bin")
    args = parser.parse_args()

    if args.generate_keys:
        generate_keys()
    elif args.encrypt:
        encrypt_file(args.encrypt, args.public_key)
    elif args.decrypt:
        decrypt_file(args.decrypt, args.secret_key)
    else:
        print("Error: Use --generate-keys, --encrypt, or --decrypt.")
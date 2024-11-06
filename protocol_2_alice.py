import socket
import logging
import json
import random
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import argparse

BLOCK_SIZE = 32

def generate_prime_pair(lower=400, upper=500):
    """Generate two primes p and q in range (400, 500)."""
    primes = []
    for num in range(lower, upper+1):
        if is_prime(num):
            primes.append(num)
    p, q = random.sample(primes, 2)
    return p, q

def is_prime(n):
    """Check if a number is prime."""
    if n <= 1:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True

def rsa_keygen(p, q):
    """Generate RSA public/private key pair."""
    n = p * q
    phi_n = (p - 1) * (q - 1)
    e = 65537  # Common choice for e
    d = mod_inverse(e, phi_n)
    return (n, e), (n, d)

def mod_inverse(a, m):
    """Return the modular inverse of a under modulo m."""
    m0, x0, x1 = m, 0, 1
    if m == 1:
        return 0
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def rsa_encrypt(public_key, message):
    """Encrypt each letter of the message using RSA."""
    n, e = public_key
    encrypted_msg = [pow(char, e, n) for char in message]
    return encrypted_msg

def rsa_decrypt(private_key, encrypted_msg):
    """Decrypt the encrypted message using RSA."""
    n, d = private_key
    decrypted_msg = ''.join([chr(pow(char, d, n)) for char in encrypted_msg])
    return decrypted_msg

def encrypt_aes(key, msg):
    """Encrypt a message using AES-ECB."""
    pad = BLOCK_SIZE - len(msg) % BLOCK_SIZE
    msg = msg + pad * chr(pad)
    aes = AES.new(key, AES.MODE_ECB)
    return aes.encrypt(msg.encode())

def decrypt_aes(key, encrypted):
    """Decrypt a message using AES-ECB."""
    aes = AES.new(key, AES.MODE_ECB)
    decrypted = aes.decrypt(encrypted)
    return decrypted.rstrip(decrypted[-1:]).decode()

def run(addr, port):
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((addr, port))
    logging.info("Alice connected to {}:{}".format(addr, port))

    # Fetch RSA public key from Bob
    msg = "hello"  # Example message
    p, q = generate_prime_pair()
    public_key, private_key = rsa_keygen(p, q)
    n, e = public_key
    
    # Alice sends Bob the public key parameters
    smsg = {
        "opcode": 0,
        "type": "RSA"
    }
    sjs = json.dumps(smsg)
    conn.send(sjs.encode("ascii"))
    logging.info("[*] Sent public key: {}".format(smsg))
    
    # Receive Bob's public key
    rbytes = conn.recv(1024)
    rmsg = json.loads(rbytes.decode("ascii"))
    logging.info(f"[*] Received Bob's public key: {rmsg}")

    # Generate and encrypt AES key
    aes_key = get_random_bytes(32)  # AES key is 32 bytes (256 bits)
    print(aes_key)
    encrypted_aes_key = rsa_encrypt((rmsg["parameter"]["n"], rmsg["public"]), aes_key)

    smsg = {
        "opcode": 1,
        "type": "RSA",
        "encrypted_key": encrypted_aes_key  # <-- encrypted_key로 보내야 함
    }
    sjs = json.dumps(smsg)
    conn.send(sjs.encode("ascii"))
    logging.info(f"[*] Sent encrypted AES key to Bob: {encrypted_aes_key}")

    
    # Send encrypted message using AES
    msg = "secret message"
    encrypted_msg = encrypt_aes(aes_key, msg)
    smsg = {
        "opcode": 2,
        "type": "AES",
        "encryption": base64.b64encode(encrypted_msg).decode()
    }
    sjs = json.dumps(smsg)
    print(sjs)
    conn.send(sjs.encode("ascii"))
    logging.info(f"[*] Sent AES encrypted message: {smsg}")

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", metavar="<bob's IP address>", help="Bob's IP address", type=str, default="127.0.0.1")
    parser.add_argument("-p", "--port", metavar="<bob's open port>", help="Bob's port", type=int, required=True)
    parser.add_argument("-l", "--log", metavar="<log level>", help="Log level", type=str, default="INFO")
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    logging.basicConfig(level=args.log)
    run(args.addr, args.port)

if __name__ == "__main__":
    main()

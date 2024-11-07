import socket
import logging
import json
import random
import argparse
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import math

BLOCK_SIZE = 32

def is_prime(n):
    if n <= 1:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True

def generate_prime_pair(lower=400, upper=500):
    """Generate two primes p and q in range (400, 500)."""
    primes = []
    for num in range(lower, upper + 1):
        if is_prime(num):
            primes.append(num)
    p, q = random.sample(primes, 2)
    return p, q

def rsa_keygen(p, q):
    """Generate RSA public/private key pair with a random coprime for e."""
    n = p * q
    phi_n = (p - 1) * (q - 1)

    # Choose e randomly such that 1 < e < phi_n and gcd(e, phi_n) == 1
    while True:
        e = random.randint(2, phi_n - 1)
        if math.gcd(e, phi_n) == 1:
            break

    # Calculate d, the modular inverse of e modulo phi_n
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
    decrypted_msg = b''
    for char in encrypted_msg:
        decrypted_msg += pow(char, d, n).to_bytes(1, byteorder='big')
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

def handler(conn):
    try:
        # Generate RSA key pair for Bob
        p, q = generate_prime_pair()
        public_key, private_key = rsa_keygen(p, q)
        n, e = public_key

        # Resived 
        rbytes = conn.recv(2048)
        rmsg = json.loads(rbytes.decode("ascii"))
        print(rmsg)

        # Send RSA public key to Alice
        smsg = {
            "opcode": 1,
            "type": "RSA",
            "public": e,
            "parameter": {"n": n}
        }
        sjs = json.dumps(smsg)
        conn.send(sjs.encode("ascii"))
        logging.info("[*] Sent RSA public key to Alice")

        # Receive RSA encrypted symmetric key from Alice
        rbytes = conn.recv(2048)
        rmsg = json.loads(rbytes.decode("ascii"))
        print(rmsg)
        encrypted_key = rmsg.get("encrypted_key")
        if encrypted_key is None:
            logging.error("[*] Missing encrypted_key in Alice's message")
            return

        # Decrypt the symmetric key using RSA
        aes_key = rsa_decrypt(private_key, encrypted_key)
        logging.info("[*] Decrypted AES key: {}".format(len(aes_key)))

        # Receive AES encrypted message from Alice
        rbytes = conn.recv(1024)
        rmsg = json.loads(rbytes.decode("ascii"))
        encrypted_msg = base64.b64decode(rmsg["encryption"])

        # Decrypt the message using AES
        msg = decrypt_aes(aes_key, encrypted_msg)
        logging.info("[*] Decrypted message: {}".format(msg))

        # Encrypt a new message using AES
        new_msg = "world"
        encrypted_new_msg = encrypt_aes(aes_key, new_msg)
        smsg = {
            "opcode": 2,
            "type": "AES",
            "encryption": base64.b64encode(encrypted_new_msg).decode()
        }
        sjs = json.dumps(smsg)
        conn.send(sjs.encode("ascii"))
        logging.info("[*] Sent AES encrypted message to Alice")

    except Exception as e:
        logging.error(f"Error in handler: {e}")
    finally:
        logging.info("[*] Closing connection to Alice.")
        conn.close()  # Ensure connection is closed after handling

def run(port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', port))  # Bind to localhost for local communication
    server.listen(5)
    logging.info("Bob is listening on port {}".format(port))

    try:
        conn, addr = server.accept()  # Accept the first incoming connection
        logging.info(f"[*] Connection from {addr}")
        handler(conn)  # Handle the connection
    except Exception as e:
        logging.error(f"Error while accepting connection: {e}")
    finally:
        server.close()  # Ensure the server socket is closed

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--port", metavar="<bob's open port>", help="Bob's port", type=int, required=True)
    parser.add_argument("-l", "--log", metavar="<log level>", help="Log level", type=str, default="INFO")
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    logging.basicConfig(level=args.log)
    run(args.port)

if __name__ == "__main__":
    main()

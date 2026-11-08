import socket
import threading
import argparse
import logging
import json
import base64
from Crypto.Random import random
from Crypto.Cipher import AES


def is_prime(n):
    if n <= 1:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True


def factorize(n):
    factors = set()
    d = 2
    while d * d <= n:
        while (n % d) == 0:
            factors.add(d)
            n //= d
        d += 1
    if n > 1:
        factors.add(n)
    return factors


def is_valid_generator(g, p):
    factors = factorize(p - 1)
    for q in factors:
        if pow(g, (p - 1) // q, p) == 1:
            return False
    return True


def generate_dh_params():
    while True:
        p = random.randint(400, 500)
        if is_prime(p):
            break
    while True:
        g = random.randint(2, p - 1)
        if is_valid_generator(g, p):
            break
    return p, g


def dh_public_key(p, g, private_key):
    return pow(g, private_key, p)


def encrypt(key, msg):
    pad = 16 - len(msg) % 16
    msg = msg + chr(pad) * pad
    aes = AES.new(key, AES.MODE_ECB)
    return aes.encrypt(msg.encode())


def decrypt(key, encrypted):
    aes = AES.new(key, AES.MODE_ECB)
    return aes.decrypt(encrypted)


def recv_message(conn):
    try:
        data = conn.recv(1024)
        if not data:
            raise ConnectionError("Connection closed before a message was received")
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ValueError(f"Received data is not a complete valid JSON message: {e}") from e


def handler(conn, msg):
    try:
        rmsg = recv_message(conn)
        logging.info("[*] Received initial message: %s", rmsg)

        if rmsg.get("opcode") != 0 or rmsg.get("type") != "DH":
            logging.error("Invalid initial message")
            return

        p, g = generate_dh_params()
        bob_private_key = random.randint(2, p - 1)
        bob_public_key = dh_public_key(p, g, bob_private_key)

        smsg = {
            "opcode": 1,
            "type": "DH",
            "public": bob_public_key,
            "parameter": {"p": p, "g": g},
        }
        conn.sendall(json.dumps(smsg).encode("ascii"))
        logging.info("[*] Sent Bob's DH parameters and public key: %s", smsg)

        rmsg = recv_message(conn)
        logging.info("[*] Received Alice's public key: %s", rmsg)
        alice_public_key = rmsg["public"]

        shared_secret = pow(alice_public_key, bob_private_key, p)
        dh_shared_bytes = shared_secret.to_bytes(2, "big")
        aes_key = dh_shared_bytes * 16

        encrypted = encrypt(aes_key, msg)
        smsg = {
            "opcode": 2,
            "type": "AES",
            "encryption": base64.b64encode(encrypted).decode("utf-8"),
        }
        conn.sendall(json.dumps(smsg).encode("ascii"))
        logging.info("[*] Sent Bob's encryption: %s", smsg)

        alice_msg = recv_message(conn)
        alice_encrypted_msg = base64.b64decode(alice_msg["encryption"])
        decrypted_msg = AES.new(aes_key, AES.MODE_ECB).decrypt(alice_encrypted_msg)
        pad_len = decrypted_msg[-1]
        decrypted_msg = decrypted_msg[:-pad_len]

        logging.info(
            "[*] Decrypted message from Alice: %s",
            decrypted_msg.decode("utf-8"),
        )
    except (ConnectionError, ValueError, KeyError, TypeError) as e:
        logging.error("Error handling client message: %s", e)
    finally:
        conn.close()


def run(addr, port, msg):
    bob = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bob.bind((addr, port))
    bob.listen(10)
    logging.info("[*] Bob is listening on %s:%s", addr, port)

    while True:
        conn, info = bob.accept()
        logging.info("[*] Bob accepts connection from %s:%s", info[0], info[1])
        threading.Thread(target=handler, args=(conn, msg)).start()


def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-a",
        "--addr",
        metavar="<bob's IP address>",
        help="Bob's IP address",
        type=str,
        default="0.0.0.0",
    )
    parser.add_argument(
        "-p",
        "--port",
        metavar="<bob's open port>",
        help="Bob's port",
        type=int,
        required=True,
    )
    parser.add_argument(
        "-m", "--message", metavar="<message>", help="Message", type=str, required=True
    )
    parser.add_argument(
        "-l", "--log", metavar="<log level>", help="Log level", type=str, default="INFO"
    )
    return parser.parse_args()


def main():
    args = command_line_args()
    logging.basicConfig(level=args.log)
    run(args.addr, args.port, args.message)


if __name__ == "__main__":
    main()
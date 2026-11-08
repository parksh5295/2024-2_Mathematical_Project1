import argparse
import base64
import json
import logging
import socket
import threading

from Crypto.Cipher import AES
from Crypto.Random import random


def is_prime(n):
    if n <= 1:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True


def factorize(n):
    factors = set()
    divisor = 2
    while divisor * divisor <= n:
        while n % divisor == 0:
            factors.add(divisor)
            n //= divisor
        divisor += 1
    if n > 1:
        factors.add(n)
    return factors


def is_valid_generator(g, p):
    return all(pow(g, (p - 1) // q, p) != 1 for q in factorize(p - 1))


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


def generate_dh_params_wrong_p():
    while True:
        p = random.randint(400, 500)
        if not is_prime(p):
            break
    while True:
        g = random.randint(2, p - 1)
        if is_valid_generator(g, p):
            break
    return p, g


def generate_dh_params_wrong_g():
    while True:
        p = random.randint(400, 500)
        if is_prime(p):
            break
    while True:
        g = random.randint(2, p - 1)
        if not is_valid_generator(g, p):
            break
    return p, g


def dh_public_key(p, g, private_key):
    return pow(g, private_key, p)


def encrypt(key, msg):
    pad = 16 - len(msg) % 16
    padded_msg = msg + chr(pad) * pad
    return AES.new(key, AES.MODE_ECB).encrypt(padded_msg.encode("utf-8"))


def recv_message(conn):
    data = conn.recv(1024)
    if not data:
        raise ConnectionError("Connection closed before a message was received")
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ValueError(f"Received data is not valid JSON: {e}") from e


def send_message(conn, message):
    payload = json.dumps(message).encode("ascii")
    conn.sendall(payload)


def handler(conn, error, msg):
    try:
        initial = recv_message(conn)
        logging.info("[*] Received initial message: %s", initial)
        if initial.get("opcode") != 0 or initial.get("type") != "DH":
            logging.error("Invalid initial message")
            return

        if error == "p":
            p, g = generate_dh_params_wrong_p()
        elif error == "g":
            p, g = generate_dh_params_wrong_g()
        elif error == "None":
            p, g = generate_dh_params()
        else:
            send_message(
                conn,
                {
                    "opcode": 3,
                    "error": "incorrect error args",
                    "error args": error,
                },
            )
            logging.error("Invalid -e value: %s (use p, g, or None)", error)
            return

        bob_private_key = random.randint(2, p - 1)
        bob_public_key = dh_public_key(p, g, bob_private_key)

        send_message(
            conn,
            {
                "opcode": 1,
                "type": "DH",
                "public": bob_public_key,
                "parameter": {"p": p, "g": g},
            },
        )
        logging.info("[*] Sent Bob's DH parameters and public key")

        if error in ("p", "g"):
            alice_error = recv_message(conn)
            logging.info("[*] Received Alice's parameter error: %s", alice_error)
            return

        alice_public = recv_message(conn)
        if alice_public.get("opcode") == 3 and "error" in alice_public:
            logging.error("Alice rejected the DH parameters: %s", alice_public["error"])
            return
        if alice_public.get("opcode") != 1 or alice_public.get("type") != "DH":
            logging.error("Invalid Alice public-key message: %s", alice_public)
            return

        shared_secret = pow(alice_public["public"], bob_private_key, p)
        aes_key = shared_secret.to_bytes(2, "big") * 16

        encrypted = encrypt(aes_key, msg)
        send_message(
            conn,
            {
                "opcode": 2,
                "type": "AES",
                "encryption": base64.b64encode(encrypted).decode("utf-8"),
            },
        )
        logging.info("[*] Sent Bob's encrypted message")

        alice_message = recv_message(conn)
        encrypted_from_alice = base64.b64decode(alice_message["encryption"])
        decrypted = AES.new(aes_key, AES.MODE_ECB).decrypt(encrypted_from_alice)
        pad_len = decrypted[-1]
        if not 1 <= pad_len <= AES.block_size:
            raise ValueError(f"Invalid AES padding length: {pad_len}")
        decrypted = decrypted[:-pad_len]
        logging.info("[*] Decrypted message from Alice: %s", decrypted.decode("utf-8"))
    except (ConnectionError, ValueError, KeyError, TypeError) as e:
        logging.error("Error handling Alice's messages: %s", e)
    finally:
        conn.close()


def run(addr, port, error, msg):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((addr, port))
    server.listen(10)
    logging.info("[*] Bob is listening on %s:%s", addr, port)

    while True:
        conn, info = server.accept()
        logging.info("[*] Bob accepts connection from %s:%s", info[0], info[1])
        threading.Thread(target=handler, args=(conn, error, msg)).start()


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
        "-e",
        "--error",
        metavar="<error mode>",
        help="DH parameter mode: p (invalid prime), g (invalid generator), or None (valid parameters)",
        type=str,
        required=True,
    )
    parser.add_argument(
        "-l",
        "--log",
        metavar="<log level>",
        help="Log level",
        type=str,
        default="INFO",
    )
    return parser.parse_args()


def main():
    args = command_line_args()
    logging.basicConfig(level=args.log)
    run(args.addr, args.port, args.error, args.message)


if __name__ == "__main__":
    main()
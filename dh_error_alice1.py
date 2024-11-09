import socket
import argparse
import logging
import json
import base64
from math import gcd
from Crypto.PublicKey import ECC
from Crypto.Random import random
from Crypto.Cipher import AES


SEPARATOR = "\n"


def is_prime(n):
    if n <= 1:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True


# Diffie-Hellman 파라미터 생성
def generate_dh_params():
    while True:
        p = random.randint(400, 500)  # 400에서 500 사이의 정수 p 생성
        if is_prime(p):  # p가 소수인지 확인
            break
    g = random.randint(2, p - 1)  # 생성자 g 선택 (2 이상 p 미만)
    return p, g


# Diffie-Hellman 공개키 생성
def dh_public_key(p, g, private_key):
    return pow(g, private_key, p)


# 소수성 검사
def is_valid_prime(p):
    return is_prime(p)


# 소인수 분해 함수 (p-1의 소인수 구하기)
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


# g가 p에 대한 원시근인지 확인하는 함수
def is_valid_generator(g, p):
    # p-1의 소인수 목록을 구합니다.
    factors = factorize(p - 1)

    # 모든 소인수 q에 대해 g^((p-1)/q) % p != 1 확인
    for q in factors:
        if pow(g, (p - 1) // q, p) == 1:
            return False  # 원시근이 아님
    return True  # 원시근임


# AES 암호화
def encrypt(key, msg):
    pad = 16 - len(msg) % 16
    msg = msg + chr(pad) * pad
    aes = AES.new(key, AES.MODE_ECB)
    return aes.encrypt(msg.encode())


# AES 복호화
def decrypt(key, encrypted):
    aes = AES.new(key, AES.MODE_ECB)
    return aes.decrypt(encrypted)


# 초기 메시지 전송 (opcode 0)
def send_initial_message(conn):
    init_smsg = {"opcode": 0, "type": "DH"}
    init_sjs = json.dumps(init_smsg) + SEPARATOR
    conn.send(init_sjs.encode("ascii"))
    logging.info("[*] Sent initial message: {}".format(init_smsg))


# 메시지를 한 번에 수신하는 함수
def recv_message(conn):
    try:
        # 1024 바이트씩 수신하여 한 번에 받습니다.
        data = conn.recv(1024)
        if not data:
            logging.error("No data received, connection may be closed")
            return None  # 데이터를 받지 못하면 None을 반환
        return json.loads(data.decode())
    except json.JSONDecodeError:
        logging.error("Failed to decode JSON data")
        return None
    except Exception as e:
        logging.error(f"Error receiving data: {e}")
        return None


def run(addr, port):
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((addr, port))
    logging.info("Alice is connected to {}:{}".format(addr, port))  # 앨리스가client

    send_initial_message(conn)

    # 2. 밥로부터 DH 파라미터 수신받음
    rmsg = recv_message(conn)
    if "error" in rmsg:
        logging.info("[*] Received BoB's invalid error agrs: {}".format(rmsg))
        conn.close()
    else:
        logging.info("[*] Received Bob's DH parameters and public key: {}".format(rmsg))
        # dh_params = json.loads(rmsg)

        p = rmsg["parameter"]["p"]
        g = rmsg["parameter"]["g"]
        bob_public_key = rmsg["public"]

        # 2. 소수성 검사 및 생성자 검증
        if not is_valid_prime(p):
            smsg = {"opcode": 3, "error": "incorrect prime number"}
            sjs = json.dumps(smsg) + SEPARATOR
            conn.send(sjs.encode("ascii"))
            logging.error("[*] Received invalid prime number: {}".format(sjs))
            conn.close()
            return

        if not is_valid_generator(g, p):
            smsg = {"opcode": 3, "error": "incorrect generator"}
            sjs = json.dumps(smsg) + SEPARATOR
            conn.send(sjs.encode("ascii"))
            logging.error("[*] Received invalid generator: {}".format(sjs))
            conn.close()
            return

        # 3. 앨리스의 비밀키 및 공개키 생성
        alice_private_key = random.randint(2, p - 1)
        alice_public_key = dh_public_key(p, g, alice_private_key)

        # 4. 공유 비밀키 계산 (앨리스의 비밀키와 밥의 공개키 사용)
        shared_secret = pow(bob_public_key, alice_private_key, p)

        # ✔️ 5. DH 공유 비밀키를 2바이트로 변환하고, 이를 반복하여 32바이트 AES 키로 생성
        dh_shared_bytes = shared_secret.to_bytes(2, "big")
        aes_key = dh_shared_bytes * 16  # 2바이트를 16번 반복하여 32바이트로 채움

        # 6. Alice publice key bob에게 보냄
        # encrypted = encrypt(aes_key,msg)
        smsg = {
            "opcode": 1,
            "type": "DH",
            "public": alice_public_key,
            # "encryption": base64.b64encode(encrypted).decode("utf-8"),
        }

        sjs = json.dumps(smsg) + SEPARATOR
        conn.send(sjs.encode("ascii"))
        logging.info("[*] Sent Alice's public key: {}".format(sjs))

        # 5. 밥으로부터 암호화된 메시지 수신 및 복호화
        bob_encrypted_msg = base64.b64decode(recv_message(conn)["encryption"])
        decrypted_msg_from_bob = AES.new(aes_key, AES.MODE_ECB).decrypt(
            bob_encrypted_msg
        )
        pad_len = decrypted_msg_from_bob[-1]
        decrypted_msg_from_bob = decrypted_msg_from_bob[:-pad_len]
        logging.info(
            "[*] Decrypted message from Bob: {}".format(
                decrypted_msg_from_bob.decode("utf-8")
            )
        )

        # 6. 사용자 입력(input)으로 메시지 작성 및 암호화 후 전송
        msg_to_bob = input("Enter message to send to Bob: ")

        # 메시지 패딩 (AES는 16바이트 블록 크기를 사용하므로 패딩이 필요함)
        pad_length = 16 - len(msg_to_bob) % 16
        padded_msg = msg_to_bob + chr(pad_length) * pad_length

        # 메시지 암호화
        encrypted_msg_to_bob = AES.new(aes_key, AES.MODE_ECB).encrypt(
            padded_msg.encode()
        )

        # Base64 인코딩
        encrypted_msg_to_bob_b64 = base64.b64encode(encrypted_msg_to_bob).decode(
            "utf-8"
        )

        # JSON으로 직렬화하여 전송
        conn.send(
            (json.dumps({"encryption": encrypted_msg_to_bob_b64}) + SEPARATOR).encode()
        )
        logging.info("[*] Sent encrypted message to Bob")

        conn.close()


def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-a",
        "--addr",
        metavar="<bob's address>",
        help="Bob's address",
        type=str,
        required=True,
    )
    parser.add_argument(
        "-p",
        "--port",
        metavar="<bob's port>",
        help="Bob's port",
        type=int,
        required=True,
    )
    parser.add_argument(
        "-l", "--log", metavar="<log level>", help="Log level", type=str, default="INFO"
    )
    args = parser.parse_args()
    return args


def main():
    args = command_line_args()
    log_level = args.log
    logging.basicConfig(level=log_level)
    run(args.addr, args.port)


if __name__ == "__main__":
    main()

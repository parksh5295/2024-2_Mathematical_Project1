import socket
import threading
import argparse
import logging
import json
import base64
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


# Diffie-Hellman 파라미터 생성
def generate_dh_params():
    while True:
        p = random.randint(400, 500)  # 400에서 500 사이의 정수 p 생성
        if is_prime(p):  # p가 소수인지 확인
            break
    while True:
        g = random.randint(2, p - 1)  # 생성자 g 선택 (2 이상 p 미만)
        if is_valid_generator(g, p):
            break
    return p, g


def generate_dh_params_wrong_p():
    while True:
        p = random.randint(400, 500)  # 400에서 500 사이의 정수 p 생성
        if not is_prime(p):  # p가 소수인지 확인
            break
    while True:
        g = random.randint(2, p - 1)  # 생성자 g 선택 (2 이상 p 미만)
        if is_valid_generator(g, p):
            break
    return p, g


def generate_dh_params_wrong_g():
    while True:
        p = random.randint(400, 500)  # 400에서 500 사이의 정수 p 생성
        if is_prime(p):  # p가 소수인지 확인
            break
    while True:
        g = random.randint(2, p - 1)  # 생성자 g 선택 (2 이상 p 미만)
        if not is_valid_generator(g, p):
            break
    return p, g


# Diffie-Hellman 공개키 생성
def dh_public_key(p, g, private_key):
    return pow(g, private_key, p)


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


# 메시지를 구분자까지 수신하는 함수
def recv_all(conn):
    data = b""
    while True:
        try:
            chunk = conn.recv(1024)
            if not chunk:  # If no data is received, connection may be closed
                break
            data += chunk
            if SEPARATOR.encode() in data:
                break
        except Exception as e:
            logging.error(f"Error receiving data: {e}")
            return None  # Return None if data reception fails
    try:
        return json.loads(data.decode().rstrip(SEPARATOR))
    except json.JSONDecodeError:
        logging.error("Failed to decode JSON data")
        return data.decode().rstrip(SEPARATOR)


def handler(conn, error, msg):

    # 1. 초기 메시지 수신 (opcode 0)
    rmsg = recv_all(conn)
    logging.info("[*] Received initial message: {}".format(rmsg))

    if rmsg["opcode"] != 0 or rmsg["type"] != "DH":
        logging.error("Invalid initial message")
        conn.close()
        return

    # 1. 밥의 Diffie-Hellman 파라미터 생성
    if error == "p":
        p, g = generate_dh_params_wrong_p()
    elif error == "g":
        p, g = generate_dh_params_wrong_g()
    elif error == "None":
        p, g = generate_dh_params()
    else:
        smsg = {"opcode": 3, "error": "incorrect error args", "error args": error}
        sjs = json.dumps(smsg) + SEPARATOR
        conn.send(sjs.encode("ascii"))
        logging.info("[*] Received invalid error args: {}".format(smsg))
        conn.close()

    try:
        bob_private_key = random.randint(2, p - 1)  # 밥의 비밀키
        bob_public_key = dh_public_key(p, g, bob_private_key)

        # 2. 밥의 DH 파라미터 및 공개키를 앨리스에게 전송
        smsg = {
            "opcode": 1,
            "type": "DH",
            "public": bob_public_key,
            "parameter": {"p": p, "g": g},
        }
        sjs = json.dumps(smsg) + SEPARATOR
        conn.send(sjs.encode("ascii"))
        logging.info("[*] Sent Bob's DH parameters and public key: {}".format(sjs))

        # p or g가 잘못설정되었음을 앨리스로부터 받음
        if error == "p":
            logging.info(
                "[*] Received Alice's invalid prime number message: {}".format(
                    recv_all(conn)
                )
            )
            conn.close()
        if error == "g":
            logging.info("[*] Received invalid generator: {}".format(recv_all(conn)))
            conn.close()
        if error == "None":
            pass

        # 3. 앨리스의 공개키 수신받음

        rbytes = conn.recv(1024)
        rmsg = json.loads(rbytes.decode("ascii").rstrip(SEPARATOR))
        logging.info("[*] Received Alice's public key: {}".format(rmsg))

        # 4. 앨리스의 DH 공개키 추출
        alice_public_key = rmsg["public"]

        # 5. 공유 비밀키 계산 (밥의 비밀키와 앨리스의 공개키 사용)
        shared_secret = pow(alice_public_key, bob_private_key, p)

        # ✔️ 공유 비밀키를 2바이트로 변환하고 32바이트 AES 키로 확장
        dh_shared_bytes = shared_secret.to_bytes(2, "big")
        aes_key = dh_shared_bytes * 16  # 2바이트를 16번 반복하여 32바이트로 채움

        # 6. Bob의 메시지 encryption
        encrypted = encrypt(aes_key, msg)
        smsg = {
            "opcode": 2,
            "type": "AES",
            "encryption": base64.b64encode(encrypted).decode("utf-8"),
        }

        sjs = json.dumps(smsg) + SEPARATOR
        conn.send(sjs.encode("ascii"))
        logging.info("[*] Sent Bob's encryption: {}".format(sjs))

        # 5. 앨리스로부터 암호화된 메시지 수신 및 복호화
        alice_encrypted_msg_b64 = recv_all(conn)["encryption"]

        # Base64 디코딩
        alice_encrypted_msg = base64.b64decode(alice_encrypted_msg_b64)

        # AES 복호화
        decrypted_msg_from_alice = AES.new(aes_key, AES.MODE_ECB).decrypt(
            alice_encrypted_msg
        )

        # 패딩 길이 가져오기 및 제거
        pad_len = decrypted_msg_from_alice[-1]
        decrypted_msg_from_alice = decrypted_msg_from_alice[:-pad_len]

        logging.info(
            "[*] Decrypted message from Alice: {}".format(
                decrypted_msg_from_alice.decode("utf-8")
            )
        )

        conn.close()
    except:
        pass


def run(addr, port, error, msg):
    bob = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bob.bind((addr, port))

    bob.listen(10)
    logging.info("[*] Bob is listening on {}:{}".format(addr, port))

    while True:
        conn, info = bob.accept()
        logging.info("[*] Bob accepts connection from {}:{}".format(info[0], info[1]))
        # 스레드를 사용하여 연결을 처리
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
        metavar="<log level>",
        help="p or g or None",
        type=str,
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
    run(args.addr, args.port, args.error, args.message)


if __name__ == "__main__":
    main()

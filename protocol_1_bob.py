import socket
import threading
import argparse
import logging
import json
import random

def is_prime(n):
    if n <= 1:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True

def generate_random_prime(lower=400, upper=500):
    while True:
        num = random.randint(lower, upper)
        if is_prime(num):
            return num
        
def is_relative_prime(a: int, b: int):
    '''RSA: checks whether [a] and [b] are relatively prime to each other
    returns True when [a] and [b] are relative prime, else return False
    requires function [is_prime]'''
    
    if a <= 0 or b <= 0:
        print('Issue from [is_relative_prime] function: more than one value is not positive')
        return False

    high = max(a, b)
    low = min(a, b)
    
    if low == 1 or high == low:
        return True
    
    for i in range(2, low + 1):
        if is_prime(i):
            if low % i == 0 and high % i == 0:
                return False
            
    return True

def generate_relative_prime(subject: int, min: int, max: int) -> int:
    '''RSA: returns relative prime to [subject] which is above [min], below [max]
    requries function [is_relative_prime]'''
    relprimewannabe = random.randint(min, max)
    while(not is_relative_prime(subject, relprimewannabe)):
        relprimewannabe = random.randint(min, max)
    return relprimewannabe

def phin_from(p: int, q: int) -> int:
    '''RSA: calculates Φ(n) = ([p] - 1)([q] - 1)
    checks whether [p] and [q] are prime before calculating, therefore requiring function [is_prime]'''
    if not is_prime(p) or not is_prime(q):
        print("Issue from [phin_from] function: more than one value is not prime")
        return -1
    return (p-1)*(q-1)

def d_from(e: int, phin: int):
    '''RSA: calculates inverse of [e] in modular of [phin]
    checks whether [e] and [phin] are relative prime before calculating, therefore requiring function [is_relative_prime]'''
    if not is_relative_prime(e, phin):
        print("Issue from [d_from] function: e and phin are not relative prime")
        return -1
    for i in range(1, phin + 1): # planed to optimize this part with EEA, but cancelled
        if e * i % phin == 1:
            return i
    return -2 #this should never happen

def rsa_encryption(message, e, n):
    '''RSA: encrypts given [message] with using public key pair ([e], [n])'''
    if message > n:
        print("Issue from [rsa_encryption] function: message is too long to encrypt")
        return -1
    return message**e % n

def rsa_decryption(encyrpted_message, d, n):
    '''RSA: decrypes given [encyrpted_message] with using private key pair ([d], [n])'''
    return encyrpted_message**d % n

def validate_rsa_keypair(d: int, e: int, pien: int) -> bool:
    '''RSA: validates whether public key [d], private key [e], and Φ(n) [pien]'''
    return d*e % pien == 1

prime_p = generate_random_prime()
prime_q = generate_random_prime()
public_e = generate_relative_prime(phin_from(prime_p, prime_q), min = 2, max = phin_from(prime_p, prime_q))
private_d = d_from(public_e, phin_from(prime_p, prime_q))

def handler(sock):
    try:       
        data = sock.recv(1024).decode('utf-8')
        logging.info("Received message: {}".format(data))
        message = json.loads(data)
       
        if message == {"opcode":0, "type": "RSAKey"}:          
                    
            response = {
                "opcode":0,
                "type": "RSAKey",
                "private": private_d, #17279
                "public": public_e, #204335                
                "parameter": {"p":prime_p, "q":prime_q}} #350, 487
            
            response_json = json.dumps(response)
            sock.sendall(response_json.encode('utf-8'))
            logging.info("Sent response: {}".format(response_json))
        else:
            logging.warning("Invalid message received.")

    except Exception as e:
        logging.error("Error in handler: {}".format(e))
    finally:
        sock.close()

def run(addr, port):
    bob = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bob.bind((addr, port))

    bob.listen(10)
    logging.info("[*] Bob is listening on {}:{}".format(addr, port))

    while True:
        conn, info = bob.accept()

        logging.info("[*] Bob accepts the connection from {}:{}".format(info[0], info[1]))

        conn_handle = threading.Thread(target=handler, args=(conn,))
        conn_handle.start()

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", metavar="<bob's IP address>", help="Bob's IP address", type=str, default="0.0.0.0")
    parser.add_argument("-p", "--port", metavar="<bob's open port>", help="Bob's port", type=int, required=True)
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    log_level = args.log
    logging.basicConfig(level=log_level)

    run(args.addr, args.port)

if __name__ == "__main__":
    main()

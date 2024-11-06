import socket
import argparse
import logging
import json


def int_to_bin(num):
    return list(bin(num))[2:]

def exp(a, b, n):
    c = 0
    f = 1
    bin_b = int_to_bin(b)
    k = len(bin_b)
    for i in range(k):
        c = 2 * c
        f = f * f % n
        if bin_b[i] == '1':
            c = c + 1
            f = f * a % n
    return f

def test(a, n):
    bits = int_to_bin(n-1)
    k = len(bits) - 1
    t = 0

    while bits[k] == '0':
        t += 1
        k -= 1

    u = (n-1) >> t
    x = exp(a, u, n)
    for _ in range(t):
        _x = x
        x = (_x * _x) % n
        if x == 1 and _x != 1 and _x != n-1:
            return True

    if x != 1:
        return True
    else:
        return False
    

def run(addr, port):
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        conn.connect((addr, port))
        logging.info("Alice is connected to {}:{}".format(addr, port))
        
        message = {"opcode":0, "type": "RSAKey"}
        conn.sendall(json.dumps(message).encode('utf-8'))
        logging.info("Sent message: {}".format(message))
        
        response = conn.recv(4096)  
        logging.info("Received response: {}".format(response.decode('utf-8')))

        response_data = json.loads(response.decode('utf-8'))
        
        p = response_data['parameter']['p']
        q = response_data['parameter']['q']

        if test(2, p):
            logging.info("p is composite.")
        else:
            logging.info("p is likely prime.")

        if test(2, q):
            logging.info("q is composite.")
        else:
            logging.info("q is likely prime.")

        conn.close()

    except (socket.error, Exception) as e:
        logging.error("Error occurred: {}".format(e))
    finally:
        conn.close()
        logging.info("Connection closed")

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", metavar="<bob's address>", help="Bob's address", type=str, required=True)
    parser.add_argument("-p", "--port", metavar="<bob's port>", help="Bob's port", type=int, required=True)
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

import socket
import hashlib
import time
import random
import json
import os
from threading import Thread, Lock

# Configuration
address = '1MnSQzCXBiCsC7p6R5GW8jyTcNFw6fMcNR.python'
num_hashes = 100000000
host = 'solo.ckpool.org'
port = 3333
num_threads = 4  # Number of threads for mining

print_lock = Lock()

def double_sha256(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def connect_pool(sock, host, port, address):
    sock.connect((host, port))
    request = json.dumps({"id": 1, "method": "mining.subscribe", "params": []}) + "\n"
    sock.sendall(request.encode())
    response = sock.recv(1024).decode()
    response = json.loads(response.split("\n")[0])
    sub_details, extranonce1, extranonce2_size = response['result']
    request = json.dumps({"params": [address, "password"], "id": 2, "method": "mining.authorize"}) + "\n"
    sock.sendall(request.encode())
    response = ''
    while response.count('\n') < 4 and 'mining.notify' not in response:
        response += sock.recv(1024).decode()
    response = sorted(response.split("\n"), key=len, reverse=True)
    response = json.loads(response[0])
    job_id, prevhash, coinb1, coinb2, merkle_branch, version, nbits, ntime, clean_jobs = response['params']
    return job_id, prevhash, coinb1, coinb2, merkle_branch, version, nbits, ntime, clean_jobs, extranonce1

def markle_root(coinb1, extranonce1, extranonce2, coinb2, merkle_branch):
    coinbase = coinb1 + extranonce1 + extranonce2 + coinb2
    coinbase_hash_bin = double_sha256(bytes.fromhex(coinbase))
    merkle_root = coinbase_hash_bin
    for h in merkle_branch:
        merkle_root = double_sha256(merkle_root + bytes.fromhex(h))
    return merkle_root.hex()

def block_to_hash(version, previousblock, merkleroot, time, bits, nonce):
    def reverse_hex(hex_str):
        return ''.join(reversed([hex_str[i:i+2] for i in range(0, len(hex_str), 2)]))
    version = reverse_hex(version)
    previousblock = reverse_hex(previousblock)
    merkleroot = reverse_hex(merkleroot)
    time = reverse_hex(f'{time:08x}')
    bits = reverse_hex(bits)
    nonce = reverse_hex(f'{nonce:08x}')
    blockheader = version + previousblock + merkleroot + time + bits + nonce
    hash1 = hashlib.sha256(bytes.fromhex(blockheader)).digest()
    hash2 = hashlib.sha256(hash1).digest()
    blockhash = hash2.hex()
    return ''.join(reversed([blockhash[i:i+2] for i in range(0, len(blockhash), 2)]))

def bitstotarget(bits):
    exponent = int(bits[:2], 16)
    coefficient = bits[2:8]
    target = coefficient.ljust(exponent * 2, '0').rjust(64, '0')
    return target

def flush_output():
    print(" " * 4096, flush=True)

def hex_to_ascii(hex_str):
    bytes_obj = bytes.fromhex(hex_str)
    ascii_str = bytes_obj.decode('ascii', errors='replace')
    return ascii_str

def mine_thread(job_details, thread_id, num_hashes, target, sock):
    job_id, prevhash, coinb1, coinb2, merkle_branch, version, nbits, ntime, clean_jobs, extranonce1 = job_details
    extranonce2 = ''.join(random.choices('0123456789abcdef', k=8))
    merkle_root = markle_root(coinb1, extranonce1, extranonce2, coinb2, merkle_branch)
    previousblock = ''.join(reversed([prevhash[i:i+8] for i in range(0, len(prevhash), 8)]))
    time_hex = int(ntime, 16)
    nonce = 0

    coinb2_ascii = hex_to_ascii(coinb2)

    with print_lock:
        print(f"\nVersion: {version}")
        print(f"Coinb1: {coinb1}")
        print(f"Coinb2: {coinb2}")
        print(f"Coinb2 (ASCII): {coinb2_ascii}")
        print(f"Previous Hash: {previousblock} [current block]")
        print(f"Merkle Root: {merkle_root}")
        print(f"----------------------------")
        print(f"Merkle branch: {merkle_branch}")
        print(f"----------------------------")
        print(f"Time: {time_hex}")
        print(f"Bits: {nbits}")
        print(f"Nonce: {nonce}")
        print(f"ExtraNonce: {extranonce2}")
        print(f"Job ID: {job_id}")
        print(f"Target: {target}\n")

    start_time = time.time()
    last_exec_time = start_time
    inp = 0

    for in_ in range(num_hashes):
        nonce = random.randint(0, 2**32 - 1)
        hash_ = block_to_hash(version, previousblock, merkle_root, time_hex, nbits, nonce)

        if hash_.startswith('00000'):
            noncer = ''.join(reversed([f'{nonce:08x}'[i:i+2] for i in range(0, 8, 2)]))
            with print_lock:
                print(f"\nThread {thread_id} - Hash: {hash_}")
                print(f"Nonce (decimal): {nonce}")
                print(f"Nonce (reversed hex): {noncer}", flush=True)

        if hash_ < target:
            with print_lock:
                print("\n\n\nBLOCK SOLVED!!!")
                print(f"Thread {thread_id} - Block hash: {hash_}\n\n\n", flush=True)
                nonce_hex = f'{nonce:08x}'
                payload = json.dumps({"params": [address, job_id, extranonce2, ntime, nonce_hex], "id": 1, "method": "mining.submit"}) + "\n"
                print(f"\n\nThread {thread_id} - Payload: {payload}", flush=True)
                sock.sendall(payload.encode())
                ret = sock.recv(1024).decode()
                print(f"\n\nThread {thread_id} - Pool response: {ret}", flush=True)
            break

        if time.time() - last_exec_time >= 50:
            try:
                with print_lock:
                    print(f"Thread {thread_id} - Waiting for pool response...")
                if os.path.exists("h.txt"):
                    response = sock.recv(7400).decode()
                    response_lines = sorted(response.split("\n"), key=len, reverse=True)
                    cphash = json.loads(response_lines[0]).get('params', [None, ''])[1]
                    if prevhash != cphash:
                        prevhash = cphash
                        sock.close()
                        with print_lock:
                            print(f"\n\nThread {thread_id} - New block detected on network.\n\n", flush=True)
                        break
                else:
                    with print_lock:
                        print(f"\n\n\nThread {thread_id} - Mining Stopped! (h.txt file not found)", flush=True)
                    exit()
            except Exception as e:
                with print_lock:
                    print(f"Thread {thread_id} - Error no pool response or no h.txt file detected: {e}", flush=True)

            end_time = time.time()
            elapsed_time = end_time - last_exec_time
            hash_rate = (in_ - inp) / elapsed_time
            with print_lock:
                print(f"Thread {thread_id} - Hash rate: {round(hash_rate):,} hashes per second.", flush=True)
            flush_output()
            inp = in_
            last_exec_time = time.time()

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    job_details = connect_pool(sock, host, port, address)

    extranonce2 = ''.join(random.choices('0123456789abcdef', k=8))
    merkle_root = markle_root(job_details[2], job_details[9], extranonce2, job_details[3], job_details[4])
    previousblock = ''.join(reversed([job_details[1][i:i+8] for i in range(0, len(job_details[1]), 8)]))
    time_hex = int(job_details[7], 16)
    target = bitstotarget(job_details[6])

    threads = []

    for thread_id in range(num_threads):
        t = Thread(target=mine_thread, args=(job_details, thread_id, num_hashes, target, sock))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

if __name__ == "__main__":
    main()

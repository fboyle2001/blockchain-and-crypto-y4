import hashlib
import time
import multiprocessing
import copy
import sys

def basic_miner_runnable(malleable: str, difficulty: int):
    target = "0" * difficulty
    nonce = 0
    start_time = time.time()

    while True:
        header_str = malleable + nonce.__str__() + "}"
        header_hash = hashlib.sha256(hashlib.sha256(header_str.encode()).digest()).hexdigest()

        if nonce != 0 and nonce % 100000 == 0:
            sys.stdout.write(f"\rNonce: {nonce}. hashes/second: {nonce / (time.time() - start_time)} hashes/s.\n")

        if header_hash.startswith(target):
            return nonce

        nonce += 1

def hash_updating_miner_runnable(malleable: str, difficulty: int):
    target = "0" * difficulty
    nonce = 0
    start_time = time.time()

    prehashed = hashlib.sha256(malleable.encode())

    while True:
        header_hash = prehashed.copy()
        nonce_str = nonce.__str__() + "}"

        header_hash.update(nonce_str.encode())
        header_hash_digest = hashlib.sha256(header_hash.digest()).digest()

        if nonce != 0 and nonce % 100000 == 0:
            print(f"\rNonce: {nonce}, hashes/second: {nonce / (time.time() - start_time)} hashes/s")

        if header_hash_digest[0] == 0x00:
            header_hash_hex = header_hash_digest.hex()
            if header_hash_hex.startswith(target):
                return nonce

        nonce += 1

if __name__ == "__main__":
    malleable = '{"merkle_root": "2aecf36fa79bbbc04dfabbe839753fb8f44e66e6b3b5344c70bdc2c87eaf25da", "previous_block_hash": "050d3220e978ef969e9379d8421a4f2d31134c48de8dbb3e6dda9a98c4550cf4", "timestamp": 1672143935.188773, "n_tx": 5, "difficulty": 1, "nonce":'
    difficulty = 5

    runnables = [hash_updating_miner_runnable]
    processes = []
    results = []

    for runnable in runnables:
        start_time = time.time()

        solution_nonce = runnable(copy.deepcopy(malleable), difficulty)

        end_time = time.time()
        delta_time = end_time - start_time

        print(f"Nonce: {solution_nonce} took {delta_time}s to find")

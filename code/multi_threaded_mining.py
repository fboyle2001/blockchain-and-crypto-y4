import multiprocessing
import hashlib
import time
from blockchain import Block, Blockchain, BlockchainIdentity
import sys

def func(idx):
    st = time.time()

    for i in range(10000000):
        s = str(idx) + ":" + str(i)
        hashlib.sha256(s.encode())

    dt = time.time() - st
    print(f"Process {idx} took {dt}s to complete: hash rate is {10000000 / dt}")

def hash_updating_miner_runnable(idx: int, malleable: str, shared_difficulty, q, priv_queue):
    known_diff = shared_difficulty.value
    target = "0" * known_diff
    nonce = 0
    start_time = time.time()
    int_goal = 16 ** (64 - shared_difficulty.value) - 1

    prehashed = hashlib.sha256((str(idx) + malleable).encode())

    while True:
        header_hash = prehashed.copy()
        nonce_str = nonce.__str__() + "}"

        header_hash.update(nonce_str.encode())
        header_hash_digest = hashlib.sha256(header_hash.digest()).digest()
        value = int.from_bytes(header_hash_digest[::-1], "little")

        if nonce != 0 and nonce % 100000 == 0:
            if priv_queue.full():
                priv_queue.get()
            hash_rate = nonce / (time.time() - start_time)
            priv_queue.put(hash_rate)
            print(f"{idx}: Nonce: {nonce}, hashes/second: {hash_rate} hashes/s")

            if known_diff != shared_difficulty.value:
                print(f"{idx}: Changing difficulty to {shared_difficulty.value}")
                known_diff = shared_difficulty.value
                target = "0" * known_diff

        # if header_hash_digest[0] == 0x00:
        #     header_hash_hex = header_hash_digest.hex()
        #     if header_hash_hex.startswith(target):
        #         print(f"{idx}: Found sol as {nonce} for difficulty {known_diff}")
        #         print(f"Hashes/second: {nonce / (time.time() - start_time)} hashes/s")
        #         print(f"As int: L: {hex(int.from_bytes(header_hash_digest[::-1], 'little'))} B: {hex(int.from_bytes(header_hash_digest[::-1], 'big'))}")

        #         print(value, int_goal, value < int_goal)

        #         known_diff += 1
        #         shared_difficulty.value = known_diff
        #         target = "0" * known_diff
        #         q.put(1)
        
        if value < int_goal:
            print(f"{idx}: Found sol as {nonce} for difficulty {known_diff}")
            print(f"Hashes/second: {nonce / (time.time() - start_time)} hashes/s")
            print(f"As int: L: {hex(int.from_bytes(header_hash_digest[::-1], 'little'))} B: {hex(int.from_bytes(header_hash_digest[::-1], 'big'))}")
            known_diff += 1
            shared_difficulty.value = known_diff
            target = "0" * known_diff
            q.put(1)

        nonce += 1

if __name__ == "__main__":
    count = 8
    difficulty = 3

    chain = Blockchain(1)
    idens = [
        BlockchainIdentity("1J5txDKRWLtHCc4ppFKYLEkWicAy5PtZ6S", "Kwc4dJTvEeFMMg3fHwuE1ZujDPckztiFGKespwoPKN3qx2wm8wFT"),
        BlockchainIdentity("1GTpnkyNdR8foqbdfgv8JkWxMgvDNRGxHV", "KyYAA6BXCkW1H2ZxL9UgpdsL7Y8RZNRmr25xGirR7YbqHsXCPgL1"),
        BlockchainIdentity("1Gq7q7CjhFLLJVsFKV72rbNJQNZ3TCtXd2", "L1ABw5f7tbAmxaL2vzKF8qMwPFEJszkLYJzLyxekccJjJrmQ4La9"),
        BlockchainIdentity("19mGEKM611fHFnztN8BmVRRjyhSAfGf4aP", "L4Mv6qu6kguwpf8WyMpoifgqYt6BsDiD1esYQqfVLszfaSeYSJt9"),
        BlockchainIdentity("1K81wn79X6r495N2PcEMDdujAcxKF5JVYT", "L1K5kYNinu19PQhh2bGm31nJs6ahz5HCsD4HSiMzxTiRyG7LrEDD"),

        BlockchainIdentity("1G6zJsQy7WxpySxjovkidSb8aaZsMaTqaC", "KyMgXMMeMPvDtbpEcC4qxZ4e9NMFcCCYB1HwUkj3mXZJXzYuoLBE"),
        BlockchainIdentity("13jHFqxxn3MnXAR1Drv5DgG24ZvQwbXtxt", "KxPGZWDRJhFg676SRfKAA2EzqiLXUDrzRz3F8HYzMzn62sAv8k4X"),

        BlockchainIdentity("1MRHcvxBaqiiAVYCGG8F2Dom4xoRnutLGZ", "KzGwaUyL3wTm7DrhVSNBLZgYczAH8R5kX6yicycN4B6zcaGbQLKK"),
        BlockchainIdentity("1LBQ8jjfnpAJ6tck9pcMf2QMbEhL5nqVqR", "KycvKsfWXbAkY3GGjxYyFPakEu3V7FFa3NFWnHg7xF9SwVLzbxyK"),
        BlockchainIdentity("1682GahbBriPZdGQ4DYgU29TV3Ff6zvTgr", "L5mkSj2rKhpnbEGKAxLfzRRaML7vXqpj87s6A6XeZnksGJhyiVAW"),

        BlockchainIdentity("1C2yiq3HAfBvZhWrGh3cF6MXprACpDDZeq", "Kzvx8dh3XhyfHheW69gya4gK2y6bSn1WjVZX6vurbaszLw1EstV8"),
        BlockchainIdentity("1LAMSiaEdox8ZcPtWdN5dN6CELKf116tkR", "L5YPZCEVrJdEwDqR1NUG6F8HKg6r5nSGMCNGiSvywYZcKgT6We2c"),
        BlockchainIdentity("14g8cTU97W9gWkRzKS3gYuuMja11mKJDQY", "Kzttkaav8BUMo8Evim6GTUvyZZuQeWstX2LodLeqm3GjPbdhvNNK"),
        BlockchainIdentity("1B4daVXZPWW8NMzag6F4uS2L8hcSKivy4A", "KyDccbXQAgtmKuueAW8KMpXsH5K3bsmxrZYgMCQUpQRRCjtWS5Va"),
        BlockchainIdentity("1LW2uNLuRjRW14qg855NHNHudnnu4aPk4Z", "L471B8sYTpvroueVyCCT5dKBZgLxyEUsEnbNHf1LmShSak3kcog2")
    ]
    
    processes = []
    priv_queues = []
    queue = multiprocessing.Queue(maxsize=1)
    shared_difficulty = multiprocessing.Value("i", 6)

    for i in range(count):
        block = chain.create_unmined_block(idens[i], [], difficulty=difficulty)
        priv_queue = multiprocessing.Queue(maxsize=1)
        priv_queues.append(priv_queue)
        p = multiprocessing.Process(target=hash_updating_miner_runnable, args=(i, block.get_malleable_mining_str(), shared_difficulty, queue, priv_queue))
        processes.append(p)

    for process in processes:
        process.start()

    queue.get()
    #queue.get()
    #queue.get()
    # queue.get()

    for process in processes:
        process.terminate()

    hash_rate_sum = sum([private_queue.get() for private_queue in priv_queues])
    avg_hash_rate = hash_rate_sum / count
    print(hash_rate_sum, avg_hash_rate)
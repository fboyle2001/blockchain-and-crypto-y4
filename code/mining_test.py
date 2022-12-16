import hashlib
import time
import random
import string

def generate_random_data(length):
    return ''.join(random.choices(string.ascii_uppercase + string.digits + string.ascii_lowercase, k=length))

def cpu_miner(max_difficulty=11):
    data = generate_random_data(64)
    difficulties = range(1, max_difficulty)

    print("Using string", data, "as the raw data")

    for difficulty in difficulties:
        print("Difficulty", difficulty)
        start_time = time.time()
        counter = 0
        requirement = difficulty * "0"

        while True:
            concat = str(counter) + data
            hashed = hashlib.sha256(concat.encode()).hexdigest()
            
            if hashed[:difficulty] == requirement:
                time_taken = time.time() - start_time 
                print(f"Solved in {time_taken}s")
                print(f"Nonce is {counter}")
                print(f"Hash is {hashed}")
                print()
                break

            counter += 1

def string_check(hashed, req, difficulty):
    return hashed.hexdigest()[:difficulty] == req

def starts_with(hashed, req, difficulty):
    return hashed.hexdigest().startswith(req)

dif_bytes = 0
print(dif_bytes)

def bin_check(hashed, req, difficulty):
    return int.from_bytes(hashed.digest()[:difficulty], byteorder="little") | dif_bytes == 0

def mining_test(check, difficulty=10, hashes=1000000, base_data="ToleyC4YwnEG71XeTWd1VfghZqdV2jM8SyZSmefhMjvY6dbbnX8N0Zrl4Qc0pRkY"):
    requirement = difficulty * "0"
    start_time = time.time()

    for i in range(hashes):
        concat = str(i) + base_data
        hashed = hashlib.sha256(concat.encode())
        matched = check(hashed, requirement, difficulty)

    end_time = time.time()
    return end_time - start_time

if __name__ == "__main__":
    runs = 10
    funcs = [bin_check, starts_with, string_check]


    for func in funcs:
        taken = 0
        print(func.__name__)

        for run in range(runs):
            print(run + 1)
            taken += mining_test(func)

        print("Taken", taken / runs)
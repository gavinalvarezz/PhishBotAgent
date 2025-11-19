import hashlib

def get_file_hash(filename):
    try:
        with open(filename, "rb") as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
            print(f"{filename} SHA-256: {file_hash}")
    except FileNotFoundError:
        print(f"{filename} not found.")

get_file_hash("danger_words.txt")
get_file_hash("safe_words.txt")
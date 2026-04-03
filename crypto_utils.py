import base64
import hashlib
import math
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

SEPARATOR = "::"

# --------------------------------------------------
# HASH
# --------------------------------------------------
def sha256_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

# --------------------------------------------------
# ENTROPY
# --------------------------------------------------
def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1

    entropy = 0.0
    length = len(data)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)

    return entropy

# --------------------------------------------------
# TEXT ENCRYPTION
# --------------------------------------------------
def encrypt_text(plaintext: str):
    key = os.urandom(32)
    iv = os.urandom(16)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))

    original_hash = sha256_hash(plaintext.encode())
    entropy = calculate_entropy(key)

    if entropy >= 4.5:
        strength = "STRONG"
    elif entropy >= 3.5:
        strength = "MEDIUM"
    else:
        strength = "WEAK"

    combined = (
        base64.b64encode(key).decode()
        + SEPARATOR
        + base64.b64encode(iv + ciphertext).decode()
    )

    return combined, key.hex(), original_hash, strength, entropy

# --------------------------------------------------
# TEXT DECRYPTION
# --------------------------------------------------
def decrypt_text(combined: str):
    key_b64, cipher_b64 = combined.split(SEPARATOR)
    key = base64.b64decode(key_b64)
    raw = base64.b64decode(cipher_b64)

    iv = raw[:16]
    ciphertext = raw[16:]

    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

    return plaintext.decode(), sha256_hash(plaintext)

# --------------------------------------------------
# FILE ENCRYPTION
# --------------------------------------------------
def encrypt_file_bytes(data: bytes):
    key = os.urandom(32)
    iv = os.urandom(16)

    file_hash = sha256_hash(data)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))

    combined = (
        base64.b64encode(key).decode()
        + SEPARATOR
        + file_hash
        + SEPARATOR
        + base64.b64encode(iv + ciphertext).decode()
    )

    return combined, key.hex()

# --------------------------------------------------
# FILE DECRYPTION
# --------------------------------------------------
def decrypt_file_bytes(combined: str):
    key_b64, stored_hash, cipher_b64 = combined.split(SEPARATOR)

    key = base64.b64decode(key_b64)
    raw = base64.b64decode(cipher_b64)

    iv = raw[:16]
    ciphertext = raw[16:]

    cipher = AES.new(key, AES.MODE_CBC, iv)
    data = unpad(cipher.decrypt(ciphertext), AES.block_size)

    if sha256_hash(data) != stored_hash:
        raise ValueError("File integrity verification failed")

    return data

# --------------------------------------------------
# FORMAT CHECK
# --------------------------------------------------
def is_combined_format(value: str) -> bool:
    return bool(value and SEPARATOR in value)

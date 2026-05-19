import base64
import os
import random
from Crypto.Cipher import AES


BLOCK_SIZE = 16


# =========================
# Common helpers
# =========================

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def random_aes_key() -> bytes:
    return os.urandom(16)


def chunks(data: bytes, size: int):
    return [data[i:i + size] for i in range(0, len(data), size)]


def aes_ecb_encrypt(plaintext: bytes, key: bytes) -> bytes:
    return AES.new(key, AES.MODE_ECB).encrypt(plaintext)


def aes_ecb_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    return AES.new(key, AES.MODE_ECB).decrypt(ciphertext)


def is_ecb(ciphertext: bytes, block_size: int = 16) -> bool:
    blocks = chunks(ciphertext, block_size)
    return len(blocks) != len(set(blocks))


# =========================
# Challenge 9
# Implement PKCS#7 padding
# =========================

def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len]) * pad_len


# =========================
# Challenge 15
# PKCS#7 padding validation
# =========================

def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    if not data:
        raise ValueError("Invalid PKCS#7 padding: empty input")

    pad_len = data[-1]

    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Invalid PKCS#7 padding length")

    if len(data) < pad_len:
        raise ValueError("Invalid PKCS#7 padding: padding longer than data")

    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid PKCS#7 padding bytes")

    return data[:-pad_len]


# =========================
# Challenge 10
# Implement CBC mode
# =========================

def aes_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    plaintext = pkcs7_pad(plaintext, BLOCK_SIZE)
    prev = iv
    out = b""

    for block in chunks(plaintext, BLOCK_SIZE):
        xored = xor_bytes(block, prev)
        encrypted = aes_ecb_encrypt(xored, key)
        out += encrypted
        prev = encrypted

    return out


def aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes, unpad: bool = True) -> bytes:
    prev = iv
    out = b""

    for block in chunks(ciphertext, BLOCK_SIZE):
        decrypted = aes_ecb_decrypt(block, key)
        plaintext_block = xor_bytes(decrypted, prev)
        out += plaintext_block
        prev = block

    return pkcs7_unpad(out, BLOCK_SIZE) if unpad else out


# =========================
# Challenge 11
# ECB/CBC detection oracle
# =========================

def encryption_oracle(data: bytes):
    key = random_aes_key()
    prefix = os.urandom(random.randint(5, 10))
    suffix = os.urandom(random.randint(5, 10))
    plaintext = prefix + data + suffix
    plaintext = pkcs7_pad(plaintext, BLOCK_SIZE)

    mode = random.choice(["ECB", "CBC"])

    if mode == "ECB":
        ciphertext = aes_ecb_encrypt(plaintext, key)
    else:
        iv = os.urandom(16)
        ciphertext = aes_cbc_encrypt(prefix + data + suffix, key, iv)

    return ciphertext, mode


def detect_ecb_or_cbc(oracle_func) -> str:
    payload = b"A" * 64
    ciphertext, _real_mode = oracle_func(payload)
    return "ECB" if is_ecb(ciphertext, BLOCK_SIZE) else "CBC"


# =========================
# Challenge 12
# Byte-at-a-time ECB decryption Simple
# =========================

UNKNOWN_STRING_B64 = (
    b"Um9sbGluJyBpbiBteSA1LjAK"
    b"V2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwo="
    b"VGhlIGdpcmxpZXMgb24gc3RhbmRieSB3YXZpbmcganVzdCB0byBqdXN0IHNheSBoaQo="
    b"RGlkIHlvdSBzdG9wPyBObywgSSBqdXN0IGRyb3ZlIGJ5Cg=="
)

UNKNOWN_STRING = base64.b64decode(UNKNOWN_STRING_B64)

CH12_KEY = random_aes_key()


def ecb_oracle_simple(user_input: bytes) -> bytes:
    plaintext = user_input + UNKNOWN_STRING
    return aes_ecb_encrypt(pkcs7_pad(plaintext, BLOCK_SIZE), CH12_KEY)


def detect_block_size(oracle_func) -> int:
    base_len = len(oracle_func(b""))

    for i in range(1, 128):
        new_len = len(oracle_func(b"A" * i))
        if new_len > base_len:
            return new_len - base_len

    raise RuntimeError("Could not detect block size")


def byte_at_a_time_ecb_decrypt_simple(oracle_func) -> bytes:
    block_size = detect_block_size(oracle_func)

    if not is_ecb(oracle_func(b"A" * block_size * 4), block_size):
        raise RuntimeError("Oracle is not ECB")

    known = b""
    total_len = len(oracle_func(b""))

    for _ in range(total_len):
        pad_len = block_size - 1 - (len(known) % block_size)
        prefix = b"A" * pad_len

        block_index = len(known) // block_size
        target = oracle_func(prefix)[
            block_index * block_size:(block_index + 1) * block_size
        ]

        dictionary = {}

        for b in range(256):
            attempt = prefix + known + bytes([b])
            encrypted = oracle_func(attempt)
            dictionary[
                encrypted[block_index * block_size:(block_index + 1) * block_size]
            ] = bytes([b])

        if target in dictionary:
            known += dictionary[target]
        else:
            break

    try:
        return pkcs7_unpad(known, block_size)
    except ValueError:
        return known


# =========================
# Challenge 13
# ECB cut-and-paste
# =========================

CH13_KEY = random_aes_key()


def parse_kv(s: str) -> dict:
    result = {}

    for pair in s.split("&"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            result[k] = v

    return result


def profile_for(email: str) -> str:
    email = email.replace("&", "").replace("=", "")
    return f"email={email}&uid=10&role=user"


def encrypt_profile(email: str) -> bytes:
    profile = profile_for(email).encode()
    return aes_ecb_encrypt(pkcs7_pad(profile, BLOCK_SIZE), CH13_KEY)


def decrypt_profile(ciphertext: bytes) -> dict:
    plaintext = aes_ecb_decrypt(ciphertext, CH13_KEY)
    plaintext = pkcs7_unpad(plaintext, BLOCK_SIZE)
    return parse_kv(plaintext.decode(errors="ignore"))


def ecb_cut_and_paste_attack() -> dict:
    admin_block_plain = b"admin" + bytes([11]) * 11

    email_for_admin_block = b"A" * 10 + admin_block_plain
    c1 = encrypt_profile(email_for_admin_block.decode("latin1"))
    admin_block = c1[16:32]

    email_for_role_block = "B" * 13
    c2 = encrypt_profile(email_for_role_block)

    forged = c2[:32] + admin_block

    return decrypt_profile(forged)


# =========================
# Challenge 14
# Byte-at-a-time ECB decryption Harder
# =========================

CH14_KEY = random_aes_key()
CH14_RANDOM_PREFIX = os.urandom(random.randint(1, 64))


def ecb_oracle_harder(user_input: bytes) -> bytes:
    plaintext = CH14_RANDOM_PREFIX + user_input + UNKNOWN_STRING
    return aes_ecb_encrypt(pkcs7_pad(plaintext, BLOCK_SIZE), CH14_KEY)


def find_prefix_alignment(oracle_func, block_size: int):
    marker = b"B" * (block_size * 2)

    for pad_len in range(block_size):
        data = b"A" * pad_len + marker
        ciphertext = oracle_func(data)
        blocks = chunks(ciphertext, block_size)

        for i in range(len(blocks) - 1):
            if blocks[i] == blocks[i + 1]:
                return pad_len, i

    raise RuntimeError("Could not align random prefix")


def byte_at_a_time_ecb_decrypt_harder(oracle_func) -> bytes:
    block_size = detect_block_size(oracle_func)

    if not is_ecb(oracle_func(b"A" * block_size * 8), block_size):
        raise RuntimeError("Oracle is not ECB")

    prefix_pad_len, prefix_blocks = find_prefix_alignment(oracle_func, block_size)

    known = b""
    total_len = len(oracle_func(b""))

    for _ in range(total_len):
        pad_len = block_size - 1 - (len(known) % block_size)
        attack_prefix = b"A" * (prefix_pad_len + pad_len)

        block_index = prefix_blocks + (len(known) // block_size)

        target = oracle_func(attack_prefix)[
            block_index * block_size:(block_index + 1) * block_size
        ]

        dictionary = {}

        for b in range(256):
            attempt = attack_prefix + known + bytes([b])
            encrypted = oracle_func(attempt)
            dictionary[
                encrypted[block_index * block_size:(block_index + 1) * block_size]
            ] = bytes([b])

        if target in dictionary:
            known += dictionary[target]
        else:
            break

    try:
        return pkcs7_unpad(known, block_size)
    except ValueError:
        return known


# =========================
# Challenge 16
# CBC bit flipping attacks
# =========================

CH16_KEY = random_aes_key()
CH16_IV = os.urandom(16)


def sanitize_userdata(data: bytes) -> bytes:
    return data.replace(b";", b"%3B").replace(b"=", b"%3D")


def cbc_bitflip_encrypt(userdata: bytes) -> bytes:
    prefix = b"comment1=cooking%20MCs;userdata="
    suffix = b";comment2=%20like%20a%20pound%20of%20bacon"

    plaintext = prefix + sanitize_userdata(userdata) + suffix
    return aes_cbc_encrypt(plaintext, CH16_KEY, CH16_IV)


def cbc_bitflip_is_admin(ciphertext: bytes) -> bool:
    plaintext = aes_cbc_decrypt(ciphertext, CH16_KEY, CH16_IV, unpad=True)
    return b";admin=true;" in plaintext


def cbc_bitflipping_attack() -> bool:
    attack_input = b"A" * 16
    ciphertext = cbc_bitflip_encrypt(attack_input)

    desired = b";admin=true;AAAA"
    original = b"A" * 16

    prefix_len = len(b"comment1=cooking%20MCs;userdata=")
    target_block_index = prefix_len // BLOCK_SIZE

    mutable = bytearray(ciphertext)

    previous_block_start = (target_block_index - 1) * BLOCK_SIZE

    for i in range(16):
        mutable[previous_block_start + i] ^= original[i] ^ desired[i]

    forged = bytes(mutable)

    return cbc_bitflip_is_admin(forged)


# =========================
# Test runner
# =========================

def main():
    print("========== Challenge 9 ==========")
    padded = pkcs7_pad(b"YELLOW SUBMARINE", 20)
    print(padded)
    assert padded == b"YELLOW SUBMARINE\x04\x04\x04\x04"

    print("\n========== Challenge 10 ==========")
    key = b"YELLOW SUBMARINE"
    iv = b"\x00" * 16
    msg = b"This is a CBC mode test message."
    c = aes_cbc_encrypt(msg, key, iv)
    p = aes_cbc_decrypt(c, key, iv)
    print(p)
    assert p == msg

    print("\n========== Challenge 11 ==========")
    correct = 0
    total = 20
    for _ in range(total):
        ciphertext, real = encryption_oracle(b"A" * 64)
        guess = "ECB" if is_ecb(ciphertext) else "CBC"
        if guess == real:
            correct += 1
    print(f"Detection accuracy: {correct}/{total}")

    print("\n========== Challenge 12 ==========")
    recovered = byte_at_a_time_ecb_decrypt_simple(ecb_oracle_simple)
    print(recovered.decode(errors="replace"))
    assert recovered == UNKNOWN_STRING

    print("\n========== Challenge 13 ==========")
    forged_profile = ecb_cut_and_paste_attack()
    print(forged_profile)
    assert forged_profile.get("role") == "admin"

    print("\n========== Challenge 14 ==========")
    recovered_harder = byte_at_a_time_ecb_decrypt_harder(ecb_oracle_harder)
    print(recovered_harder.decode(errors="replace"))
    assert recovered_harder == UNKNOWN_STRING

    print("\n========== Challenge 15 ==========")
    good = pkcs7_unpad(b"ICE ICE BABY\x04\x04\x04\x04")
    print(good)
    assert good == b"ICE ICE BABY"

    for bad in [
        b"ICE ICE BABY\x05\x05\x05\x05",
        b"ICE ICE BABY\x01\x02\x03\x04",
    ]:
        try:
            pkcs7_unpad(bad)
            raise AssertionError("Invalid padding was accepted")
        except ValueError:
            print(f"Correctly rejected: {bad}")

    print("\n========== Challenge 16 ==========")
    ok = cbc_bitflipping_attack()
    print("Admin forged:", ok)
    assert ok is True

    print("\nAll Set 2 challenges passed.")


if __name__ == "__main__":
    main()
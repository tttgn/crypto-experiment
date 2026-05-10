import base64
import itertools
import sys
from typing import List, Tuple

# 计算两个字节串的汉明距离（不同比特的数量）
def hamming_distance(a: bytes, b: bytes) -> int:
    if len(a) != len(b):
        raise ValueError("长度必须相等")
    return sum((x ^ y).bit_count() for x, y in zip(a, b))

test_a = b"this is a test"
test_b = b"wokka wokka!!!"
assert hamming_distance(test_a, test_b) == 37, "汉明距离计算错误"

# 对字节串进行英文可读性评分
def score_english(text: bytes) -> float:
    # 英文字母和空格的频率表
    freq = {
        b'e': 0.127, b't': 0.091, b'a': 0.082, b'o': 0.075, b'i': 0.070,
        b'n': 0.067, b's': 0.063, b'h': 0.061, b'r': 0.060, b'd': 0.040,
        b'l': 0.040, b'c': 0.028, b'u': 0.028, b'm': 0.024, b'w': 0.024,
        b'f': 0.022, b'g': 0.020, b'y': 0.020, b'p': 0.019, b'b': 0.015,
        b'v': 0.010, b'k': 0.008, b'j': 0.002, b'x': 0.002, b'q': 0.001,
        b'z': 0.001, b' ': 0.192
    }
    score = 0.0
    length = len(text)
    if length == 0:
        return score
    for byte in text.lower():
        ch = bytes([byte])
        if ch in freq:
            score += freq[ch]
        elif 32 <= byte <= 126:
            score += 0.01
        else:
            score -= 0.5
    return score / length

# 破解单字节异或，返回（明文，得分，密钥字节）
def single_byte_xor_crack(ciphertext: bytes) -> Tuple[bytes, float, int]:
    best_key = 0
    best_score = -1e9
    best_plaintext = b''
    for key in range(256):
        plain = bytes([c ^ key for c in ciphertext])
        score = score_english(plain)
        if score > best_score:
            best_score = score
            best_key = key
            best_plaintext = plain
    return best_plaintext, best_score, best_key

# 猜测密钥长度，返回归一化距离最小的几个候选
def guess_keysize(ciphertext: bytes, max_keysize: int = 40, num_blocks: int = 4) -> List[int]:
    distances = []
    for keysize in range(2, max_keysize + 1):
        blocks = []
        for i in range(num_blocks):
            start = i * keysize
            end = start + keysize
            if end > len(ciphertext):
                break
            blocks.append(ciphertext[start:end])
        if len(blocks) < num_blocks:
            continue

        total_dist = 0
        pairs = 0
        for i, j in itertools.combinations(range(len(blocks)), 2):
            total_dist += hamming_distance(blocks[i], blocks[j])
            pairs += 1
        avg_dist = total_dist / pairs / keysize
        distances.append((keysize, avg_dist))

    distances.sort(key=lambda x: x[1])
    return [keysize for keysize, _ in distances[:3]]

# 转置：将每个块的第i个字节拼成新块
def transpose_blocks(ciphertext: bytes, keysize: int) -> List[bytes]:
    num_blocks = len(ciphertext) // keysize
    transposed = []
    for i in range(keysize):
        block = bytearray()
        for j in range(num_blocks):
            block.append(ciphertext[j * keysize + i])
        transposed.append(bytes(block))
    return transposed

# 恢复完整密钥
def recover_key(ciphertext: bytes, keysize: int) -> bytes:
    transposed = transpose_blocks(ciphertext, keysize)
    key_bytes = []
    for block in transposed:
        _, _, key_byte = single_byte_xor_crack(block)
        key_bytes.append(key_byte)
    return bytes(key_bytes)

# 重复密钥异或解密
def repeating_key_xor_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    key_len = len(key)
    decrypted = bytearray()
    for i, c in enumerate(ciphertext):
        decrypted.append(c ^ key[i % key_len])
    return bytes(decrypted)

def main():
    if len(sys.argv) > 1:
        filename = sys.argv[1]
    else:
        filename = "6.txt"

    try:
        with open(filename, "r") as f:
            base64_data = f.read()
    except FileNotFoundError:
        print(f"错误：找不到文件 '{filename}'")
        return

    base64_data = "".join(base64_data.split())
    ciphertext = base64.b64decode(base64_data)

    print("猜测密钥长度...")
    candidates = guess_keysize(ciphertext)
    print(f"候选密钥长度: {candidates}")

    best_plain = None
    best_key = None
    best_score = -1e9
    for keysize in candidates:
        print(f"尝试密钥长度 {keysize}...")
        key = recover_key(ciphertext, keysize)
        plaintext = repeating_key_xor_decrypt(ciphertext, key)
        score = score_english(plaintext)
        print(f"  密钥: {key} (得分 {score:.3f})")
        if score > best_score:
            best_score = score
            best_plain = plaintext
            best_key = key

    print("\n" + "=" * 60)
    print(f"确定密钥长度: {len(best_key)}")
    print(f"密钥: {best_key}")
    print("解密结果:\n")
    try:
        print(best_plain.decode('utf-8'))
    except UnicodeDecodeError:
        print(best_plain)

if __name__ == "__main__":
    main()
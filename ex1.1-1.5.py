import base64
import string
from itertools import cycle

def hex_to_bytes(s):
    return bytes.fromhex(s)

def single_byte_xor(cipher):
    best_score = 0
    best_text = ""
    best_key = 0
    for key in range(256):
        decoded = bytes([c ^ key for c in cipher])
        score = score_text(decoded)
        if score > best_score:
            best_score = score
            best_text = decoded
            best_key = key
    return best_key, best_text

def bytes_to_hex(b):
    return b.hex()

def xor_bytes(b1, b2):
    return bytes([x ^ y for x, y in zip(b1, b2)])

def challenge3():
    cipher = hex_to_bytes("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
    key, text = single_byte_xor(cipher)
    print("密钥是:", key, "明文是：",text.decode(errors="ignore"))


def challenge2():
    a = hex_to_bytes("1c0111001f010100061a024b53535009181c")
    b = hex_to_bytes("686974207468652062756c6c277320657965")
    result = xor_bytes(a, b)
    print("异或结果:", bytes_to_hex(result))

def challenge1():
    hex_str = ("49276d206b696c6c696e6720796f757220627261696e206c696b652061"
               "20706f69736f6e6f7573206d757368726f6f6d")
    raw = hex_to_bytes(hex_str)
    b64 = base64.b64encode(raw)
    print("base64:", b64.decode())

# 英文评分函数（频率分析）
def score_text(text):
    freq = {
        'a': 0.065, 'b': 0.012, 'c': 0.022, 'd': 0.032, 'e': 0.102,
        'f': 0.023, 'g': 0.016, 'h': 0.049, 'i': 0.056, 'j': 0.001,
        'k': 0.006, 'l': 0.033, 'm': 0.020, 'n': 0.057, 'o': 0.062,
        'p': 0.015, 'q': 0.001, 'r': 0.049, 's': 0.053, 't': 0.075,
        'u': 0.023, 'v': 0.008, 'w': 0.017, 'x': 0.001, 'y': 0.014,
        'z': 0.001, ' ': 0.130
    }
    return sum(freq.get(chr(c).lower(), 0) for c in text)


def challenge4():
    with open("4.txt") as f:
        lines = f.readlines()

    best_score = 0
    best_text = ""

    for line in lines:
        cipher = hex_to_bytes(line.strip())
        _, text = single_byte_xor(cipher)
        score = score_text(text)
        if score > best_score:
            best_score = score
            best_text = text

    print("找到的字符串:", best_text.decode(errors="ignore"))

# ---------------- (5) repeating-key XOR ----------------
def repeating_key_xor(text, key):
    return bytes([t ^ k for t, k in zip(text, cycle(key))])

def challenge5():
    text = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    key = b"ICE"
    encrypted = repeating_key_xor(text, key)
    print("第五题加密结果:", encrypted.hex())



# ---------------- 主函数 ----------------
if __name__ == "__main__":
    challenge1()
    challenge2()
    challenge3()
    challenge4()
    challenge5()


from math import gcd
import secrets

def egcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x1, y1 = egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1

def invmod(a, m):
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("逆元不存在")
    return x % m

def is_probable_prime(n, k=20):
    if n < 2:
        return False
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    for p in small_primes:
        if n == p:
            return True
        if n % p == 0:
            return False

    d = n - 1
    r = 0
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False

    return True

def generate_prime(bits):
    while True:
        n = secrets.randbits(bits)
        n |= 1
        n |= (1 << (bits - 1))
        if is_probable_prime(n):
            return n

def generate_rsa_key(bits=512, e=3):
    while True:
        p = generate_prime(bits // 2)
        q = generate_prime(bits // 2)
        if p == q:
            continue

        n = p * q
        et = (p - 1) * (q - 1)

        if gcd(e, et) != 1:
            continue

        d = invmod(e, et)
        return (e, n), (d, n), p, q

def int_to_bytes(x):
    if x == 0:
        return b"\x00"
    return x.to_bytes((x.bit_length() + 7) // 8, "big")

def bytes_to_int(b):
    return int.from_bytes(b, "big")

def encrypt_int(m, public_key):
    e, n = public_key
    if not 0 <= m < n:
        raise ValueError("message must be in range 0 <= m < n")
    return pow(m, e, n)

def decrypt_int(c, private_key):
    d, n = private_key
    return pow(c, d, n)

def encrypt_bytes(msg, public_key):
    m = bytes_to_int(msg)
    return encrypt_int(m, public_key)

def decrypt_bytes(c, private_key):
    m = decrypt_int(c, private_key)
    return int_to_bytes(m)

def main():
    # 小数测试
    p = 61
    q = 53
    e = 17
    n = p * q
    et = (p - 1) * (q - 1)
    d = invmod(e, et)

    print("逆元(17, 3120) =", d)

    pub = (e, n)
    priv = (d, n)

    m = 42
    c = encrypt_int(m, pub)
    recovered = decrypt_int(c, priv)

    print("小模数 RSA:")
    print("m =", m)
    print("c =", c)
    print("恢复明文 =", recovered)

    # Cryptopals 要求 e = 3
    public_key, private_key, p, q = generate_rsa_key(bits=512, e=3)

    msg = b"hello rsa"
    c = encrypt_bytes(msg, public_key)
    recovered = decrypt_bytes(c, private_key)

    print("\n大模数 RSA:")
    print("p =", p)
    print("q =", q)
    print("公钥 =", public_key)
    print("私钥 =", private_key)
    print("密文 =", c)
    print("恢复明文 =", recovered)

if __name__ == "__main__":
    main()
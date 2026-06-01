import math

def count_unconcealed(e, p, q):
    """
    计算 RSA 中某个 e 对应的不被隐藏消息数量：
    (1 + gcd(e - 1, p - 1)) * (1 + gcd(e - 1, q - 1))
    """
    return (1 + math.gcd(e - 1, p - 1)) * (1 + math.gcd(e - 1, q - 1))


def main():
    p = 1009
    q = 3643
    phi = (p - 1) * (q - 1)

    min_count = float("inf")
    total_sum = 0
    best_e_count = 0

    for e in range(2, phi):
        if math.gcd(e, phi) != 1:
            continue

        num = count_unconcealed(e, p, q)

        if num < min_count:
            min_count = num
            total_sum = e
            best_e_count = 1
        elif num == min_count:
            total_sum += e
            best_e_count += 1

    print("phi =", phi)
    print("最少的不被隐藏消息数量 =", min_count)
    print("满足最小数量的 e 的个数 =", best_e_count)
    print(" e 的和 =", total_sum)


if __name__ == "__main__":
    main()
def init_sbox():
    sbox = [0 for _ in range(256)]
    p = 1
    q = 1
    while True:
        # Multiply p by x+1.
        p = p ^ lsh(p, 1, 8) ^ (0x1B if (p & 0x80) else 0)
        # Divide q by x+1.
        q ^= lsh(q, 1, 8)
        q ^= lsh(q, 2, 8)
        q ^= lsh(q, 4, 8)
        q ^= 0x09 if (q & 0x80) else 0
        # Compute the affine transformation.
        sbox[p] = 0x63 ^ q ^ rol(q, 1, 8) ^ rol(q, 2, 8) ^ rol(q, 3, 8) ^ rol(q, 4, 8)

        if p == 1:
            break
    sbox[0] = 0x63
    return sbox


# Rotate bits left. If the most significant bit is 1, the least significant bit will be set to 1.
def rol(x, shift, size):
    if shift < 0 or shift > size:
        raise ValueError("Shift is out of range.")
    if shift < 1:
        return x
    x &= 2**size-1
    return lsh(x, shift, size) | (x >> (size - shift))


# Left bit shift with fall-off.
def lsh(x, shift, size):
    if shift < 0 or shift > size:
        raise ValueError("Shift is out of range.")
    if shift < 1:
        return x
    x <<= shift
    return x & 2**size-1


def main():
    assert rol(0x01, 3, 4) == 8
    assert rol(0x01, 4, 4) == 1

    assert lsh(0x01, 3, 4) == 8
    assert lsh(0x01, 4, 4) == 0

    sbox = init_sbox()
    assert sbox[0] == 0x63
    assert sbox[1] == 0x7C
    assert sbox[255] == 0x16

    print("rijndael_sbox: All tests passed.")


if __name__ == '__main__':
    main()

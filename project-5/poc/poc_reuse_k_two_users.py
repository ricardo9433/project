
# PoC: two different users reuse the same k -> each can recover other's d
from sm2.sm2_sign import keygen, sign
from sm2.sm2_params import n
from sm2.ecc import mod_inv

def recover_d_from_sig_with_k(r, s, k):
    # d ≡ (k - s)/(s + r) mod n
    return ((k - s) * mod_inv((s + r) % n, n)) % n

def main():
    A = keygen(); B = keygen()
    ZA = b"Alice"; ZB = b"Bob"
    M1 = b"Tx A"; M2 = b"Tx B"
    # shared bad nonce
    k = 0xDEADBEEF % n
    r1, s1, _ = sign(A.d, ZA, M1, deterministic=False, k_force=k)
    r2, s2, _ = sign(B.d, ZB, M2, deterministic=False, k_force=k)
    dB = recover_d_from_sig_with_k(r2, s2, k)
    dA = recover_d_from_sig_with_k(r1, s1, k)
    print("A learns dB:", dB == B.d, " | B learns dA:", dA == A.d)

if __name__ == "__main__":
    main()

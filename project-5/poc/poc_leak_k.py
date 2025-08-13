
# PoC: leak k -> recover d
from sm2.sm2_sign import keygen, sign
from sm2.sm2_params import n
from sm2.ecc import G, mul, mod_inv

def recover_d_from_leaked_k(r, s, k):
    # d ≡ (k - s) * (s + r)^-1 mod n
    return ((k - s) * mod_inv((s + r) % n, n)) % n

def main():
    kp = keygen()
    ID = b"Alice"
    M  = b"hello sm2"
    # Use fixed k to simulate leakage
    k = 0x1234567890ABCDEF1234567890ABCDEF12345678 % n
    r, s, e = sign(kp.d, ID, M, deterministic=False, k_force=k)
    d_rec = recover_d_from_leaked_k(r, s, k)
    ok = d_rec == kp.d
    print("leak-k recover d ok:", ok)

if __name__ == "__main__":
    main()


# PoC: same user reuses k twice -> recover d
from sm2.sm2_sign import keygen, sign
from sm2.sm2_params import n
from sm2.ecc import mod_inv

def recover_d_from_two_sigs(r1, s1, r2, s2):
    # d ≡ (s2 - s1) / (s1 - s2 + r1 - r2) mod n
    num = (s2 - s1) % n
    den = (s1 - s2 + r1 - r2) % n
    return (num * mod_inv(den, n)) % n

def main():
    kp = keygen()
    ID = b"Alice"
    M1 = b"msg-1"
    M2 = b"msg-2"
    # force same k
    k = 0x42424242424242424242424242424242 % n
    r1, s1, _ = sign(kp.d, ID, M1, deterministic=False, k_force=k)
    r2, s2, _ = sign(kp.d, ID, M2, deterministic=False, k_force=k)
    d_rec = recover_d_from_two_sigs(r1, s1, r2, s2)
    print("reuse-k same user recover d ok:", d_rec == kp.d)

if __name__ == "__main__":
    main()


# PoC: same (d,k) used for ECDSA and SM2 -> recover d
from sm2.sm2_sign import keygen, sign
from sm2.ecdsa import sign_ecdsa
from sm2.sm2_params import n
from sm2.ecc import mod_inv

def recover_d_cross_alg(r1, s1, e1, r2, s2):
    # From slides: d = (s1*s2 - e1) / (r1 - s1*s2 - s1*r2) mod n
    num = (s1*s2 - e1) % n
    den = (r1 - s1*s2 - s1*r2) % n
    return (num * mod_inv(den, n)) % n

def main():
    kp = keygen()
    M_ecdsa = b"ecdsa-message"
    ID = b"Alice"; M_sm2 = b"sm2-message"
    k = 0x13579BDF2468ACE0FACEB00C % n
    r1, s1, e1 = sign_ecdsa(kp.d, M_ecdsa, k)
    r2, s2, e2 = sign(kp.d, ID, M_sm2, deterministic=False, k_force=k)
    d_rec = recover_d_cross_alg(r1, s1, e1, r2, s2)
    print("same (d,k) across ECDSA/SM2 recover d ok:", d_rec == kp.d)

if __name__ == "__main__":
    main()

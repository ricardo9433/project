
# Educational PoC: recover public key candidates from (r,s,e) if x1=r-e mod n is usable
from sm2.sm2_sign import keygen, sign, verify, recover_pub_from_sig
from sm2.ecc import mul, G
from sm2.sm2_params import n

def main():
    kp = keygen()
    ID = b"demo"
    M  = b"educational"
    # use deterministic k to ensure reproducibility
    r, s, e = sign(kp.d, ID, M, deterministic=True)
    # Recover candidates
    P1, P2 = recover_pub_from_sig(r, s, e)
    # Check which passes verification
    ok1 = verify(P1, ID, M, r, s)
    ok2 = verify(P2, ID, M, r, s)
    print("candidate1 ok?", ok1, " candidate2 ok?", ok2)

if __name__ == "__main__":
    main()

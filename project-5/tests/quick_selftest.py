
from sm2.sm2_sign import keygen, sign, verify
from sm2.sm2_params import n

def main():
    kp = keygen()
    ID = b"Alice"
    for msg in [b"hello", b"world", b"SM2"]:
        r, s, _ = sign(kp.d, ID, msg, deterministic=True)
        assert verify(kp.P, ID, msg, r, s)
    print("SM2 sign/verify deterministic self-test OK")

if __name__ == "__main__":
    main()

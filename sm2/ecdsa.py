
# Tiny ECDSA (for cross-algorithm PoC on SM2 curve)
from __future__ import annotations
from typing import Tuple
from .sm3 import sm3
from .ecc import Point, G, mul, add, mod_inv
from .sm2_params import n

def sign_ecdsa(d: int, m: bytes, k: int) -> Tuple[int,int,int]:
    R = mul(k, G)
    r = R.x % n
    if r == 0: raise ValueError("bad k")
    e = int.from_bytes(sm3(m), 'big')
    s = (mod_inv(k, n) * (e + d*r)) % n
    if s == 0: raise ValueError("bad k")
    return r, s, e

def verify_ecdsa(P: Point, m: bytes, r: int, s: int) -> bool:
    if not (1 <= r < n and 1 <= s < n): return False
    e = int.from_bytes(sm3(m), 'big')
    w = mod_inv(s, n)
    u1 = (e*w) % n
    u2 = (r*w) % n
    X = add(mul(u1, G), mul(u2, P))
    v = X.x % n
    return v == r

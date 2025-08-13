
# SM2 Sign/Verify and utilities
from __future__ import annotations
from dataclasses import dataclass
from typing import Tuple, Optional
from .sm3 import sm3, hmac_sm3
from .ecc import Point, G, mul, add, on_curve, mod_inv, recover_y_from_x
from .sm2_params import p, a, b, Gx, Gy, n

def int2bytes(x: int, length: int) -> bytes:
    return x.to_bytes(length, 'big')

def bytes2int(b: bytes) -> int:
    return int.from_bytes(b, 'big')

def ZA(IDA: bytes, PA: Point) -> bytes:
    entla = (len(IDA)*8).to_bytes(2, 'big')
    data = entla + IDA
    data += int2bytes(a, 32) + int2bytes(b, 32)
    data += int2bytes(Gx, 32) + int2bytes(Gy, 32)
    data += int2bytes(PA.x, 32) + int2bytes(PA.y, 32)
    return sm3(data)

@dataclass
class KeyPair:
    d: int
    P: Point

def keygen(seed: Optional[int]=None) -> KeyPair:
    import secrets
    d = (seed or secrets.randbelow(n-1)+1) % n
    if d == 0: d = 1
    P = mul(d, G)
    return KeyPair(d, P)

def rfc6979_k(d: int, e: int, extra: bytes=b"") -> int:
    # Deterministic nonce using HMAC-SM3. (Minimal; for teaching only)
    x = int2bytes(d, 32) + int2bytes(e, 32) + extra
    K = hmac_sm3(b"\x00"*32, x)
    V = b"\x01"*32
    K = hmac_sm3(K, V + b"\x00" + x)
    V = hmac_sm3(K, V)
    K = hmac_sm3(K, V + b"\x01" + x)
    V = hmac_sm3(K, V)
    while True:
        V = hmac_sm3(K, V)
        k = bytes2int(V) % n
        if 1 <= k < n:
            return k
        K = hmac_sm3(K, V + b"\x00")
        V = hmac_sm3(K, V)

def sign(d: int, IDA: bytes, M: bytes, deterministic: bool=True, k_force: Optional[int]=None) -> Tuple[int,int,int]:
    ZA_ = ZA(IDA, mul(d, G))
    e = bytes2int(sm3(ZA_ + M))
    if k_force is not None:
        k = k_force % n
    elif deterministic:
        k = rfc6979_k(d, e)
    else:
        import secrets
        k = secrets.randbelow(n-1)+1
    x1y1 = mul(k, G)
    r = (e + x1y1.x) % n
    if r == 0 or r + k == n:
        return sign(d, IDA, M, deterministic, k_force)  # retry
    s = (mod_inv(1 + d, n) * (k - r*d)) % n
    if s == 0:
        return sign(d, IDA, M, deterministic, k_force)
    return r, s, e  # return e for PoC convenience

def verify(P: Point, IDA: bytes, M: bytes, r: int, s: int) -> bool:
    if not (1 <= r < n and 1 <= s < n): return False
    ZA_ = ZA(IDA, P)
    e = bytes2int(sm3(ZA_ + M))
    t = (r + s) % n
    if t == 0: return False
    x1y1 = add(mul(s, G), mul(t, P))
    R = (e + x1y1.x) % n
    return R == r

def recover_pub_from_sig(r: int, s: int, e: int) -> Tuple[Point, Point]:
    # Educational: given (r,s,e) and knowing x1 = r-e mod n, compute candidates of P = (s+r)^-1 (kG - sG)
    x1 = (r - e) % n
    # compute y from curve and try both signs
    P1, P2 = recover_y_from_x(x1)
    inv_sr = mod_inv((s + r) % n, n)
    K1 = P1  # kG candidate
    K2 = P2
    Pcand1 = mul(inv_sr, add(K1, mul((-s) % n, G)))
    Pcand2 = mul(inv_sr, add(K2, mul((-s) % n, G)))
    return Pcand1, Pcand2


# Minimal prime-field EC arithmetic for SM2
from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, Tuple
from .sm2_params import p, a, b, Gx, Gy, n

def mod_inv(x: int, m: int) -> int:
    # Extended Euclid (constant-time-ish not guaranteed in Python)
    if x == 0:
        raise ZeroDivisionError("inverse of 0")
    lm, hm = 1, 0
    low, high = x % m, m
    while low > 1:
        r = high // low
        nm, new = hm - lm * r, high - low * r
        lm, low, hm, high = nm, new, lm, low
    return lm % m

def legendre_symbol(a_: int) -> int:
    return pow(a_ % p, (p - 1) // 2, p)

def mod_sqrt(y2: int) -> Optional[int]:
    # Tonelli-Shanks for p % 4 == 3?  Here p % 4 == 3 is False; use general TS.
    a_ = y2 % p
    if a_ == 0:
        return 0
    if legendre_symbol(a_) != 1:
        return None
    # factor p-1 as q*2^s with q odd
    q = p - 1
    s = 0
    while q % 2 == 0:
        s += 1
        q //= 2
    # find z which is quadratic non-residue
    z = 2
    while legendre_symbol(z) != p - 1:
        z += 1
    c = pow(z, q, p)
    x = pow(a_, (q + 1) // 2, p)
    t = pow(a_, q, p)
    m = s
    while t != 1:
        # find least i in [1, m) such that t^(2^i) == 1
        i = 1
        t2i = (t * t) % p
        while i < m and t2i != 1:
            t2i = (t2i * t2i) % p
            i += 1
        b = pow(c, 1 << (m - i - 1), p)
        x = (x * b) % p
        t = (t * b * b) % p
        c = (b * b) % p
        m = i
    return x

@dataclass(frozen=True)
class Point:
    x: Optional[int]
    y: Optional[int]
    def is_inf(self) -> bool:
        return self.x is None or self.y is None

INF = Point(None, None)
G = Point(Gx, Gy)

def on_curve(P: Point) -> bool:
    if P.is_inf(): return True
    return (P.y * P.y - (P.x * P.x * P.x + a * P.x + b)) % p == 0

def negate(P: Point) -> Point:
    if P.is_inf(): return P
    return Point(P.x, (-P.y) % p)

def add(P: Point, Q: Point) -> Point:
    if P.is_inf(): return Q
    if Q.is_inf(): return P
    if P.x == Q.x and (P.y != Q.y or P.y == 0):
        return INF
    if P.x == Q.x:
        # P == Q, point doubling
        l = (3 * P.x * P.x + a) * mod_inv(2 * P.y, p) % p
    else:
        l = (Q.y - P.y) * mod_inv(Q.x - P.x, p) % p
    x3 = (l * l - P.x - Q.x) % p
    y3 = (l * (P.x - x3) - P.y) % p
    R = Point(x3, y3)
    return R

def mul(k: int, P: Point) -> Point:
    k = k % n
    if k == 0 or P.is_inf(): return INF
    R = INF
    Q = P
    while k > 0:
        if k & 1:
            R = add(R, Q)
        Q = add(Q, Q)
        k >>= 1
    return R

def decompress_point(x: int, y_lsb: int) -> Optional[Point]:
    # Recover y from x and its parity (lsb)
    rhs = (pow(x, 3, p) + a * x + b) % p
    y = mod_sqrt(rhs)
    if y is None:
        return None
    if y % 2 != y_lsb % 2:
        y = (-y) % p
    P = Point(x, y)
    return P if on_curve(P) else None

def recover_y_from_x(x: int) -> Tuple[Point, Point]:
    rhs = (pow(x,3,p) + a*x + b) % p
    y = mod_sqrt(rhs)
    if y is None:
        raise ValueError("no square root for given x")
    P1 = Point(x, y)
    P2 = Point(x, (-y) % p)
    return P1, P2


# Pure Python SM3 (minimal, for teaching/PoC; not constant-time)
# Spec: GM/T 0004-2012
from __future__ import annotations
import struct

IV = (
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
)

def _rotl(x, n):
    n &= 31
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

def P0(x): return x ^ _rotl(x, 9) ^ _rotl(x, 17)
def P1(x): return x ^ _rotl(x, 15) ^ _rotl(x, 23)

def T(j): return 0x79CC4519 if j <= 15 else 0x7A879D8A

def _cf(v, b):
    W = [0]*68
    W_ = [0]*64
    for i in range(16):
        W[i] = struct.unpack(">I", b[4*i:4*i+4])[0]
    for i in range(16, 68):
        W[i] = P1(W[i-16] ^ W[i-9] ^ _rotl(W[i-3], 15)) ^ _rotl(W[i-13], 7) ^ W[i-6]
    for i in range(64):
        W_[i] = W[i] ^ W[i+4]
    A,B,C,D,E,F,G,H = v
    for j in range(64):
        if j <= 15:
            FF = A ^ B ^ C
            GG = E ^ F ^ G
        else:
            FF = (A & B) | (A & C) | (B & C)
            GG = (E & F) | ((~E) & G)
        SS1 = _rotl((_rotl(A,12) + E + _rotl(T(j), j)) & 0xFFFFFFFF, 7)
        SS2 = SS1 ^ _rotl(A,12)
        TT1 = (FF + D + SS2 + W_[j]) & 0xFFFFFFFF
        TT2 = (GG + H + SS1 + W[j]) & 0xFFFFFFFF
        D = C
        C = _rotl(B,9)
        B = A
        A = TT1
        H = G
        G = _rotl(F,19)
        F = E
        E = P0(TT2)
    return [(x ^ y) & 0xFFFFFFFF for x,y in zip((A,B,C,D,E,F,G,H), v)]

def sm3(data: bytes) -> bytes:
    ml = len(data) * 8
    data = data + b"\x80"
    pad_len = ((56 - (len(data) % 64)) + 64) % 64
    data = data + b"\x00"*pad_len + struct.pack(">Q", ml)
    v = list(IV)
    for i in range(0, len(data), 64):
        v = _cf(v, data[i:i+64])
    return b"".join(struct.pack(">I", x) for x in v)

def hmac_sm3(key: bytes, msg: bytes) -> bytes:
    block = 64
    if len(key) > block:
        key = sm3(key)
    key = key + b"\x00"*(block - len(key))
    o_key_pad = bytes((k ^ 0x5c) for k in key)
    i_key_pad = bytes((k ^ 0x36) for k in key)
    return sm3(o_key_pad + sm3(i_key_pad + msg))

""" 
Google 密码检测 — 第 3.1 节协议 (参考实现)
--------------------------------------------
该脚本实现了 Thomas 等人在 USENIX Security 2019 论文
《Protecting accounts from credential stuffing with password breach alerting》
中提出的有限泄漏变体 (Section 3.1)。

协议流程回顾 (第 3.1 节)：
- 客户端计算 H = HASH(规范化用户名, 密码)，并取前 n 位 H[0:n] 作为前缀用于分桶。
  客户端生成随机私钥 a，对 H 进行可交换盲化得到 H^a。
- 服务器生成随机私钥 b，计算 (H^a)^b = H^{ab}，并返回：
    • H^{ab}
    • 与相同前缀匹配的泄漏集合 S0（每个元素为 H_i^b）
- 客户端对每个 S0 中的元素计算 (H_i^b)^a = H_i^{ab}，判断是否与 H^{ab} 相等。
  若相等，表示凭据已泄漏。

本演示使用 RFC 3526 MODP Group 14 中的 2048 位安全素数模群进行可交换盲化。
HASH 采用 SHA-256（实际部署建议 Argon2/scrypt 等）。

本代码仅供学术演示。

"""

from __future__ import annotations
import hashlib
import os
from dataclasses import dataclass
from typing import Dict, List, Tuple

# 2048 位 MODP 群 (RFC 3526, Group 14)
P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF", 16
)

# --- 工具函数 -----------------------------------------------------------------

def canonicalize_username(u: str) -> str:
    """规范化用户名：去掉空格、小写化。
    实际部署可能还需进行 Unicode 归一化、特殊字符处理等。
    """
    return "".join(u.split()).lower()

def sha256_bytes(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()

def credential_hash(u: str, p: str) -> bytes:
    """计算 H = SHA-256(规范化用户名 || 0x00 || 密码)"""
    u0 = canonicalize_username(u).encode()
    return sha256_bytes(u0, b"\x00", p.encode())

def map_hash_to_group(h: bytes) -> int:
    """将 32 字节哈希映射到群元素区间 [2, P-2]，避免 0/1 元素。"""
    x = int.from_bytes(h, "big")
    return 2 + (x % (P - 3))

def blind(x: int, a: int) -> int:
    """可交换盲化：计算 x^a mod P"""
    return pow(x, a, P)

def bits_prefix(h: bytes, n_bits: int) -> bytes:
    """取哈希的前 n_bits 位（字节对齐）。"""
    if n_bits % 8:
        n = (n_bits + 7) // 8
    else:
        n = n_bits // 8
    return h[:n]

# --- 服务器端状态 -------------------------------------------------------------

@dataclass
class ServerEntry:
    prefix: bytes  # H[0:n] 前缀
    H_elem: int    # 对应凭据的群元素

class Server:
    def __init__(self, n_bits: int):
        self.n_bits = n_bits
        self.buckets: Dict[bytes, List[ServerEntry]] = {}

    @staticmethod
    def _entry_from_credential(u: str, p: str, n_bits: int) -> ServerEntry:
        H = credential_hash(u, p)
        H_elem = map_hash_to_group(H)
        pref = bits_prefix(H, n_bits)
        return ServerEntry(prefix=pref, H_elem=H_elem)

    def build_from_leaked(self, leaked: List[Tuple[str, str]]):
        """用泄漏数据 (用户名, 密码) 初始化服务器桶。"""
        for u, p in leaked:
            e = self._entry_from_credential(u, p, self.n_bits)
            self.buckets.setdefault(e.prefix, []).append(e)

    def create_response(self, prefix: bytes, H_a: int) -> Tuple[int, List[int]]:
        """服务器根据客户端请求生成响应（协议第 3 步）。"""
        b = int.from_bytes(os.urandom(32), "big") % (P - 2) + 2
        H_ab = blind(H_a, b)
        entries = self.buckets.get(prefix, [])
        S0 = [blind(e.H_elem, b) for e in entries]
        return H_ab, S0

# --- 客户端操作 ---------------------------------------------------------------

@dataclass
class ClientRequest:
    prefix: bytes
    H_a: int
    a: int  # 客户端私钥

@dataclass
class ClientResponse:
    H_ab: int
    S0: List[int]

class Client:
    def __init__(self, n_bits: int):
        self.n_bits = n_bits

    def create_request(self, username: str, password: str) -> ClientRequest:
        """客户端生成请求（协议第 1-2 步）。"""
        H = credential_hash(username, password)
        prefix = bits_prefix(H, self.n_bits)
        H_elem = map_hash_to_group(H)
        a = int.from_bytes(os.urandom(32), "big") % (P - 2) + 2
        H_a = blind(H_elem, a)
        return ClientRequest(prefix=prefix, H_a=H_a, a=a)

    def verdict(self, resp: ClientResponse, a: int) -> bool:
        """客户端根据服务器响应判断是否泄漏（协议第 4 步）。"""
        target = resp.H_ab
        for y in resp.S0:
            if pow(y, a, P) == target:
                return True
        return False

# --- 演示与测试 ---------------------------------------------------------------

def demo():
    leaked = [
        ("Alice@example.com", "correct horse battery staple"),
        ("bob@example.com", "hunter2"),
        ("carol@example.com", "summer2020!"),
    ]

    n_bits = 20  # 前缀位数，可调
    server = Server(n_bits)
    server.build_from_leaked(leaked)

    client = Client(n_bits)

    # 测试 1: 泄漏凭据
    req = client.create_request("bob@example.com", "hunter2")
    H_ab, S0 = server.create_response(req.prefix, req.H_a)
    is_compromised = client.verdict(ClientResponse(H_ab, S0), req.a)
    print("bob@example.com / hunter2 -> 泄漏?", is_compromised)

    # 测试 2: 安全凭据
    req2 = client.create_request("dave@example.com", "unique-strong-password")
    H_ab2, S02 = server.create_response(req2.prefix, req2.H_a)
    is_compromised2 = client.verdict(ClientResponse(H_ab2, S02), req2.a)
    print("dave@example.com / unique-strong-password -> 泄漏?", is_compromised2)

if __name__ == "__main__":
    demo()

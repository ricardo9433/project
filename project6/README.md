# Project 6: Google 密码检测协议 (第 3.1 节实现)

本项目实现了 Google Password Checkup 协议在论文
[Protecting accounts from credential stuffing with password breach alerting](https://eprint.iacr.org/2019/723.pdf)
中 **Section 3.1** 提出的有限前缀泄漏变体。

## 协议概述

目标：在不直接暴露明文密码的情况下，检测用户凭据是否出现在泄漏数据集中。

### 数学符号

- $H$: 哈希值 $H = \text{Hash}(\text{username}, \text{password})$
- $p$: 大素数（安全群模数）
- $a$: 客户端随机私钥
- $b$: 服务器随机私钥
- $g$: 群生成元（本协议直接使用 $H$ 作为基）
- $n$: 前缀位数

### 步骤

1. **客户端计算凭据哈希**
   $$
   H = \text{SHA-256}(\text{canonicalize}(u) \| 0x00 \| p)
   $$
   将 $H$ 映射到群元素 $x \in [2, P-2]$。取前 $n$ 位作为前缀 $\text{prefix}$。

2. **客户端盲化**
   生成随机私钥 $a$，计算
   $$
   H^a \bmod P
   $$
   发送 $(\text{prefix}, H^a)$ 给服务器。

3. **服务器匹配前缀并再次盲化**
   - 选取随机私钥 $b$，计算 $(H^a)^b = H^{ab} \bmod P$。
   - 在泄漏库中找到所有前缀相同的条目 $H_i$，计算 $H_i^b$，组成集合 $S_0$。
   - 返回 $(H^{ab}, S_0)$ 给客户端。

4. **客户端去盲化并比较**
   对每个 $y \in S_0$，计算 $y^a = H_i^{ab}$，若有值等于 $H^{ab}$，则说明匹配成功（凭据泄漏）。

### 协议性质

- **隐私性**：客户端不向服务器发送明文凭据，服务器无法知道客户端的确切 $H$。
- **有限泄漏**：仅暴露前缀 $n$ 位，防止服务器扫描整个空间。
- **可交换盲化**：由于幂运算交换律 $(H^a)^b = (H^b)^a$，客户端与服务器都能在不共享私钥的情况下计算 $H^{ab}$。

## 文件说明

- `project6.py` — 协议实现与演示代码（中文注释）
- `README.md` — 协议数学推导与说明

## 运行方法

```bash
python3 project6.py
```

运行后会显示两组凭据的检测结果（一个泄漏，一个安全）。

## 参考文献

Thomas, Kurt, et al. *Protecting accounts from credential stuffing with password breach alerting.* USENIX Security Symposium. 2019.

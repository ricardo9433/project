
# Project 5: SM2 软件实现与误用验证（PoC）


## 目录
- `sm2`
  - `sm3.py`：SM3 摘要（含 HMAC-SM3）
  - `ecc.py`：有限域与椭圆曲线点运算（含常规与常数时间求逆）
  - `sm2_params.py`：SM2 椭圆曲线参数（国密 prime 域）
  - `sm2_sign.py`：SM2 签名/验签、ZA 计算、RFC6979 风格的确定性 k
  - `ecdsa.py`：最小可用 ECDSA（用于“同 d 同 k”跨算法 PoC）
- `poc/`
  - `poc_leak_k.py`：泄露随机数 k 恢复私钥 d
  - `poc_reuse_k_same_user.py`：同一用户复用 k，利用两条签名恢复 d
  - `poc_reuse_k_two_users.py`：不同用户复用同一个 k，互相恢复对方 d
  - `poc_same_dk_with_ecdsa.py`：同一对 (d, k) 分别用于 ECDSA 与 SM2，恢复 d
  - `poc_recover_pub_from_sig.py`：在特定前置条件下由 (r, s, e) 反推出公钥 P（教材级演示）
- `tests/`
  - `quick_selftest.py`：自测试（KeyGen/Sign/Verify/PoC sanity）

## 数学与算法要点

SM2 签名（prime 域）：
- 系统参数：素数域 ( mathbb{F}_p )，曲线 ( y^2 = x^3 + ax + b )，基点 ( G)，阶 ( n )，cofactor ( h )。
- 预处理：
  [ Z_A = mathrm{SM3}(mathrm{ENTL}_A Vert mathrm{ID}_A Vert a Vert b Vert x_G Vert y_G Vert x_A Vert y_A) ]
- 令 ( M' = Z_A Vert M ), ( e = mathrm{SM3}(M') )。取随机( k in [1, n-1] )，计算 ( kG=(x_1,y_1) )，
  [ r equiv (e + x_1) bmod n,quad s equiv (1+d_A)^{-1} (k - r d_A) \bmod n. ]
- 验证：( t=(r+s)\bmod n )，计算 ( (x_1',y_1') = sG + tP_A )，
  [ R equiv (e + x_1') bmod n stackrel{?}{=} r.]

从 (r,s,e) 推公钥：
[ s(1+d_A) equiv k - r d_A pmod n Rightarrow d_A equiv (k - s),(s+r)^{-1} \pmod n. ]
若能由 ( r-e pmod n ) 复原 ( kG=(x_1,y_1) )（选取满足曲线方程的 ( y_1 )），则：
[ P_A = d_AG = (s+r)^{-1}(kG - sG). ]
这要求攻击者能得到正确的 ( kG )（通常做不到）；本仓库仅在可控环境中以“已知 kG”可枚举根的演示条件重现推导流程。

误用与陷阱（与 PoC 对应）：
- 泄露 ( k )：由 ( s(1+d)=k-rd Rightarrow d equiv (k-s)(s+r)^{-1} mod n ) 立即恢复私钥。  
- 同用户复用 ( k )：两次签名 ( (r_1,s_1),(r_2,s_2) ) 推出  
  [ d equiv frac{s_2-s_1}{,s_1-s_2+r_1-r_2,} pmod n. ]
- 不同用户复用同一个 ( k )：双方皆可由对方签名解出对方私钥（见 `poc_reuse_k_two_users.py`）。
- 同一对 ( d,k ) 同时用于 ECDSA 与 SM2：可联立两式消去 ( k ) 得到 ( d )（见 `poc_same_dk_with_ecdsa.py`）。
- 本实现用 HMAC-SM3 给出一个最小参考版本。

### 运行方式
```
# 1) 进入目录
cd sm2-project-5

# 2) 快速自测
python -m tests.quick_selftest

# 3) 逐个跑 PoC
python -m poc.poc_leak_k
python -m poc.poc_reuse_k_same_user
python -m poc.poc_reuse_k_two_users
python -m poc.poc_same_dk_with_ecdsa
python -m poc.poc_recover_pub_from_sig
```


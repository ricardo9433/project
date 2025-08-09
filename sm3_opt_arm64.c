#include "sm3.h"
#include <arm_neon.h>
// 初始常量（符合GM/T 0004-2012）
static const uint32_t IV[8] = {
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
};

// 常量T
static const uint32_t T[64] = {
    0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
    0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
    0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
    0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A
};

// 循环左移宏
#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

// 置换函数
#define P0(x) ((x) ^ ROTL((x), 9) ^ ROTL((x), 17))
#define P1(x) ((x) ^ ROTL((x), 15) ^ ROTL((x), 23))

// 布尔函数
#define FF0(x, y, z) ((x) ^ (y) ^ (z))
#define FF1(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define GG0(x, y, z) ((x) ^ (y) ^ (z))
#define GG1(x, y, z) (((x) & (y)) | ((~(x)) & (z)))

void sm3_init(SM3_CTX *ctx) {
    memcpy(ctx->state, IV, sizeof(IV));
    ctx->count = 0;
    memset(ctx->buffer, 0, 64);
}

// 消息扩展函数
static void message_expansion_neon(const uint8_t block[64], uint32_t W[68]) {
    // 加载整个块到4个128位寄存器
    uint8x16x4_t data = vld1q_u8_x4(block);
    
    // 反转每个32位字的字节序 (大端转小端)
    uint32x4_t w0 = vreinterpretq_u32_u8(vrev32q_u8(data.val[0]));
    uint32x4_t w1 = vreinterpretq_u32_u8(vrev32q_u8(data.val[1]));
    uint32x4_t w2 = vreinterpretq_u32_u8(vrev32q_u8(data.val[2]));
    uint32x4_t w3 = vreinterpretq_u32_u8(vrev32q_u8(data.val[3]));
    
    // 存储前16个字
    vst1q_u32(&W[0], w0);
    vst1q_u32(&W[4], w1);
    vst1q_u32(&W[8], w2);
    vst1q_u32(&W[12], w3);
    
    // 向量化循环展开 - 每次处理4个字
    for (int j = 16; j < 68; j += 4) {
        // 加载依赖的字
        uint32x4_t w_j16 = vld1q_u32(&W[j - 16]);
        uint32x4_t w_j9 = vld1q_u32(&W[j - 9]);
        uint32x4_t w_j3 = vld1q_u32(&W[j - 3]);
        uint32x4_t w_j13 = vld1q_u32(&W[j - 13]);
        uint32x4_t w_j6 = vld1q_u32(&W[j - 6]);
        
        // 计算 temp = W[j-16] ^ W[j-9] ^ ROTL(W[j-3], 15)
        uint32x4_t rot_w3 = vorrq_u32(
            vshlq_n_u32(w_j3, 15),
            vshrq_n_u32(w_j3, 17)
        );
        uint32x4_t temp = veorq_u32(veorq_u32(w_j16, w_j9), rot_w3);
        
        // 计算 P1(temp) = temp ^ ROTL(temp, 15) ^ ROTL(temp, 23)
        uint32x4_t rot15 = vorrq_u32(
            vshlq_n_u32(temp, 15),
            vshrq_n_u32(temp, 17)
        );
        uint32x4_t rot23 = vorrq_u32(
            vshlq_n_u32(temp, 23),
            vshrq_n_u32(temp, 9)
        );
        uint32x4_t p1 = veorq_u32(veorq_u32(temp, rot15), rot23);
        
        // 计算 ROTL(W[j-13], 7)
        uint32x4_t rot_w13 = vorrq_u32(
            vshlq_n_u32(w_j13, 7),
            vshrq_n_u32(w_j13, 25)
        );
        
        // 最终计算 W[j] = P1(temp) ^ rot_w13 ^ W[j-6]
        uint32x4_t w_j = veorq_u32(veorq_u32(p1, rot_w13), w_j6);
        
        // 存储结果
        vst1q_u32(&W[j], w_j);
    }
}

// 压缩函数
static void compress(uint32_t state[8], const uint8_t block[64]) {
    uint32_t W[68];
    uint32_t W_[64];
    uint32_t A, B, C, D, E, F, G, H;
    uint32_t SS1, SS2, TT1, TT2;
    int j;
    
    message_expansion(block, W);
    
    for (j = 0; j < 64; j++) {
        W_[j] = W[j] ^ W[j + 4];
    }
    
    A = state[0]; B = state[1]; C = state[2]; D = state[3];
    E = state[4]; F = state[5]; G = state[6]; H = state[7];
    
    for (j = 0; j < 64; j++) {
        uint32_t T_j = T[j];
        
        // 计算SS1
        SS1 = ROTL(ROTL(A, 12) + E + ROTL(T_j, j), 7);
        SS2 = SS1 ^ ROTL(A, 12);
        
        // 布尔函数选择
        uint32_t FF, GG;
        if (j < 16) {
            FF = FF0(A, B, C);
            GG = GG0(E, F, G);
        } else {
            FF = FF1(A, B, C);
            GG = GG1(E, F, G);
        }
        
        TT1 = FF + D + SS2 + W_[j];
        TT2 = GG + H + SS1 + W[j];
        
        // 更新寄存器
        D = C;
        C = ROTL(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL(F, 19);
        F = E;
        E = P0(TT2);
    }
    
    // 更新状态
    state[0] ^= A; state[1] ^= B; state[2] ^= C; state[3] ^= D;
    state[4] ^= E; state[5] ^= F; state[6] ^= G; state[7] ^= H;
}

void sm3_update(SM3_CTX *ctx, const uint8_t *data, size_t len) {
    size_t buffer_used = ctx->count % 64;
    ctx->count += len * 8;  // 增加位数
    
    // 处理缓冲区中的数据
    if (buffer_used > 0) {
        size_t free_space = 64 - buffer_used;
        
        if (len < free_space) {
            memcpy(ctx->buffer + buffer_used, data, len);
            return;
        }
        
        memcpy(ctx->buffer + buffer_used, data, free_space);
        compress(ctx->state, ctx->buffer);
        data += free_space;
        len -= free_space;
    }
    
    // 处理完整块
    while (len >= 64) {
        compress(ctx->state, data);
        data += 64;
        len -= 64;
    }
    
    // 存储剩余数据
    if (len > 0) {
        memcpy(ctx->buffer, data, len);
    }
}

void sm3_final(SM3_CTX *ctx, uint8_t digest[32]) {
    size_t buffer_used = ctx->count % 64;
    uint64_t bit_count = ctx->count;
    
    // 添加填充
    ctx->buffer[buffer_used++] = 0x80;
    
    // 如果空间不足，处理当前块
    if (64 - buffer_used < 8) {
        memset(ctx->buffer + buffer_used, 0, 64 - buffer_used);
        compress(ctx->state, ctx->buffer);
        buffer_used = 0;
    }
    
    // 填充0
    memset(ctx->buffer + buffer_used, 0, 56 - buffer_used);
    
    // 添加位长度
    bit_count = __builtin_bswap64(bit_count);
    memcpy(ctx->buffer + 56, &bit_count, 8);
    compress(ctx->state, ctx->buffer);
    
    // 输出哈希值
    for (int i = 0; i < 8; i++) {
        digest[i * 4] = (uint8_t)(ctx->state[i] >> 24);
        digest[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        digest[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        digest[i * 4 + 3] = (uint8_t)(ctx->state[i]);
    }
    
    // 清理上下文
    memset
#ifndef SM3_H
#define SM3_H

#include <stdint.h>
#include <string.h>

// SM3哈希上下文结构
typedef struct {
    uint32_t state[8];     // 中间状态
    uint64_t count;        // 已处理消息位数
    uint8_t buffer[64];    // 消息缓冲区
} SM3_CTX;

// 公共接口函数
void sm3_init(SM3_CTX *ctx);
void sm3_update(SM3_CTX *ctx, const uint8_t *data, size_t len);
void sm3_final(SM3_CTX *ctx, uint8_t digest[32]);

#endif // SM3_H
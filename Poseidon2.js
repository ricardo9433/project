pragma circom 2.1.4;

// 矩阵乘法组件 (3x3 MDS矩阵)
template MatrixMul() {
    signal input in[3];
    signal output out[3];
    
    var M[3][3] = [
        [5, 7, 1],
        [3, 4, 6],
        [1, 1, 4]
    ];
    
    out[0] <== M[0][0]*in[0] + M[0][1]*in[1] + M[0][2]*in[2];
    out[1] <== M[1][0]*in[0] + M[1][1]*in[1] + M[1][2]*in[2];
    out[2] <== M[2][0]*in[0] + M[2][1]*in[1] + M[2][2]*in[2];
}

template FullRound(roundIndex) {
    signal input in[3];
    signal output out[3];
    
    var rc_full[8][3] = [
        ["0x8a8b7c6d5", "0x9e9f8a7b6", "0xa5b4c3d2e"],  
        ["0x789abcdef", "0x012345678", "0xbcdef0123"],
        ["0xef0123456", "0x6789abcde", "0x23456789a"],
        ["0x123456789", "0xabcdef012", "0x456789abc"],
        ["0x789012345", "0xcdef01234", "0x56789abcd"],
        ["0xef0123456", "0x789abcdef", "0x012345678"],
        ["0x123456789", "0xabcdef012", "0x456789abc"],
        ["0x789abcdef", "0x012345678", "0xbcdef0123"]
    ];
    
    // AddRoundConstants
    signal afterARC[3];
    afterARC[0] <== in[0] + rc[roundIndex][0];
    afterARC[1] <== in[1] + rc[roundIndex][1];
    afterARC[2] <== in[2] + rc[roundIndex][2];
    
    // S-box (x^5)
    signal afterSBOX[3];
    afterSBOX[0] <== afterARC[0]*afterARC[0]*afterARC[0]*afterARC[0]*afterARC[0];
    afterSBOX[1] <== afterARC[1]*afterARC[1]*afterARC[1]*afterARC[1]*afterARC[1];
    afterSBOX[2] <== afterARC[2]*afterARC[2]*afterARC[2]*afterARC[2]*afterARC[2];
    
    // 线性层
    component matmul = MatrixMul();
    matmul.in[0] <== afterSBOX[0];
    matmul.in[1] <== afterSBOX[1];
    matmul.in[2] <== afterSBOX[2];
    out[0] <== matmul.out[0];
    out[1] <== matmul.out[1];
    out[2] <== matmul.out[2];
}

// 部分轮次 (Partial Round)
template PartialRound(roundIndex) {
    signal input in[3];
    signal output out[3];
    
    var rc_partial[56] = [
        "0x1a2b3c4d5e6f7890", "0x1234567890abcdef", "0x23456789abcdef01",
        "0x3456789abcdef012", "0x456789abcdef0123", "0x56789abcdef01234",
        "0x6789abcdef012345", "0x789abcdef0123456", "0x89abcdef01234567",
        "0x9abcdef012345678", "0xabcdef0123456789", "0xbcdef0123456789a",
        "0xcdef0123456789ab", "0xdef0123456789abc", "0xef0123456789abcd",
        "0xf0123456789abcde", "0x0123456789abcdef", "0x123456789abcdef0",
        "0x23456789abcdef01", "0x3456789abcdef012", "0x456789abcdef0123",
        "0x56789abcdef01234", "0x6789abcdef012345", "0x789abcdef0123456",
        "0x89abcdef01234567", "0x9abcdef012345678", "0xabcdef0123456789",
        "0xbcdef0123456789a", "0xcdef0123456789ab", "0xdef0123456789abc",
        "0xef0123456789abcd", "0xf0123456789abcde", "0x0123456789abcdef",
        "0x123456789abcdef0", "0x23456789abcdef01", "0x3456789abcdef012",
        "0x456789abcdef0123", "0x56789abcdef01234", "0x6789abcdef012345",
        "0x789abcdef0123456", "0x89abcdef01234567", "0x9abcdef012345678",
        "0xabcdef0123456789", "0xbcdef0123456789a", "0xcdef0123456789ab",
        "0xdef0123456789abc", "0xef0123456789abcd", "0xf0123456789abcde",
        "0x0123456789abcdef", "0x123456789abcdef0", "0x23456789abcdef01",
        "0x3456789abcdef012", "0x456789abcdef0123", "0x56789abcdef01234",
        "0x6789abcdef012345", "0x789abcdef0123456"
    ];
    
    // 仅处理第一个元素
    signal afterARC;
    afterARC <== in[0] + rc[roundIndex];
    
    // S-box (x^5)
    signal afterSBOX;
    afterSBOX <== afterARC*afterARC*afterARC*afterARC*afterARC;
    
    // 准备矩阵输入
    signal midState[3];
    midState[0] <== afterSBOX;
    midState[1] <== in[1]; // 其他元素直接传递
    midState[2] <== in[2];
    
    // 线性层 (M_I矩阵)
    component matmul = MatrixMul();
    matmul.in[0] <== midState[0];
    matmul.in[1] <== midState[1];
    matmul.in[2] <== midState[2];
    out[0] <== matmul.out[0];
    out[1] <== matmul.out[1];
    out[2] <== matmul.out[2];
}

// Poseidon2主电路
template Poseidon2() {
    signal input inputs[3];   // 隐私输入 (3个域元素)
    signal output out;         // 公开输出 (哈希值)
    
    // 初始线性层 M_E
    component initMatMul = MatrixMul();
    initMatMul.in[0] <== inputs[0];
    initMatMul.in[1] <== inputs[1];
    initMatMul.in[2] <== inputs[2];
    
    // 前4个完整轮次 (R_F/2)
    component fullRounds1[4];
    for (var i = 0; i < 4; i++) {
        fullRounds1[i] = FullRound(i);
        if (i == 0) {
            fullRounds1[i].in[0] <== initMatMul.out[0];
            fullRounds1[i].in[1] <== initMatMul.out[1];
            fullRounds1[i].in[2] <== initMatMul.out[2];
        } else {
            fullRounds1[i].in[0] <== fullRounds1[i-1].out[0];
            fullRounds1[i].in[1] <== fullRounds1[i-1].out[1];
            fullRounds1[i].in[2] <== fullRounds1[i-1].out[2];
        }
    }
    
    // 56个部分轮次 (R_P)
    component partialRounds[56];
    for (var i = 0; i < 56; i++) {
        partialRounds[i] = PartialRound(i);
        if (i == 0) {
            partialRounds[i].in[0] <== fullRounds1[3].out[0];
            partialRounds[i].in[1] <== fullRounds1[3].out[1];
            partialRounds[i].in[2] <== fullRounds1[3].out[2];
        } else {
            partialRounds[i].in[0] <== partialRounds[i-1].out[0];
            partialRounds[i].in[1] <== partialRounds[i-1].out[1];
            partialRounds[i].in[2] <== partialRounds[i-1].out[2];
        }
    }
    
    // 后4个完整轮次 (R_F/2)
    component fullRounds2[4];
    for (var i = 0; i < 4; i++) {
        fullRounds2[i] = FullRound(i+4); // 使用索引4-7的常数
        if (i == 0) {
            fullRounds2[i].in[0] <== partialRounds[55].out[0];
            fullRounds2[i].in[1] <== partialRounds[55].out[1];
            fullRounds2[i].in[2] <== partialRounds[55].out[2];
        } else {
            fullRounds2[i].in[0] <== fullRounds2[i-1].out[0];
            fullRounds2[i].in[1] <== fullRounds2[i-1].out[1];
            fullRounds2[i].in[2] <== fullRounds2[i-1].out[2];
        }
    }
    
    // 输出第一个状态元素作为哈希值
    out <== fullRounds2[3].out[0];
}

component main = Poseidon2();
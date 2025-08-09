RFC6962_PREFIX_LEAF = b'\x00'
RFC6962_PREFIX_NODE = b'\x01'

class MerkleTree:
    def __init__(self):
        self.leaves = []
        self.tree = []
        self.root = b''
    
    def add_leaf(self, data):
        """添加叶子节点"""
        leaf_hash = sm3_hash(RFC6962_PREFIX_LEAF + data)
        self.leaves.append(leaf_hash)
    
    def build(self):
        """构建Merkle树"""
        # 特殊处理空树
        if not self.leaves:
            self.root = sm3_hash(b'')
            return
            
        # 确保叶子数为2^n
        level = self.leaves
        while len(level) > 1:
            next_level = []
            for i in range(0, len(level), 2):
                left = level[i]
                right = level[i+1] if i+1 < len(level) else level[i]
                node_hash = sm3_hash(RFC6962_PREFIX_NODE + left + right)
                next_level.append(node_hash)
            self.tree.append(level)
            level = next_level
        self.root = level[0]
        self.tree.append([self.root])
    
    def get_proof(self, index):
        """获取存在性证明"""
        proof = []
        for level in self.tree[:-1]:
            sibling_index = index + 1 if index % 2 == 0 else index - 1
            if sibling_index < len(level):
                position = 'right' if index % 2 == 0 else 'left'
                proof.append((level[sibling_index], position))
            index //= 2
        return proof

def verify_proof(leaf, root, proof):
    """验证存在性证明"""
    current = leaf
    for sibling, position in proof:
        if position == 'left':
            current = sm3_hash(RFC6962_PREFIX_NODE + sibling + current)
        else:
            current = sm3_hash(RFC6962_PREFIX_NODE + current + sibling)
    return current == root

def generate_absence_proof(tree, target):
    """生成不存在性证明"""
    # 1. 查找前驱和后继
    sorted_leaves = sorted(tree.leaves)
    idx = bisect.bisect_left(sorted_leaves, target)
    
    # 边界检查
    if idx == 0:
        predecessor = None
        successor = sorted_leaves[0]
    elif idx == len(sorted_leaves):
        predecessor = sorted_leaves[-1]
        successor = None
    else:
        predecessor = sorted_leaves[idx-1]
        successor = sorted_leaves[idx]
    
    # 2. 生成存在性证明
    proof = []
    if predecessor:
        pred_idx = tree.leaves.index(predecessor)
        proof.append(('predecessor', tree.get_proof(pred_idx)))
    if successor:
        succ_idx = tree.leaves.index(successor)
        proof.append(('successor', tree.get_proof(succ_idx)))
    
    return proof
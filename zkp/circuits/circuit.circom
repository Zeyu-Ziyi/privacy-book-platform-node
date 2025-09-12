pragma circom 2.0.0;

// 1. 导入我们唯一需要的依赖：Poseidon
include "circomlib/circuits/poseidon.circom";

// ----------------------------------------------------
// 2. 自包含的 Merkle 验证器组件 (保持不变)
// ----------------------------------------------------
template Swap(n) {
    assert(n == 2);
    signal input in[n];
    signal input c; 
    signal output out[n];
    c * (c - 1) === 0;
    signal diff <== in[1] - in[0];
    signal c_diff <== c * diff;
    out[0] <== in[0] + c_diff;
    out[1] <== in[1] - c_diff;
}

template MerkleProof(levels) {
    signal input leaf;
    signal input path_elements[levels];
    signal input path_indices[levels];
    signal input root;

    component swappers[levels];
    component hashers[levels];

    swappers[0] = Swap(2);
    swappers[0].in[0] <== leaf;
    swappers[0].in[1] <== path_elements[0];
    swappers[0].c <== path_indices[0];

    hashers[0] = Poseidon(2);
    hashers[0].inputs[0] <== swappers[0].out[0];
    hashers[0].inputs[1] <== swappers[0].out[1];

    for (var i = 1; i < levels; i++) {
        swappers[i] = Swap(2);
        swappers[i].in[0] <== hashers[i-1].out;
        swappers[i].in[1] <== path_elements[i];
        swappers[i].c <== path_indices[i];

        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== swappers[i].out[0];
        hashers[i].inputs[1] <== swappers[i].out[1];
    }
    root === hashers[levels-1].out;
}

// ----------------------------------------------------
// 3. 您的主模板 (已修改)
// ----------------------------------------------------
template PurchaseVerifier(TREE_LEVELS) {

    // --- 私有输入 ---
    signal input book_id;
    signal input nonce;
    signal input price;
    signal input merkle_proof[TREE_LEVELS];
    signal input merkle_path_indices[TREE_LEVELS];

    // --- 公开输入 ---
    signal input merkle_root;
    signal input commitment;

    // --- 公开输出 ---
    signal output nullifier;

    // --- 约束逻辑 ---

    // 约束 1: 验证承诺
    component commitment_hasher = Poseidon(3);
    commitment_hasher.inputs[0] <== book_id;
    commitment_hasher.inputs[1] <== nonce;
    commitment_hasher.inputs[2] <== price;
    commitment_hasher.out === commitment;

    // 约束 2: 验证 Merkle 树
    // 2a. 计算叶子节点
    component leaf_hasher = Poseidon(2);
    leaf_hasher.inputs[0] <== book_id;
    leaf_hasher.inputs[1] <== price; // <-- CRITICAL FIX: 'leaf_haser' -> 'leaf_hasher'
    signal leaf <== leaf_hasher.out;

    // 2b. 使用我们自己编写的 MerkleProof 组件
    component merkle_verifier = MerkleProof(TREE_LEVELS);
    merkle_verifier.leaf <== leaf;
    merkle_verifier.root <== merkle_root;
    for (var i = 0; i < TREE_LEVELS; i++) {
        merkle_verifier.path_elements[i] <== merkle_proof[i];
        merkle_verifier.path_indices[i] <== merkle_path_indices[i];
    }

    // 约束 3: 计算并输出废止符
    component nullifier_hasher = Poseidon(1);
    nullifier_hasher.inputs[0] <== nonce;
    nullifier <== nullifier_hasher.out;
}

// 4. 实例化主组件
component main { public [merkle_root, commitment] } = PurchaseVerifier(8);


import { MerkleTree } from "circomlibjs";

const tree = new MerkleTree(20); // 20 层 Merkle tree
tree.insert(1n);
tree.insert(2n);

console.log("Root:", tree.root);

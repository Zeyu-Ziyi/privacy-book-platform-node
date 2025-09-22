// ot_example.js

import { ed25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha256.js';

// -----------------------------------------------------------
// 辅助函数：使用 AES-GCM 进行对称加密和解密
// -----------------------------------------------------------

/**
 * 从共享秘密点派生出 AES 密钥。
 * @param {Uint8Array} sharedSecret - 共享秘密点的原始字节。
 * @returns {Promise<CryptoKey>} AES-GCM 密钥。
 */
async function deriveAesKey(sharedSecret) {
    const hash = sha256(sharedSecret);
    return await crypto.subtle.importKey(
        'raw',
        hash.slice(0, 32), // 使用哈希的前32字节作为密钥
        { name: 'AES-GCM' },
        false,
        ['encrypt', 'decrypt']
    );
}

/**
 * 使用 AES-GCM 加密数据。
 * @param {CryptoKey} key - AES 密钥。
 * @param {Uint8Array} data - 要加密的数据。
 * @returns {Promise<{ ciphertext: Uint8Array, iv: Uint8Array }>} 加密后的数据和 IV。
 */
async function symmetricEncrypt(key, data) {
    const iv = crypto.getRandomValues(new Uint8Array(12)); // AES-GCM 推荐使用 12 字节 IV
    const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        key,
        data
    );
    return { ciphertext: new Uint8Array(ciphertext), iv };
}

/**
 * 使用 AES-GCM 解密数据。
 * @param {CryptoKey} key - AES 密钥。
 * @param {Uint8Array} ciphertext - 加密后的数据。
 * @param {Uint8Array} iv - 初始化向量。
 * @returns {Promise<Uint8Array>} 解密后的数据。
 */
async function symmetricDecrypt(key, ciphertext, iv) {
    try {
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            key,
            ciphertext
        );
        return new Uint8Array(decrypted);
    } catch (e) {
        console.error("解密失败，密钥不匹配。");
        return null;
    }
}


// -----------------------------------------------------------
// 主函数：运行不经意传输协议
// -----------------------------------------------------------

/**
 * 运行完整的 1-out-of-2 OT 协议。
 * @param {number} bobChoice - Bob 的选择，0 或 1。
 */
async function runObliviousTransfer(bobChoice) {
    console.log(`Bob's choice: M${bobChoice}`);
    
    // -----------------------------------------------------------
    // 第 1 步: Alice 生成并发送初始公钥
    // -----------------------------------------------------------
    console.log("\n--- Step 1: Alice generates her key pair ---");
    const a_private = ed25519.utils.randomPrivateKey();
    const A_public_point = ed25519.Point.fromPrivateKey(a_private);
    
    // 模拟 Alice -> Bob 通信
    const A_public_bytes = A_public_point.toRawBytes();
    console.log("Alice's public key (A) sent to Bob.");


    // -----------------------------------------------------------
    // 第 2 步: Bob 根据选择构造并发送公钥
    // -----------------------------------------------------------
    console.log("\n--- Step 2: Bob generates his key and sends a crafted point ---");
    
    // Bob 接收到 Alice 的公钥
    const A_public_from_alice = ed25519.Point.fromHex(A_public_bytes);
    
    // Bob 生成自己的密钥对
    const b_private = ed25519.utils.randomPrivateKey();
    const B_public_point = ed25519.Point.fromPrivateKey(b_private);
    
    // 根据选择 c 构造要发送的点
    let P_to_send;
    if (bobChoice === 0) {
        P_to_send = B_public_point;
    } else { // bobChoice === 1
        P_to_send = A_public_from_alice.subtract(B_public_point);
    }
    
    // 模拟 Bob -> Alice 通信
    const P_from_bob_bytes = P_to_send.toRawBytes();
    console.log("Bob's crafted point (P) sent to Alice.");


    // -----------------------------------------------------------
    // 第 3 步: Alice 加密并发送消息
    // -----------------------------------------------------------
    console.log("\n--- Step 3: Alice encrypts and sends messages ---");
    
    // Alice 接收到 Bob 的点
    const P_from_bob = ed25519.Point.fromHex(P_from_bob_bytes);
    
    // Alice 的两条消息
    const M0 = new TextEncoder().encode("Hello, this is the secret message for choice 0!");
    const M1 = new TextEncoder().encode("Hi there, here is the secret message for choice 1!");
    
    // Alice 计算两个可能的共享密钥点
    const shared_point_0 = P_from_bob.multiply(a_private);
    const shared_point_1 = A_public_from_alice.subtract(P_from_bob).multiply(a_private);
    
    // 使用哈希和 HKDF 派生出对称密钥
    const k0 = await deriveAesKey(shared_point_0.toRawBytes());
    const k1 = await deriveAesKey(shared_point_1.toRawBytes());
    
    // 使用 k0 和 k1 对消息进行对称加密
    const encrypted0 = await symmetricEncrypt(k0, M0);
    const encrypted1 = await symmetricEncrypt(k1, M1);
    
    // 模拟 Alice -> Bob 通信
    const encryptedMessages = {
        E0: encrypted0.ciphertext,
        E0_iv: encrypted0.iv,
        E1: encrypted1.ciphertext,
        E1_iv: encrypted1.iv,
    };
    console.log("Alice sent both encrypted messages (E0, E1) to Bob.");


    // -----------------------------------------------------------
    // 第 4 步: Bob 解密他选择的消息
    // -----------------------------------------------------------
    console.log("\n--- Step 4: Bob decrypts his chosen message ---");
    
    // Bob 接收到 Alice 的加密消息
    const { E0, E0_iv, E1, E1_iv } = encryptedMessages;
    
    // Bob 计算真实的共享密钥点
    const shared_point_real = A_public_from_alice.multiply(b_private);
    
    // 派生出真实的对称密钥
    const k_real = await deriveAesKey(shared_point_real.toRawBytes());
    
    // 根据选择解密对应的消息
    const chosenCiphertext = bobChoice === 0 ? E0 : E1;
    const chosenIv = bobChoice === 0 ? E0_iv : E1_iv;
    
    const decrypted_message = await symmetricDecrypt(k_real, chosenCiphertext, chosenIv);

    if (decrypted_message) {
        console.log("Successfully decrypted message!");
        console.log("Decrypted message:", new TextDecoder().decode(decrypted_message));
    }
    
    // 尝试解密另一条消息（理论上会失败）
    console.log("\nAttempting to decrypt the other message (should fail)...");
    const otherCiphertext = bobChoice === 0 ? E1 : E0;
    const otherIv = bobChoice === 0 ? E1_iv : E0_iv;
    await symmetricDecrypt(k_real, otherCiphertext, otherIv);

}

// 运行协议，可以改变参数来测试 Bob 选择 M0 或 M1 的情况
// 例如：runObliviousTransfer(0);
runObliviousTransfer(1);
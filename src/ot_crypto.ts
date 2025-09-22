// src/ot_crypto.ts
import { createCipheriv, randomBytes, createHash } from 'node:crypto';
import { p256 } from '@noble/curves/nist';

/**
 * 服务器为OT的每一轮生成一个临时的私钥b和公钥g=bG。
 */
export const generateServerOtKeyPair = (): { privateKey: Uint8Array; publicKey: Uint8Array } => {
  const privateKey = p256.utils.randomSecretKey();
  const publicKey = p256.getPublicKey(privateKey);
  
  // --- DEBUG LOG ---
  console.log(`[OT-CRYPTO-SERVER] 产生新的密钥对:`);
  console.log(`  - PrivKey: ${Buffer.from(privateKey).toString('hex').substring(0, 10)}...`);
  console.log(`  - PubKey:  ${Buffer.from(publicKey).toString('hex').substring(0, 10)}...`);
  // --- END DEBUG LOG ---

  return { privateKey, publicKey };
};

/**
 * 服务器使用其私钥和客户端的公钥派生共享密钥。
 */
export const deriveServerSharedSecret = (serverPrivateKey: Uint8Array, clientPublicKey: Uint8Array): Buffer => {
    // --- DEBUG LOG ---
    console.log(`[OT-CRYPTO-SERVER] 正在派生共享密钥...`);
    console.log(`  - Server PrivKey: ${Buffer.from(serverPrivateKey).toString('hex').substring(0, 10)}...`);
    console.log(`  - Client PubKey:  ${Buffer.from(clientPublicKey).toString('hex').substring(0, 10)}...`);
    // --- END DEBUG LOG ---

    const sharedSecret = p256.getSharedSecret(serverPrivateKey, clientPublicKey);
    const hashedSecret = createHash('sha256').update(sharedSecret).digest();
    
    // --- DEBUG LOG ---
    console.log(`  - 派生的共享密钥 (哈希后): ${hashedSecret.toString('hex')}`);
    // --- END DEBUG LOG ---
    
    return hashedSecret;
}

/**
 * 使用 AES-256-GCM 对数据进行加密。
 */
export const aesGcmEncrypt = (key: Buffer, plaintext: Buffer): Buffer => {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return Buffer.concat([iv, ciphertext, authTag]);
};
// src/ot_crypto.ts
import { createCipheriv, randomBytes, createHash } from 'node:crypto';
import { p256 } from '@noble/curves/nist';

/**
 * server generates a temporary private key b and public key g=bG for each round of OT.
 */
export const generateServerOtKeyPair = (): { privateKey: Uint8Array; publicKey: Uint8Array } => {
  const privateKey = p256.utils.randomSecretKey();
  const publicKey = p256.getPublicKey(privateKey);
  
  // --- DEBUG LOG ---
  console.log(`[OT-CRYPTO-SERVER] generate new key pair:`);
  console.log(`  - PrivKey: ${Buffer.from(privateKey).toString('hex').substring(0, 10)}...`);
  console.log(`  - PubKey:  ${Buffer.from(publicKey).toString('hex').substring(0, 10)}...`);
  // --- END DEBUG LOG ---

  return { privateKey, publicKey };
};

/**
 * server derives the shared secret using its private key and the client's public key.
 */
export const deriveServerSharedSecret = (serverPrivateKey: Uint8Array, clientPublicKey: Uint8Array): Buffer => {
    // --- DEBUG LOG ---
    console.log(`[OT-CRYPTO-SERVER] deriving shared secret...`);
    console.log(`  - Server PrivKey: ${Buffer.from(serverPrivateKey).toString('hex').substring(0, 10)}...`);
    console.log(`  - Client PubKey:  ${Buffer.from(clientPublicKey).toString('hex').substring(0, 10)}...`);
    // --- END DEBUG LOG ---

    const sharedSecret = p256.getSharedSecret(serverPrivateKey, clientPublicKey);
    const hashedSecret = createHash('sha256').update(sharedSecret).digest();
    
    // --- DEBUG LOG ---
    console.log(`  - derived shared secret (hashed): ${hashedSecret.toString('hex')}`);
    // --- END DEBUG LOG ---
    
    return hashedSecret;
}

/**
 * encrypt data using AES-256-GCM.
 */
export const aesGcmEncrypt = (key: Buffer, plaintext: Buffer): Buffer => {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return Buffer.concat([iv, ciphertext, authTag]);
};
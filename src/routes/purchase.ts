import { verify as verifyJwt } from 'hono/jwt';
import pool from '../db.js';
import R2 from '../r2.js';
import { GetObjectCommand } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner"; 
import { groth16 } from 'snarkjs';
import { readFileSync } from 'fs';
import path from 'path';
import type { WebSocket } from 'ws';
import { createECDH, createCipheriv, randomBytes, createHash } from 'node:crypto';

const vkey = JSON.parse(readFileSync(path.join(process.cwd(), 'zkp', 'verification_key.json'), 'utf-8'));

const aesGcmEncrypt = (key: Buffer, plaintext: Buffer): { iv: Buffer, ciphertext: Buffer, authTag: Buffer } => {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const authTag = cipher.getAuthTag();
    return { iv, ciphertext, authTag };
};

export const handlePurchaseConnection = (ws: WebSocket, purchaseId: string) => {
  let sessionState = { userId: '', purchase: null as any };
  
  ws.on('message', async (message: Buffer) => {
    const data = JSON.parse(message.toString());

    if (data.type === 'INIT') {
      try {
        const decodedPayload = await verifyJwt(data.token, process.env.JWT_SECRET!);
        if (!decodedPayload || typeof decodedPayload.sub !== 'string') return ws.close(1011, 'Invalid token payload.');
        sessionState.userId = decodedPayload.sub;
        
        const purchaseResult = await pool.query("SELECT user_id, status, commitment FROM purchases WHERE id = $1", [purchaseId]);
        if (purchaseResult.rows.length === 0 || purchaseResult.rows[0].user_id !== sessionState.userId) return ws.close(1011, 'Purchase not found.');
        if (purchaseResult.rows[0].status !== 'paid') return ws.close(1011, `Purchase status not 'paid'.`);
        sessionState.purchase = purchaseResult.rows[0];
        ws.send(JSON.stringify({ type: 'ZKP_READY' }));
      } catch (err) {
        console.error('INIT Error:', err);
        ws.close(1011, 'Authentication failed.');
      }
    }
    
    else if (data.type === 'ZKP_PROVE') {
      const { proof, publicSignals } = data.payload;
      const clientNullifier = publicSignals[0];
      const clientMerkleRoot = publicSignals[1]; 
      const clientCommitment = publicSignals[2];
      
      if (clientCommitment !== sessionState.purchase.commitment) {
        return ws.close(1011, 'Public commitment mismatch.');
      }
      
      const isVerified = await groth16.verify(vkey, publicSignals, proof);
      if (isVerified) {
        try {
          const updateResult = await pool.query(
            "UPDATE purchases SET status = 'verified', nullifier_hash = $1 WHERE id = $2 AND status = 'paid'",
            [clientNullifier, purchaseId]
          );
          if (updateResult.rowCount === 0) return ws.close(1011, 'Purchase already verified.');
          ws.send(JSON.stringify({ type: 'OT_READY' }));
        } catch (dbErr: any) {
          if (dbErr.code === '23505') return ws.close(1011, 'Proof already used.');
          return ws.close(1011, 'DB finalization error.');
        }
      } else {
        ws.close(1011, 'ZKP verification failed.');
      }
    }
    
    else if (data.type === 'OT_START') {
      const clientPublicKeyHex = data.payload.publicKey;
      try {
        const bucketName = process.env.R2_BUCKET_NAME;
        if (!bucketName) return ws.close(1011, 'Server configuration error.');

        const booksResult = await pool.query('SELECT id, file_key, secret_key FROM books ORDER BY id');
        const allBookSecrets = booksResult.rows;

        const allSignedUrls = await Promise.all(
          allBookSecrets.map(book => getSignedUrl(R2, new GetObjectCommand({ Bucket: bucketName, Key: book.file_key }), { expiresIn: 300 }))
        );

        const clientPublicKey = Buffer.from(clientPublicKeyHex, 'hex');

        const otResponsePayload = allBookSecrets.map((book) => {
          const serverEcdh = createECDH('prime256v1');
          const serverTempPublicKey = serverEcdh.generateKeys();
          const sharedSecret = serverEcdh.computeSecret(clientPublicKey);
          const encryptionKey = createHash('sha256').update(sharedSecret).digest();
          const realBookKey = Buffer.from(book.secret_key, 'hex');
          const { iv, ciphertext, authTag } = aesGcmEncrypt(encryptionKey, realBookKey);

          return {
            serverTempPublicKey: serverTempPublicKey.toString('hex'),
            // --- 关键修改: 使用 IV -> Ciphertext -> AuthTag 的标准顺序 ---
            encryptedBookKey: Buffer.concat([iv, ciphertext, authTag]).toString('hex'),
          };
        });

        ws.send(JSON.stringify({ 
          type: 'OT_CHALLENGE', 
          payload: { otResponses: otResponsePayload, signedUrls: allSignedUrls } 
        }));

        await pool.query("UPDATE purchases SET status = 'completed' WHERE id = $1", [purchaseId]);
        console.log(`[OT] Challenge sent for purchase ${purchaseId}.`);
      } catch (err) {
        console.error('OT_START Error:', err);
        ws.close(1011, 'Oblivious Transfer failed on server.');
      }
    }
  });

  ws.on('close', () => console.log(`[WS] Connection closed for purchase: ${purchaseId}`));
  ws.on('error', (err: Error) => console.error('[WS] Error:', err));
};


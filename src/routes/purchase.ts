import { verify as verifyJwt } from 'hono/jwt';
import pool from '../db.js';
import R2 from '../r2.js';
import { GetObjectCommand } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner"; 
import { groth16 } from 'snarkjs';
import { readFileSync } from 'fs';
import path from 'path';
import type { WebSocket } from 'ws'; // <-- 导入 'ws' 的类型定义

const vkey = JSON.parse(readFileSync(path.join(process.cwd(), 'zkp', 'verification_key.json'), 'utf-8'));

class SimpleOTServer {
  private items: string[];
  constructor(items: string[]) { this.items = items; }
  processRequest(clientEncryptedChoice: number): string[] {
    return this.items.map((item, index) => {
      if (index === clientEncryptedChoice) { return `ENCRYPTED(${item})`; }
      return `ENCRYPTED(GARBAGE_${index})`;
    });
  }
}

/**
 * 处理一个已建立的、与特定购买相关的 WebSocket 连接。
 * @param {WebSocket} ws - 来自 'ws' 包的原生 WebSocket 实例。
 * @param {string} purchaseId - 从 URL 中解析出的购买 ID。
 */
export const handlePurchaseConnection = (ws: WebSocket, purchaseId: string) => {
  let sessionState = { userId: '', purchase: null as any };
  
  ws.on('message', async (message: Buffer) => {
    const messageData = message.toString();
    const data = JSON.parse(messageData);
    console.log('data', data);
    if (data.type === 'INIT') {
      try {
        const decodedPayload = await verifyJwt(data.token, process.env.JWT_SECRET!);
        if (!decodedPayload || typeof decodedPayload.sub !== 'string') {
          return ws.close(1011, 'Invalid token payload.');
        }
        sessionState.userId = decodedPayload.sub;
        
        const purchaseResult = await pool.query(
          "SELECT user_id, status, commitment FROM purchases WHERE id = $1", [purchaseId]
        );
        if (purchaseResult.rows.length === 0 || purchaseResult.rows[0].user_id !== sessionState.userId) {
          return ws.close(1011, 'Purchase not found or not owned by user.');
        }
        if (purchaseResult.rows[0].status !== 'paid') {
          return ws.close(1011, `Purchase status is not 'paid' (current: ${purchaseResult.rows[0].status}).`);
        }
        sessionState.purchase = purchaseResult.rows[0];
        ws.send(JSON.stringify({ type: 'ZKP_READY' }));
      } catch (err) {
        console.error('An error occurred in the INIT block:', err);
        ws.close(1011, 'Authentication failed.');
      }
    }
    
    else if (data.type === 'ZKP_PROVE') {
      const { proof, publicSignals } = data.payload;
      const clientCommitment = publicSignals[2];
      const clientNullifier = publicSignals[0]; 
      if (clientCommitment !== sessionState.purchase.commitment) {
        return ws.close(1011, 'Public commitment mismatch.');
      }

      const isVerified = await groth16.verify(vkey, publicSignals, proof);
      console.log('isVerified', isVerified);
      if (isVerified) {
        try {
          // 使用废止符 (Nullifier) 来防止重放攻击
          const updateResult = await pool.query(
            "UPDATE purchases SET status = 'verified', nullifier_hash = $1 WHERE id = $2 AND status = 'paid'",
            [clientNullifier, purchaseId]
          );
          if (updateResult.rowCount === 0) {
            return ws.close(1011, 'Purchase already verified or status is not paid.');
          }
          ws.send(JSON.stringify({ 'OT_READY': true }));
        } catch (dbErr: any) {
          if (dbErr.code === '23505') { // unique_violation on nullifier_hash
            console.warn(`REPLAY ATTACK DETECTED: Nullifier ${clientNullifier} already used.`);
            return ws.close(1011, 'Proof has already been used.');
          }
          console.error('Failed to update purchase with nullifier:', dbErr);
          return ws.close(1011, 'DB error during finalization.');
        }
      } else {
        ws.close(1011, 'ZKP verification failed.');
      }
    }
    
    else if (data.type === 'OT_SELECT') {
      const clientChoiceIndex = data.payload.choiceIndex;
      const booksResult = await pool.query('SELECT id, file_key FROM books ORDER BY id');
      if (clientChoiceIndex < 0 || clientChoiceIndex >= booksResult.rows.length) {
        return ws.close(1011, 'Invalid choice index for OT.');
      }
      const allPresignedUrls = await Promise.all(
        booksResult.rows.map(book => getSignedUrl(R2, new GetObjectCommand({
          Bucket: process.env.R2_BUCKET_NAME!,
          Key: book.file_key,
        }), { expiresIn: 300 }))
      );
      const otServer = new SimpleOTServer(allPresignedUrls);
      const encryptedResults = otServer.processRequest(clientChoiceIndex);
      ws.send(JSON.stringify({ type: 'OT_RESULT', payload: encryptedResults }));
      await pool.query("UPDATE purchases SET status = 'completed' WHERE id = $1", [purchaseId]);
      ws.close(1000, 'Purchase completed.');
    }
  });

  ws.on('close', () => {
    console.log(`[WS] Connection closed for purchase: ${purchaseId}`);
  });
  ws.on('error', (err: Error) => {
      console.error('[WS] Error:', err);
  });
};


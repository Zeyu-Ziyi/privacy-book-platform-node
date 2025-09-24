// src/routes/purchase.ts
import { verify as verifyJwt } from 'hono/jwt';
import pool from '../db.js';
import R2 from '../r2.js';
import { GetObjectCommand } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { groth16 } from 'snarkjs';
import { readFileSync } from 'fs';
import path from 'path';
import type { WebSocket } from 'ws';
import { randomBytes } from 'node:crypto';
// 导入基于noble-curves的密码学工具
import {
  generateServerOtKeyPair,
  deriveServerSharedSecret,
  aesGcmEncrypt,
} from '../ot_crypto.js';

// 加载ZKP支付验证密钥
const vkey = JSON.parse(readFileSync(path.join(process.cwd(), 'zkp', 'verification_key.json'), 'utf-8'));

/**
 * 这个类为每个WebSocket连接管理半诚实OT协议的完整状态。
 */
class SemiHonestOtSender {
  private ws: WebSocket;
  private bookSecrets: Buffer[];
  private choiceBitCount: number;
  private currentRound = 0;
  private roundSeeds: { seed0: Buffer, seed1: Buffer }[] = [];

  constructor(ws: WebSocket, books: { secret_key: string }[]) {
    this.ws = ws;
    this.bookSecrets = books.map(b => Buffer.from(b.secret_key, 'hex'));
    this.choiceBitCount = books.length > 1 ? Math.ceil(Math.log2(books.length)) : 0;
    for (let j = 0; j < this.choiceBitCount; j++) {
      this.roundSeeds.push({ seed0: randomBytes(32), seed1: randomBytes(32) });
    }
  }

  public start() {
    if (this.choiceBitCount === 0) {
      this.sendFinalSecrets();
    } else {
      this.ws.send(JSON.stringify({ type: 'OT_ROUND_START', payload: { round: 0 } }));
    }
  }

  public processRoundResponse(payload: { round: number, clientPublicKey: string }) {
    const { round, clientPublicKey: clientPublicKeyHex } = payload;
    if (round !== this.currentRound) return this.ws.close(1011, `[OT] 轮次不匹配。`);

    const seeds = this.roundSeeds[round];
    if (!seeds) return this.ws.close(1011, `[OT] 找不到轮次 ${round} 的种子。`);

    try {
      const clientPublicKey = Buffer.from(clientPublicKeyHex, 'hex');
      const serverKeyPair0 = generateServerOtKeyPair();
      const serverKeyPair1 = generateServerOtKeyPair();

      const sharedSecret0 = deriveServerSharedSecret(serverKeyPair0.privateKey, clientPublicKey);
      const sharedSecret1 = deriveServerSharedSecret(serverKeyPair1.privateKey, clientPublicKey);

      const encryptedSeed0 = aesGcmEncrypt(sharedSecret0, seeds.seed0);
      const encryptedSeed1 = aesGcmEncrypt(sharedSecret1, seeds.seed1);

      this.ws.send(JSON.stringify({
        type: 'OT_ROUND_CHALLENGE',
        payload: {
          round,
          g0: Buffer.from(serverKeyPair0.publicKey).toString('hex'),
          g1: Buffer.from(serverKeyPair1.publicKey).toString('hex'),
          e0: encryptedSeed0.toString('hex'),
          e1: encryptedSeed1.toString('hex'),
        }
      }));

      this.currentRound++;
      if (this.currentRound < this.choiceBitCount) {
        this.ws.send(JSON.stringify({ type: 'OT_ROUND_START', payload: { round: this.currentRound } }));
      } else {
        console.log('[OT-SERVER] 所有轮次挑战已发送，等待客户端确认...');
      }
    } catch (err) {
      console.error(`[OT] 处理轮次 ${round} 时出错:`, err);
      this.ws.close(1011, 'OT协议处理失败。');
    }
  }

  public sendFinalSecrets() {
    const numBooks = this.bookSecrets.length;
    const finalEncryptedSecrets: string[] = [];
    for (let i = 0; i < numBooks; i++) {
      const bookSecret = this.bookSecrets[i];
      if (!bookSecret) continue;
      let masterKey = Buffer.alloc(32);
      for (let j = 0; j < this.choiceBitCount; j++) {
        const choiceBit = (i >> j) & 1;
        const seeds = this.roundSeeds[j];
        if (seeds) {
          const seed = choiceBit === 0 ? seeds.seed0 : seeds.seed1;
          for (let k = 0; k < 32; k++) {
            const masterKeyByte = masterKey[k];
            const seedByte = seed[k];
            if (masterKeyByte !== undefined && seedByte !== undefined) {
              masterKey[k] = masterKeyByte ^ seedByte;
            }
          }
        }
      }
      const encryptedSecret = aesGcmEncrypt(masterKey, bookSecret);
      finalEncryptedSecrets.push(encryptedSecret.toString('hex'));
    }
    this.ws.send(JSON.stringify({
      type: 'OT_DELIVER',
      payload: { encryptedSecrets: finalEncryptedSecrets }
    }));
    console.log(`[OT] 已为购买 ${this.ws.protocol} 发送最终加密密钥。`);
  }
}

export const handlePurchaseConnection = (ws: WebSocket, purchaseId: string) => {
  let sessionState = {
    userId: '',
    purchase: null as any,
    otSender: null as SemiHonestOtSender | null,
    books: [] as any[]
  };

  const handleInitLogic = async () => {
    const purchaseResult = await pool.query("SELECT user_id, status, commitment FROM purchases WHERE id = $1 AND user_id = $2", [purchaseId, sessionState.userId]);

    if (purchaseResult.rows.length === 0) {
      return ws.close(1011, '购买记录未找到。');
    }

    const purchase = purchaseResult.rows[0];

    if (purchase.status === 'paid') {
      // 状态正确，正常继续
      sessionState.purchase = purchase;
      ws.send(JSON.stringify({ type: 'ZKP_READY' }));
      return true; // 表示已成功处理
    }

    if (purchase.status !== 'pending') {
      // 如果是其他状态（如 'completed' 或 'failed'），则关闭连接
      return ws.close(1011, `无效的购买状态: ${purchase.status}`);
    }

    // 如果状态是 'pending'，则返回 false，表示需要等待
    return false;
  };

  ws.on('message', async (message: Buffer) => {
    const data = JSON.parse(message.toString());

    switch (data.type) {
      case 'INIT':
        try {
          const decodedPayload = await verifyJwt(data.token, process.env.JWT_SECRET!);
          if (!decodedPayload || typeof decodedPayload.sub !== 'string') return ws.close(1011, '无效的token。');
          sessionState.userId = decodedPayload.sub;

          // 首次尝试处理
          const success = await handleInitLogic();

          // ✅ **核心修复：如果状态是 'pending'，则启动一个简短的轮询器**
          if (!success) {
            console.log(`[WS] 购买 ${purchaseId} 状态为 pending，开始轮询等待 webhook 更新...`);
            let attempts = 0;
            const maxAttempts = 10; // 最多等待10秒
            const interval = setInterval(async () => {
              attempts++;
              const pollSuccess = await handleInitLogic();
              if (pollSuccess || attempts >= maxAttempts) {
                clearInterval(interval);
                if (!pollSuccess) {
                  ws.close(1011, '等待支付状态更新超时。');
                }
              }
            }, 1000); // 每秒检查一次
          }

        } catch (err) {
          console.error('INIT Error:', err);
          ws.close(1011, '身份验证失败。');
        }
        break;

      case 'ZKP_PROVE':
        const { proof, publicSignals } = data.payload;
        if (publicSignals[2] !== sessionState.purchase.commitment) {
          return ws.close(1011, '公开承诺不匹配。');
        }
        const isVerified = await groth16.verify(vkey, publicSignals, proof);
        if (!isVerified) return ws.close(1011, 'ZKP验证失败。');

        try {
          const updateResult = await pool.query("UPDATE purchases SET status = 'verified', nullifier_hash = $1 WHERE id = $2 AND status = 'paid'", [publicSignals[0], purchaseId]);
          if (updateResult.rowCount === 0) return ws.close(1011, '购买记录已被验证或使用。');

          const booksResult = await pool.query('SELECT id, file_key, secret_key FROM books ORDER BY id');
          sessionState.books = booksResult.rows;

          sessionState.otSender = new SemiHonestOtSender(ws, sessionState.books);

          ws.send(JSON.stringify({ type: 'OT_START', payload: { numBooks: sessionState.books.length } }));

        } catch (dbErr: any) {
          if (dbErr.code === '23505') return ws.close(1011, '证明已被使用。');
          ws.close(1011, '数据库终结错误。');
        }
        break;

      case 'OT_ACK_START':
        if (sessionState.otSender) {
          sessionState.otSender.start();
        }
        break;

      case 'OT_ROUND_RESPONSE':
        if (sessionState.otSender) {
          sessionState.otSender.processRoundResponse(data.payload);
        }
        break;

      case 'OT_ROUNDS_COMPLETE':
        if (sessionState.otSender) {
          console.log('[OT-SERVER] 收到客户端的 OT_ROUNDS_COMPLETE 信号，发送最终数据...');
          sessionState.otSender.sendFinalSecrets();
        }
        break;

      case 'REQUEST_SIGNED_URL':
        try {
          const { bookIndex } = data.payload;
          const book = sessionState.books[bookIndex];
          if (!book) return ws.close(1011, '无效的书籍索引。');

          const bucketName = process.env.R2_BUCKET_NAME;
          if (!bucketName) return ws.close(1011, '服务器配置错误。');

          const signedUrl = await getSignedUrl(R2, new GetObjectCommand({ Bucket: bucketName, Key: book.file_key }), { expiresIn: 300 });

          ws.send(JSON.stringify({ type: 'SIGNED_URL', payload: { signedUrl } }));
          console.log(`[流程] 已为购买 ${purchaseId} 发送签名URL。等待客户端确认...`);

        } catch (err) {
          console.error('URL签名错误:', err);
          ws.close(1011, '获取下载链接失败。');
        }
        break;

      case 'DOWNLOAD_READY':
        try {
          await pool.query("UPDATE purchases SET status = 'completed' WHERE id = $1", [purchaseId]);
          console.log(`[流程] 客户端确认下载就绪。购买 ${purchaseId} 已完成。`);

          ws.close(1000, '购买流程成功完成。');

        } catch (dbErr) {
          console.error('数据库最终更新错误:', dbErr);
          ws.close(1011, '数据库终结错误。');
        }
        break;
    }
  });

  ws.on('close', () => console.log(`[WS] 连接已关闭: ${purchaseId}`));
  ws.on('error', (err: Error) => console.error('[WS] 发生错误:', err));
};
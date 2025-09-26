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
import {
  generateServerOtKeyPair,
  deriveServerSharedSecret,
  aesGcmEncrypt,
} from '../ot_crypto.js';

// load ZKP verification key
const vkey = JSON.parse(readFileSync(path.join(process.cwd(), 'zkp', 'verification_key.json'), 'utf-8'));

/**
 * this class manages the complete state of the semi-honest OT protocol for each WebSocket connection
 */
export class SemiHonestOtSender {
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
    if (round !== this.currentRound) return this.ws.close(1011, `[OT] round mismatch.`);

    const seeds = this.roundSeeds[round];
    if (!seeds) return this.ws.close(1011, `[OT] round ${round} seed not found.`);

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
        console.log('[OT-SERVER] all rounds challenges sent, waiting for client confirmation...');
      }
    } catch (err) {
      console.error(`[OT] error processing round ${round}:`, err);
      this.ws.close(1011, 'OT protocol processing failed.');
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
    console.log(`[OT] final encrypted secrets sent for purchase ${this.ws.protocol}.`);
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
      return ws.close(1011, 'purchase record not found.');
    }

    const purchase = purchaseResult.rows[0];

    if (purchase.status === 'paid') {
      // status is correct, continue normally
      sessionState.purchase = purchase;
      ws.send(JSON.stringify({ type: 'ZKP_READY' }));
      return true; // indicate successful processing
    }

    if (purchase.status !== 'pending') {
      // if other status (e.g. 'completed' or 'failed'), close connection
      return ws.close(1011, `invalid purchase status: ${purchase.status}`);
    }

    // if status is 'pending', return false, indicate waiting
    return false;
  };

  ws.on('message', async (message: Buffer) => {
    const data = JSON.parse(message.toString());

    switch (data.type) {
      case 'INIT':
        try {
          const decodedPayload = await verifyJwt(data.token, process.env.JWT_SECRET!);
          if (!decodedPayload || typeof decodedPayload.sub !== 'string') return ws.close(1011, 'invalid token.');
          sessionState.userId = decodedPayload.sub;

          // first attempt to handle
          const success = await handleInitLogic();

          if (!success) {
            console.log(`[WS] purchase ${purchaseId} status is pending, start polling to wait for webhook update...`);
            let attempts = 0;
            const maxAttempts = 10; // maximum wait time is 10 seconds
            const interval = setInterval(async () => {
              attempts++;
              const pollSuccess = await handleInitLogic();
              if (pollSuccess || attempts >= maxAttempts) {
                clearInterval(interval);
                if (!pollSuccess) {
                  ws.close(1011, 'waiting for payment status update timeout.');
                }
              }
            }, 1000); // check every second
          }

        } catch (err) {
          console.error('INIT Error:', err);
          ws.close(1011, 'authentication failed.');
        }
        break;

      case 'ZKP_PROVE':
        const { proof, publicSignals } = data.payload;
        if (publicSignals[2] !== sessionState.purchase.commitment) {
          return ws.close(1011, 'commitment mismatch.');
        }
        const isVerified = await groth16.verify(vkey, publicSignals, proof);
        if (!isVerified) return ws.close(1011, 'ZKP verification failed.');

        try {
          const updateResult = await pool.query("UPDATE purchases SET status = 'verified', nullifier_hash = $1 WHERE id = $2 AND status = 'paid'", [publicSignals[0], purchaseId]);
          if (updateResult.rowCount === 0) return ws.close(1011, 'purchase record has been verified or used.');

          const booksResult = await pool.query('SELECT id, file_key, secret_key FROM books ORDER BY id');
          sessionState.books = booksResult.rows;

          sessionState.otSender = new SemiHonestOtSender(ws, sessionState.books);

          ws.send(JSON.stringify({ type: 'OT_START', payload: { numBooks: sessionState.books.length } }));

        } catch (dbErr: any) {
          if (dbErr.code === '23505') return ws.close(1011, 'proof has been used.');
          ws.close(1011, 'database final update error.');
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
          console.log('[OT-SERVER] received OT_ROUNDS_COMPLETE signal, sending final data...');
          sessionState.otSender.sendFinalSecrets();
        }
        break;

      case 'REQUEST_SIGNED_URL':
        try {
          const { bookIndex } = data.payload;
          const book = sessionState.books[bookIndex];
          if (!book) return ws.close(1011, 'invalid book index.');

          const bucketName = process.env.R2_BUCKET_NAME;
          if (!bucketName) return ws.close(1011, 'server configuration error.');

          const signedUrl = await getSignedUrl(R2, new GetObjectCommand({ Bucket: bucketName, Key: book.file_key }), { expiresIn: 300 });

          ws.send(JSON.stringify({ type: 'SIGNED_URL', payload: { signedUrl } }));
          console.log(`[process] sent signed URL for purchase ${purchaseId}. waiting for client confirmation...`);

        } catch (err) {
          console.error('URL signing error:', err);
          ws.close(1011, 'failed to get download link.');
        }
        break;

      case 'DOWNLOAD_READY':
        try {
          await pool.query("UPDATE purchases SET status = 'completed' WHERE id = $1", [purchaseId]);
            console.log(`[process] client confirmed download ready. purchase ${purchaseId} completed.`);

          ws.close(1000, 'purchase process completed.');

        } catch (dbErr) {
          console.error('database final update error:', dbErr);
          ws.close(1011, 'database final update error.');
        }
        break;
    }
  });

  ws.on('close', () => console.log(`[WS] 连接已关闭: ${purchaseId}`));
  ws.on('error', (err: Error) => console.error('[WS] 发生错误:', err));
};
import { Hono } from 'hono';
import pool from '../db.js';
import Stripe from 'stripe';
import type { JwtPayload } from '../auth.js';

const orders = new Hono<{ Variables: { jwtPayload: JwtPayload } }>();

orders.post('/', async (c) => {
  try {
    const { commitmentHash, priceInCents } = await c.req.json<{ commitmentHash: string, priceInCents: number }>();
    const userId = c.get('jwtPayload').sub;

    if (!commitmentHash || !priceInCents) {
      return c.json({ error: 'commitmentHash and priceInCents are required' }, 400);
    }

    // 价格有效性检查 (此项检查仍然非常重要，用于防止用户支付任意金额)
    const priceCheckResult = await pool.query(
      'SELECT 1 FROM books WHERE price_cents = $1 LIMIT 1',
      [priceInCents]
    );

    if (priceCheckResult.rowCount === 0) {
      return c.json({ error: 'Invalid payment amount' }, 400);
    }

    // 支付逻辑 (保持不变)
    const stripe = new Stripe(process.env.STRIPE_API_KEY!);
    const paymentIntent = await stripe.paymentIntents.create({
      amount: priceInCents,
      currency: 'usd',
      metadata: { userId },
    });

    // --- 关键修改: 从 INSERT 语句中移除 amount_paid_cents ---
    // 假设您的数据库 purchases 表已删除了 amount_paid_cents 列
    const orderResult = await pool.query(
      'INSERT INTO purchases (user_id, stripe_payment_intent_id, commitment) VALUES ($1, $2, $3) RETURNING id',
      [userId, paymentIntent.id, commitmentHash] // <-- 只传递3个参数
    );
    const newPurchaseId = orderResult.rows[0].id;
    
    return c.json({
      orderId: newPurchaseId,
      clientSecret: paymentIntent.client_secret
    });

  } catch (err) {
    console.error('Error creating order:', err);
    return c.json({ error: 'Failed to create order' }, 500);
  }
});

export default orders;
    


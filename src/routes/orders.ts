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

    // price validity check
    const priceCheckResult = await pool.query(
      'SELECT 1 FROM books WHERE price_cents = $1 LIMIT 1',
      [priceInCents]
    );

    if (priceCheckResult.rowCount === 0) {
      return c.json({ error: 'Invalid payment amount' }, 400);
    }

    // payment logic
    const stripe = new Stripe(process.env.STRIPE_API_KEY!);
    const paymentIntent = await stripe.paymentIntents.create({
      amount: priceInCents,
      currency: 'usd',
      metadata: { userId },
    });

    const orderResult = await pool.query(
      'INSERT INTO purchases (user_id, stripe_payment_intent_id, commitment) VALUES ($1, $2, $3) RETURNING id',
      [userId, paymentIntent.id, commitmentHash] 
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
    


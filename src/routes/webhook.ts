import { Hono } from 'hono';
import { HTTPException } from 'hono/http-exception';
import Stripe from 'stripe';
import pool from '../db.js';

const stripe = new Stripe(process.env.STRIPE_API_KEY!);
const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET!;

const webhook = new Hono();

// Hono will parse JSON by default, so we need c.req.text() to get the raw text.
webhook.post('/stripe', async (c) => {
  const signature = c.req.header('stripe-signature');
  const rawBody = await c.req.text(); // get the raw text body

  if (!signature) {
    throw new HTTPException(400, { message: 'stripe-signature header is missing' });
  }

  let event: Stripe.Event;

  try {
    // 1. verify the signature, ensure the request is from Stripe and not forged
    event = stripe.webhooks.constructEvent(rawBody, signature, webhookSecret);
  } catch (err: any) {
    console.error(`Webhook signature verification failed:`, err.message);
    throw new HTTPException(400, { message: `Webhook error: ${err.message}` });
  }

  // 2. payment_intent.succeeded (payment intent succeeded)
  if (event.type === 'payment_intent.succeeded') {
    const paymentIntent = event.data.object as Stripe.PaymentIntent;
    const paymentIntentId = paymentIntent.id;

    console.log(`Webhook received: payment succeeded (ID: ${paymentIntentId})`);

    try {
      // 3. find the corresponding purchases record and update the status
      const result = await pool.query(
        "UPDATE purchases SET status = 'paid' WHERE stripe_payment_intent_id = $1 AND status = 'pending' RETURNING id",
        [paymentIntentId]
      );

      if (result.rowCount === 0) {
        console.warn(`Webhook warning: no matching 'pending' purchase record found (ID: ${paymentIntentId}). It may have been processed.`);
      } else {
        console.log(`database update: purchase ${result.rows[0].id} status set to 'paid'`);
      }

    } catch (dbErr) {
        console.error(`Webhook database update failed (ID: ${paymentIntentId}):`, dbErr);
      // return 500 error, Stripe will retry this Webhook later
      throw new HTTPException(500, { message: 'database update failed' });
    }
  } else {
    console.log(`Webhook received unprocessed event type: ${event.type}`);
  }

  // 4. return 200 OK to Stripe, prevent Stripe from sending it again
  return c.json({ received: true });
});

export default webhook;
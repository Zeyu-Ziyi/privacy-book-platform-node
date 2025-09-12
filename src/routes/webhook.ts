import { Hono } from 'hono';
import { HTTPException } from 'hono/http-exception';
import Stripe from 'stripe';
import pool from '../db.js';

// Stripe 客户端实例 (您也可以从一个共享的 stripe.ts 文件中导入，如果有的话)
const stripe = new Stripe(process.env.STRIPE_API_KEY!);
const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET!;

const webhook = new Hono();

// Stripe Webhook 端点。它必须能够接收原始请求体 (raw body) 用于签名验证。
// Hono 默认会解析 JSON，所以我们需要 c.req.text() 来获取原始文本。
webhook.post('/stripe', async (c) => {
  const signature = c.req.header('stripe-signature');
  const rawBody = await c.req.text(); // 获取原始文本正文

  if (!signature) {
    throw new HTTPException(400, { message: '缺少 stripe-signature 标头' });
  }

  let event: Stripe.Event;

  try {
    // 1. 验证签名，确保请求来自 Stripe 而不是伪造的
    event = stripe.webhooks.constructEvent(rawBody, signature, webhookSecret);
  } catch (err: any) {
    console.error(`Webhook 签名验证失败:`, err.message);
    throw new HTTPException(400, { message: `Webhook 错误: ${err.message}` });
  }

  // 2. 处理我们关心的事件：payment_intent.succeeded (支付意图成功)
  if (event.type === 'payment_intent.succeeded') {
    const paymentIntent = event.data.object as Stripe.PaymentIntent;
    const paymentIntentId = paymentIntent.id;

    console.log(`Webhook 收到: 支付成功 (ID: ${paymentIntentId})`);

    try {
      // 3. 这是关键步骤：找到对应的 purchases 记录并更新状态
      const result = await pool.query(
        "UPDATE purchases SET status = 'paid' WHERE stripe_payment_intent_id = $1 AND status = 'pending' RETURNING id",
        [paymentIntentId]
      );

      if (result.rowCount === 0) {
        // 这可能是因为我们没有找到该 ID，或者它已经被处理过了 (不再是 'pending')
        console.warn(`Webhook 警告: 未找到匹配的 'pending' 购买记录 (ID: ${paymentIntentId})。可能已被处理。`);
      } else {
        console.log(`数据库更新：购买 ${result.rows[0].id} 状态已设为 'paid'`);
      }

    } catch (dbErr) {
      console.error(`Webhook 数据库更新失败 (ID: ${paymentIntentId}):`, dbErr);
      // 返回 500 错误，Stripe 会在稍后重试此 Webhook
      throw new HTTPException(500, { message: '数据库更新失败' });
    }
  } else {
    // 处理其他您可能关心的事件 (例如 .failed)，或者忽略它们
    console.log(`Webhook 收到未处理的事件类型: ${event.type}`);
  }

  // 4. 向 Stripe 返回 200 OK，告知我们已成功收到，防止 Stripe 重复发送。
  return c.json({ received: true });
});

export default webhook;
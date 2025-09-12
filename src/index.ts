import { Hono } from 'hono'
import { serve } from '@hono/node-server'
import { cors } from 'hono/cors'
import { WebSocketServer } from 'ws'

import users from './routes/users.js'
import books from './routes/books.js'
import orders from './routes/orders.js'
import auth from './auth.js'
import webhookRoutes from './routes/webhook.js'
import { parse } from 'url'
import { handlePurchaseConnection } from './routes/purchase.js'

const startServer = async () => {
  const app = new Hono()

  app.use('*', cors({
    origin: 'http://localhost:5173',
    allowHeaders: ['Content-Type', 'Authorization'],
    allowMethods: ['POST', 'GET', 'OPTIONS'],
    credentials: true,
  }))

  app.get('/', (c) => c.text('欢迎来到隐私保护书店 API!'))

  // HTTP 路由
  app.route('/users', users)
  app.route('/books', books)
  app.route('/webhooks', webhookRoutes)

  const api = new Hono()
  api.route('/orders', orders)
  app.route('/api', auth)
  app.route('/api', api)

  const port = parseInt(process.env.PORT || '3000')
  const server = serve({
    fetch: app.fetch,
    port,
  })

  console.log(`🚀 服务器运行在 http://localhost:${port}`)

  // --- ✅ 新增 WebSocket 处理 ---
  const wss = new WebSocketServer({ server: server as any })

  wss.on('connection', (ws, req) => {
    const { pathname } = parse(req.url || '', true);
    const match = pathname?.match(/^\/ws\/api\/purchase\/(.+)/);
    
    if (match && match[1]) {
      const purchaseId = match[1];
      // 如果路径匹配，将连接和 purchaseId 交给我们的专用处理函数
      handlePurchaseConnection(ws, purchaseId);
    } else {
      // 如果路径不匹配，立即关闭连接
      ws.close(1011, 'Invalid WebSocket endpoint');
    }
  })
}

startServer()

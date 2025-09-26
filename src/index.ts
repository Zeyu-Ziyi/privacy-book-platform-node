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

  app.get('/', (c) => c.text('Welcome to the privacy-preserving bookstore API!'))

  // HTTP routes
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

  console.log(`🚀 server running at http://localhost:${port}`)

  const wss = new WebSocketServer({ server: server as any })

  wss.on('connection', (ws, req) => {
    const { pathname } = parse(req.url || '', true);
    const match = pathname?.match(/^\/ws\/api\/purchase\/(.+)/);
    
    if (match && match[1]) {
      const purchaseId = match[1];
      // if the path matches, pass the connection and purchaseId to our dedicated handler
      handlePurchaseConnection(ws, purchaseId);
    } else {
      // if the path doesn't match, close the connection immediately
      ws.close(1011, 'Invalid WebSocket endpoint');
    }
  })
}

startServer()

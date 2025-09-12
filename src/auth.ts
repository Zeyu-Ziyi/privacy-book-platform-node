// src/auth.ts
import { Hono } from 'hono';
import { jwt } from 'hono/jwt';
import { HTTPException } from 'hono/http-exception';

// 定义我们期望从JWT负载中得到的类型
// 我们在登录时将 userId 存放在了 'sub' 字段中
export type JwtPayload = {
  sub: string; // User ID (UUID)
  username: string;
  exp: number;
};

// 扩展 Hono 的上下文类型，以便在后续处理程序中能方便地访问 jwtPayload
type AuthVariables = {
  jwtPayload: JwtPayload;
};

const auth = new Hono<{ Variables: AuthVariables }>();

// 使用 hono/jwt 中间件
auth.use('*', async (c, next) => {
  const jwtMiddleware = jwt({
    secret: process.env.JWT_SECRET!,
  });
  // 在下一个处理程序之前执行JWT中间件
  return jwtMiddleware(c, next);
});

// 这是一个可选的额外中间件，用于检查负载是否存在
// hono/jwt 在验证失败时会自动抛出错误，但多一层检查更稳妥
auth.use('*', async (c, next) => {
  const payload = c.get('jwtPayload');
  if (!payload || !payload.sub) {
    throw new HTTPException(401, { message: 'Unauthorized: Invalid token payload' });
  }
  await next();
});

export default auth;
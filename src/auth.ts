// src/auth.ts
import { Hono } from 'hono';
import { jwt } from 'hono/jwt';
import { HTTPException } from 'hono/http-exception';

// define the type we expect from the JWT payload
// store the userId in the 'sub' field when logging in
export type JwtPayload = {
  sub: string; // User ID (UUID)
  username: string;
  exp: number;
};

// extend the Hono context type, so we can easily access jwtPayload in subsequent handlers
type AuthVariables = {
  jwtPayload: JwtPayload;
};

const auth = new Hono<{ Variables: AuthVariables }>();

// use hono/jwt middleware
auth.use('*', async (c, next) => {
  const jwtMiddleware = jwt({
    secret: process.env.JWT_SECRET!,
  });
  // execute JWT middleware before the next handler
  return jwtMiddleware(c, next);
});

// hono/jwt will automatically throw an error when validation fails, but an extra check is more reliable
auth.use('*', async (c, next) => {
  const payload = c.get('jwtPayload');
  if (!payload || !payload.sub) {
    throw new HTTPException(401, { message: 'Unauthorized: Invalid token payload' });
  }
  await next();
});

export default auth;
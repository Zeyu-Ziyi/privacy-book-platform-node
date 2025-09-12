// src/routes/users.ts
import { Hono } from 'hono';
import { sign } from 'hono/jwt';
import bcrypt from 'bcrypt';
import pool from '../db.js'; // 导入我们的 pg 连接池

const users = new Hono<{ Bindings: { JWT_SECRET: string } }>();

// 1. 用户注册 (使用 email)
users.post('/register', async (c) => {
    try {
        // --- SQL MODIFICATION: 'username' -> 'email' ---
        const { email, password } = await c.req.json();
        if (!email || !password || password.length < 8) {
            return c.json({ error: '邮箱和密码为必填项，且密码长度至少8位' }, 400);
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        // --- SQL MODIFICATION: 'username' -> 'email' ---
        const result = await pool.query(
            'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email, created_at',
            [email, hashedPassword]
        );

        return c.json({ user: result.rows[0] }, 201);
    } catch (err: any) {
        if (err.code === '23505') { // unique_violation
            return c.json({ error: '此邮箱已存在' }, 409); // --- MODIFICATION: 消息更新 ---
        }
        console.error(err);
        return c.json({ error: '注册失败，服务器内部错误' }, 500);
    }
});

// 2. 用户登录 (使用 email)
users.post('/login', async (c) => {
    try {
        // --- SQL MODIFICATION: 'username' -> 'email' ---
        const { email, password } = await c.req.json();
        if (!email || !password) {
            return c.json({ error: '邮箱和密码为必填项' }, 400);
        }

        // --- SQL MODIFICATION: 'username' -> 'email' ---
        const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (rows.length === 0) {
            return c.json({ error: '无效的邮箱或密码' }, 401); // --- MODIFICATION: 消息更新 ---
        }

        const user = rows[0];
        const passwordMatch = await bcrypt.compare(password, user.password_hash);

        if (!passwordMatch) {
            return c.json({ error: '无效的邮箱或密码' }, 401);
        }

        const payload = {
            sub: user.id, // 'sub' (subject) 是标准的JWT声明，代表用户ID
            email: user.email, // --- MODIFICATION: 'username' -> 'email' ---
            exp: Math.floor(Date.now() / 1000) + (60 * 60 * 24) // 令牌24小时后过期
        };
        const secret = process.env.JWT_SECRET!;
        const token = await sign(payload, secret);

        return c.json({ token });
    } catch (err: any) {
        console.error(err);
        return c.json({ error: '登录失败，服务器内部错误' }, 500);
    }
});

export default users;
// src/routes/users.ts
import { Hono } from 'hono';
import { sign } from 'hono/jwt';
import bcrypt from 'bcrypt';
import pool from '../db.js';

const users = new Hono<{ Bindings: { JWT_SECRET: string } }>();

// 1. user registration (using email)
users.post('/register', async (c) => {
    try {
        const { email, password } = await c.req.json();
        if (!email || !password || password.length < 8) {
            return c.json({ error: 'email and password are required, and password must be at least 8 characters long' }, 400);
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const result = await pool.query(
            'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email, created_at',
            [email, hashedPassword]
        );

        return c.json({ user: result.rows[0] }, 201);
    } catch (err: any) {
        if (err.code === '23505') { // unique_violation
            return c.json({ error: 'this email already exists' }, 409);
        }
        console.error(err);
        return c.json({ error: 'registration failed, server internal error' }, 500);
    }
});

// 2. user login (using email)
users.post('/login', async (c) => {
    try {
        const { email, password } = await c.req.json();
        if (!email || !password) {
            return c.json({ error: 'email and password are required' }, 400);
        }

        const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (rows.length === 0) {
            return c.json({ error: 'invalid email or password' }, 401);
        }

        const user = rows[0];
        const passwordMatch = await bcrypt.compare(password, user.password_hash);

        if (!passwordMatch) {
            return c.json({ error: 'invalid email or password' }, 401);
        }

        const payload = {
            sub: user.id, // 'sub' (subject) is the standard JWT claim, representing user ID
            email: user.email,
            exp: Math.floor(Date.now() / 1000) + (60 * 60 * 24) // token expires in 24 hours
        };
        const secret = process.env.JWT_SECRET!;
        const token = await sign(payload, secret);

        return c.json({ token });
    } catch (err: any) {
        console.error(err);
        return c.json({ error: 'login failed, server internal error' }, 500);
    }
});

export default users;
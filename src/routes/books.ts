// src/routes/books.ts
import { Hono } from 'hono';
import pool from '../db.js';

const books = new Hono();

// GET /books - 获取所有书籍列表
books.get('/', async (c) => {
  try {
    // --- SQL MODIFICATION: 'price_in_cents' -> 'price_cents' ---
    // (我们假设您已将 description 和 cover_image_url 添加到您的 books 表中，因为它们是合理的公共字段)
    const result = await pool.query(
      'SELECT id, title, author, description, price_cents FROM books'
    );
    return c.json(result.rows);
  } catch (err) {
    console.error('Error fetching books:', err);
    return c.json({ error: 'Failed to fetch books' }, 500);
  }
});

export default books;
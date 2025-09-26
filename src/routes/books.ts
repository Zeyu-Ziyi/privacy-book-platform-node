// src/routes/books.ts
import { Hono } from 'hono';
import pool from '../db.js';
import { HTTPException } from 'hono/http-exception';

const books = new Hono();

// GET /books - get all books
books.get('/', async (c) => {
  const { query, type } = c.req.query();
  try {
    let sqlQuery = 'SELECT id, title, author, description, price_cents FROM books';
    const params = [];

    if (query) {
      if (type === 'title' || type === 'author') {
        sqlQuery += ` WHERE ${type} ILIKE $1`;
        params.push(`%${query}%`);
      } else {
        sqlQuery += ` WHERE title ILIKE $1 OR author ILIKE $1`;
        params.push(`%${query}%`);
      }
    }

    const result = await pool.query(sqlQuery, params);
    return c.json(result.rows);
  } catch (err) {
    console.error('Error fetching books:', err);
    return c.json({ error: 'Failed to fetch books' }, 500);
  }
});

// GET /books/:id - get a book by id
books.get('/:id', async (c) => {
  const { id } = c.req.param();

  // basic UUID format validation
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  if (!uuidRegex.test(id)) {
      return c.json({ error: 'Invalid book ID format' }, 400);
  }
  
  try {
    const result = await pool.query(
      'SELECT id, title, author, description, price_cents FROM books WHERE id = $1',
      [id]
    );

    // if no book is found, return 404 Not Found
    if (result.rows.length === 0) {
      throw new HTTPException(404, { message: 'Book not found' });
    }

    return c.json(result.rows[0]);
  } catch (err) {
    // catch 404 error and return correctly
    if (err instanceof HTTPException) {
        return err.getResponse();
    }
    console.error(`Error fetching book with id ${id}:`, err);
    return c.json({ error: 'Failed to fetch book' }, 500);
  }
});


export default books;
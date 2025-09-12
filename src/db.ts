// src/db.ts
import { Pool } from 'pg';
import 'dotenv/config';

console.log(process.env.DATABASE_URL);

const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

pool.on('connect', () => {
  console.log('Successfully connected to the database');
});

export default pool;
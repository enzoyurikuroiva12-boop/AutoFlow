import { DatabaseSync } from 'node:sqlite';
import { Pool } from 'pg';
import { mkdirSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const schema = readFileSync(resolve(root, 'migrations/001_init.sql'), 'utf8');

function placeholders(sql) {
  let i = 0;
  return sql.replace(/\?/g, () => `$${++i}`);
}

export function createDatabase(env = process.env) {
  if (env.DATABASE_URL) {
    const pool = new Pool({ connectionString: env.DATABASE_URL, ssl: env.PGSSL === 'true' ? { rejectUnauthorized: true } : undefined });
    return {
      kind: 'postgres',
      async migrate() { for (const statement of schema.split(';').map((s) => s.trim()).filter(Boolean)) await pool.query(statement); },
      async get(sql, ...params) { return (await pool.query(placeholders(sql), params)).rows[0] ?? null; },
      async all(sql, ...params) { return (await pool.query(placeholders(sql), params)).rows; },
      async run(sql, ...params) { return pool.query(placeholders(sql), params); },
      async transaction(fn) {
        const client = await pool.connect();
        try {
          await client.query('BEGIN');
          const tx = {
            get: async (sql, ...params) => (await client.query(placeholders(sql), params)).rows[0] ?? null,
            all: async (sql, ...params) => (await client.query(placeholders(sql), params)).rows,
            run: async (sql, ...params) => client.query(placeholders(sql), params),
          };
          const value = await fn(tx);
          await client.query('COMMIT');
          return value;
        } catch (error) { await client.query('ROLLBACK'); throw error; }
        finally { client.release(); }
      },
      async close() { await pool.end(); },
    };
  }

  const path = env.DB_PATH === ':memory:' ? ':memory:' : resolve(env.DB_PATH || resolve(root, '.data/autoflow.sqlite'));
  if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true });
  const sqlite = new DatabaseSync(path);
  sqlite.exec('PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000;');
  const db = {
    kind: 'sqlite',
    async migrate() { for (const statement of schema.split(';').map((s) => s.trim()).filter(Boolean)) sqlite.exec(statement); },
    async get(sql, ...params) { return sqlite.prepare(sql).get(...params) ?? null; },
    async all(sql, ...params) { return sqlite.prepare(sql).all(...params); },
    async run(sql, ...params) { return sqlite.prepare(sql).run(...params); },
    async transaction(fn) {
      sqlite.exec('BEGIN IMMEDIATE');
      try {
        const value = await fn(db);
        sqlite.exec('COMMIT');
        return value;
      } catch (error) { sqlite.exec('ROLLBACK'); throw error; }
    },
    async close() { sqlite.close(); },
  };
  return db;
}

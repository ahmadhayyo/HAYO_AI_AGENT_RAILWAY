import { drizzle as drizzlePg } from "drizzle-orm/node-postgres";
import { drizzle as drizzleSqlite } from "drizzle-orm/better-sqlite3";
import pg from "pg";
import Database from "better-sqlite3";
import * as schema from "./schema";
import path from "path";
import fs from "fs";

const { Pool } = pg;

// التحقق من نوع قاعدة البيانات المتاحة
const databaseUrl = process.env.DATABASE_URL;

export let db: any;
export let pool: any = null;

if (databaseUrl && databaseUrl.startsWith("postgres")) {
  // استخدام PostgreSQL إذا كان الرابط متاحاً
  console.log("🗄️ Using PostgreSQL Database");
  // Enable SSL for Railway/cloud PostgreSQL (rejectUnauthorized:false allows self-signed certs)
  const isLocalDb = databaseUrl.includes("localhost") || databaseUrl.includes("127.0.0.1");
  pool = new Pool({
    connectionString: databaseUrl,
    ssl: isLocalDb ? false : { rejectUnauthorized: false },
  });
  db = drizzlePg(pool, { schema });
} else if (process.env.NODE_ENV === "production") {
  // The schema is PostgreSQL-only (pgEnum/serial/jsonb/timestamp), so the SQLite
  // path cannot actually serve it. Fail loudly in production rather than booting
  // into a silently-broken state.
  throw new Error(
    "[Database] DATABASE_URL must be a PostgreSQL connection string in production. " +
      "SQLite is not compatible with this schema.",
  );
} else {
  // Local dev convenience only — the pg-only schema will not migrate here.
  console.warn("📁 Using SQLite (DEV fallback) — schema is PostgreSQL-only; most tables will not work.");
  const sqlitePath = path.resolve(process.cwd(), "hayo-ai.db");
  const sqlite = new Database(sqlitePath);
  db = drizzleSqlite(sqlite, { schema });
}

export * from "./schema";

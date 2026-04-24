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
  pool = new Pool({ connectionString: databaseUrl });
  db = drizzlePg(pool, { schema });
} else {
  // استخدام SQLite كخيار احتياطي لضمان عمل المشروع دائماً
  console.log("📁 Using SQLite Database (Local Fallback)");
  const sqlitePath = path.resolve(process.cwd(), "hayo-ai.db");
  const sqlite = new Database(sqlitePath);
  db = drizzleSqlite(sqlite, { schema });
}

export * from "./schema";

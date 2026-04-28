import { defineConfig } from "drizzle-kit";
import { fileURLToPath } from "url";
import path from "path";

// ESM-compatible __dirname (lib/db is "type": "module")
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL, ensure the database is provisioned");
}

export default defineConfig({
  schema: path.join(__dirname, "./src/schema/index.ts"),
  dialect: "postgresql",
  dbCredentials: {
    url: process.env.DATABASE_URL,
  },
  verbose: false,
  strict: false,
});

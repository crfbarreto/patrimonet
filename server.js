const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");

const app = express();
const port = process.env.PORT || 10000;

app.use(cors({
  origin: [
    "https://patrimonet-app.onrender.com",
    "https://patrimonet.onrender.com"
  ],
  methods: ["GET", "PUT", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type"]
}));
app.use(express.json({ limit: "10mb" }));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && !process.env.DATABASE_URL.includes("localhost")
    ? { rejectUnauthorized: false }
    : false
});

async function init() {
  if (!process.env.DATABASE_URL) {
    console.warn("DATABASE_URL ainda não configurada.");
    return;
  }
  await pool.query(`
    CREATE TABLE IF NOT EXISTS app_storage (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  console.log("Banco inicializado.");
}

app.get("/health", async (req, res) => {
  if (!process.env.DATABASE_URL) {
    return res.status(503).json({ ok: false, database: "not_configured" });
  }
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true, database: "connected" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ ok: false, database: "error" });
  }
});

app.get("/api/storage/:key", async (req, res) => {
  if (!process.env.DATABASE_URL) return res.status(503).json({ error: "database_not_configured" });
  try {
    const result = await pool.query("SELECT value FROM app_storage WHERE key = $1", [req.params.key]);
    if (!result.rowCount) return res.status(404).json({ found: false });
    res.json({ found: true, value: result.rows[0].value });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "database_error" });
  }
});

app.put("/api/storage/:key", async (req, res) => {
  if (!process.env.DATABASE_URL) return res.status(503).json({ error: "database_not_configured" });
  const { value } = req.body || {};
  if (typeof value !== "string") return res.status(400).json({ error: "value_must_be_string" });
  try {
    await pool.query(
      `INSERT INTO app_storage (key, value, updated_at)
       VALUES ($1, $2, NOW())
       ON CONFLICT (key)
       DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`,
      [req.params.key, value]
    );
    res.json({ ok: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "database_error" });
  }
});

app.get("/", (req, res) => {
  res.json({ service: "PatrimoNet API", status: "online" });
});

init().catch((error) => {
  console.error("Falha ao inicializar banco:", error);
});

app.listen(port, "0.0.0.0", () => {
  console.log(`PatrimoNet API ouvindo na porta ${port}`);
});

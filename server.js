const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const fs = require("fs");
const path = require("path");

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

  const migrationKey = "migration:2026-10-06-planilha-oficial-v1";
  const migration = await pool.query("SELECT value FROM app_storage WHERE key = $1", [migrationKey]);

  if (!migration.rowCount) {
    const seedPath = path.join(__dirname, "seed-data.json");
    const seed = JSON.parse(fs.readFileSync(seedPath, "utf8"));

    await pool.query("BEGIN");
    try {
      await pool.query(
        `INSERT INTO app_storage (key, value, updated_at)
         VALUES ('postos', $1, NOW())
         ON CONFLICT (key)
         DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`,
        [JSON.stringify(seed.postos)]
      );

      await pool.query(
        `INSERT INTO app_storage (key, value, updated_at)
         VALUES ('equipamentos', $1, NOW())
         ON CONFLICT (key)
         DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`,
        [JSON.stringify(seed.equipamentos)]
      );

      await pool.query(
        `INSERT INTO app_storage (key, value, updated_at)
         VALUES ($1, $2, NOW())
         ON CONFLICT (key)
         DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`,
        [migrationKey, JSON.stringify({
          appliedAt: new Date().toISOString(),
          source: seed.version,
          postos: seed.postos.length,
          equipamentos: seed.equipamentos.length
        })]
      );

      await pool.query("COMMIT");
      console.log(`Migração da planilha aplicada: ${seed.postos.length} postos e ${seed.equipamentos.length} equipamentos.`);
    } catch (error) {
      await pool.query("ROLLBACK");
      throw error;
    }
  } else {
    console.log("Migração da planilha já aplicada anteriormente.");
  }
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

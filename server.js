const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const fs = require("fs");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
const port = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || "development-only-change-me";

app.use(cors({
  origin: [
    "https://patrimonet-app.onrender.com",
    "https://patrimonet.onrender.com"
  ],
  methods: ["GET", "PUT", "POST", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));
app.use(express.json({ limit: "10mb" }));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && !process.env.DATABASE_URL.includes("localhost")
    ? { rejectUnauthorized: false }
    : false
});

function publicUser(row) {
  return {
    id: row.id,
    nome: row.nome,
    email: row.email,
    role: row.role,
    ativo: row.ativo,
    createdAt: row.created_at
  };
}

function makeToken(user) {
  return jwt.sign(
    { sub: user.id, nome: user.nome, email: user.email, role: user.role },
    JWT_SECRET,
    { expiresIn: "12h" }
  );
}

async function authRequired(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token) return res.status(401).json({ error: "unauthorized" });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const result = await pool.query(
      "SELECT id, nome, email, role, ativo, created_at FROM users WHERE id = $1",
      [decoded.sub]
    );
    if (!result.rowCount || !result.rows[0].ativo) {
      return res.status(401).json({ error: "unauthorized" });
    }
    req.user = publicUser(result.rows[0]);
    next();
  } catch (error) {
    return res.status(401).json({ error: "unauthorized" });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ error: "forbidden" });
    }
    next();
  };
}

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

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      nome TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('admin','operator','viewer')),
      ativo BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  console.log("Banco inicializado.");

  const migrationKey = "migration:2026-10-06-planilha-oficial-v1";
  const migration = await pool.query("SELECT value FROM app_storage WHERE key = $1", [migrationKey]);

  if (!migration.rowCount) {
    const seedPath = path.join(__dirname, "seed-data.json");
    if (fs.existsSync(seedPath)) {
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
    }
  } else {
    console.log("Migração da planilha já aplicada anteriormente.");
  }
}

app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true, database: "connected" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ ok: false, database: "error" });
  }
});

app.get("/api/auth/status", async (req, res) => {
  try {
    const result = await pool.query("SELECT COUNT(*)::int AS total FROM users");
    res.json({ needsSetup: result.rows[0].total === 0 });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "database_error" });
  }
});

app.post("/api/auth/setup", async (req, res) => {
  const { nome, email, password } = req.body || {};
  if (!nome || !email || !password || String(password).length < 8) {
    return res.status(400).json({ error: "invalid_input" });
  }
  try {
    const count = await pool.query("SELECT COUNT(*)::int AS total FROM users");
    if (count.rows[0].total > 0) return res.status(409).json({ error: "setup_already_done" });

    const hash = await bcrypt.hash(String(password), 12);
    const result = await pool.query(
      `INSERT INTO users (nome, email, password_hash, role)
       VALUES ($1, LOWER($2), $3, 'admin')
       RETURNING id, nome, email, role, ativo, created_at`,
      [String(nome).trim(), String(email).trim(), hash]
    );
    const user = publicUser(result.rows[0]);
    res.json({ token: makeToken(user), user });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "database_error" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body || {};
  try {
    const result = await pool.query(
      "SELECT id, nome, email, password_hash, role, ativo, created_at FROM users WHERE email = LOWER($1)",
      [String(email || "").trim()]
    );
    if (!result.rowCount || !result.rows[0].ativo) {
      return res.status(401).json({ error: "invalid_credentials" });
    }
    const ok = await bcrypt.compare(String(password || ""), result.rows[0].password_hash);
    if (!ok) return res.status(401).json({ error: "invalid_credentials" });

    const user = publicUser(result.rows[0]);
    res.json({ token: makeToken(user), user });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "database_error" });
  }
});

app.get("/api/auth/me", authRequired, async (req, res) => {
  res.json({ user: req.user });
});

app.get("/api/users", authRequired, requireRole("admin"), async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, nome, email, role, ativo, created_at FROM users ORDER BY nome"
    );
    res.json({ users: result.rows.map(publicUser) });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "database_error" });
  }
});

app.post("/api/users", authRequired, requireRole("admin"), async (req, res) => {
  const { nome, email, password, role } = req.body || {};
  if (!nome || !email || !password || String(password).length < 8 || !["admin","operator","viewer"].includes(role)) {
    return res.status(400).json({ error: "invalid_input" });
  }
  try {
    const hash = await bcrypt.hash(String(password), 12);
    const result = await pool.query(
      `INSERT INTO users (nome, email, password_hash, role)
       VALUES ($1, LOWER($2), $3, $4)
       RETURNING id, nome, email, role, ativo, created_at`,
      [String(nome).trim(), String(email).trim(), hash, role]
    );
    res.json({ user: publicUser(result.rows[0]) });
  } catch (error) {
    if (error.code === "23505") return res.status(409).json({ error: "email_exists" });
    console.error(error);
    res.status(500).json({ error: "database_error" });
  }
});

app.patch("/api/users/:id", authRequired, requireRole("admin"), async (req, res) => {
  const { role, ativo, password } = req.body || {};
  if (role !== undefined && !["admin","operator","viewer"].includes(role)) {
    return res.status(400).json({ error: "invalid_role" });
  }
  try {
    const targetId = Number(req.params.id);
    if (targetId === Number(req.user.id) && ativo === false) {
      return res.status(400).json({ error: "cannot_disable_self" });
    }

    if (role !== undefined) {
      await pool.query("UPDATE users SET role = $1 WHERE id = $2", [role, targetId]);
    }
    if (ativo !== undefined) {
      await pool.query("UPDATE users SET ativo = $1 WHERE id = $2", [Boolean(ativo), targetId]);
    }
    if (password !== undefined) {
      if (String(password).length < 8) return res.status(400).json({ error: "weak_password" });
      const hash = await bcrypt.hash(String(password), 12);
      await pool.query("UPDATE users SET password_hash = $1 WHERE id = $2", [hash, targetId]);
    }

    const result = await pool.query(
      "SELECT id, nome, email, role, ativo, created_at FROM users WHERE id = $1",
      [targetId]
    );
    if (!result.rowCount) return res.status(404).json({ error: "not_found" });
    res.json({ user: publicUser(result.rows[0]) });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "database_error" });
  }
});

app.get("/api/storage/:key", authRequired, async (req, res) => {
  try {
    const result = await pool.query("SELECT value FROM app_storage WHERE key = $1", [req.params.key]);
    if (!result.rowCount) return res.status(404).json({ found: false });
    res.json({ found: true, value: result.rows[0].value });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "database_error" });
  }
});

app.put("/api/storage/:key", authRequired, requireRole("admin", "operator"), async (req, res) => {
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

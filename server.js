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

function stringifyAuditValue(value) {
  if (value === undefined) return null;
  if (value === null) return null;
  if (typeof value === "string") return value;
  try { return JSON.stringify(value); } catch { return String(value); }
}

async function addAudit({
  user,
  entityType,
  entityId = null,
  entityLabel = null,
  action,
  field = null,
  before = null,
  after = null,
  metadata = null
}) {
  await pool.query(
    `INSERT INTO audit_logs
      (user_id, user_name, user_email, entity_type, entity_id, entity_label, action, field_name, before_value, after_value, metadata)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
    [
      user?.id || null,
      user?.nome || "Sistema",
      user?.email || null,
      entityType,
      entityId != null ? String(entityId) : null,
      entityLabel,
      action,
      field,
      stringifyAuditValue(before),
      stringifyAuditValue(after),
      metadata ? JSON.stringify(metadata) : null
    ]
  );
}

function entityLabelFor(storageKey, item) {
  if (!item) return null;
  if (storageKey === "equipamentos") {
    return item.patrimonio ? `${item.nome || "Equipamento"} · ${item.patrimonio}` : (item.nome || "Equipamento");
  }
  if (storageKey === "postos") return item.nome || "Posto";
  if (storageKey === "movimentacoes") {
    return item.equipamentoNome || item.nome || "Movimentação";
  }
  return item.nome || item.id || storageKey;
}

const auditIgnoredFields = new Set(["id"]);

async function auditStorageChange(user, key, oldValue, newValue) {
  let oldData;
  let newData;
  try { oldData = oldValue ? JSON.parse(oldValue) : []; } catch { oldData = []; }
  try { newData = newValue ? JSON.parse(newValue) : []; } catch { newData = []; }

  if (!Array.isArray(oldData) || !Array.isArray(newData)) {
    if (oldValue !== newValue) {
      await addAudit({
        user,
        entityType: key,
        action: "UPDATE",
        field: "conteudo",
        before: oldValue,
        after: newValue
      });
    }
    return;
  }

  const oldMap = new Map(oldData.filter(x => x && x.id != null).map(x => [String(x.id), x]));
  const newMap = new Map(newData.filter(x => x && x.id != null).map(x => [String(x.id), x]));

  for (const [id, item] of newMap) {
    const previous = oldMap.get(id);
    if (!previous) {
      if (key === "movimentacoes") {
        const qtd = Number(item.quantidade) || 1;
        const labelBase = item.equipamentoNome || item.nome || "Equipamento";
        await addAudit({
          user,
          entityType: "movimentacoes",
          entityId: id,
          entityLabel: qtd > 1 ? `${labelBase} (${qtd} unidades)` : labelBase,
          action: "MOVE",
          field: "Posto",
          before: item.postoOrigemNome || "Estoque / sem posto",
          after: item.postoDestinoNome || "—",
          metadata: item
        });
      } else {
        await addAudit({
          user,
          entityType: key,
          entityId: id,
          entityLabel: entityLabelFor(key, item),
          action: "CREATE",
          after: item
        });
      }
      continue;
    }

    const fields = new Set([...Object.keys(previous), ...Object.keys(item)]);
    for (const field of fields) {
      if (auditIgnoredFields.has(field)) continue;
      // Mudanças de posto geradas pela tela de movimentação já são registradas
      // pelo objeto de movimentação com origem/destino legíveis.
      if (key === "equipamentos" && field === "postoAtualId") continue;
      const before = previous[field];
      const after = item[field];
      if (JSON.stringify(before) !== JSON.stringify(after)) {
        await addAudit({
          user,
          entityType: key,
          entityId: id,
          entityLabel: entityLabelFor(key, item),
          action: "UPDATE",
          field,
          before,
          after
        });
      }
    }
  }

  for (const [id, item] of oldMap) {
    if (!newMap.has(id)) {
      await addAudit({
        user,
        entityType: key,
        entityId: id,
        entityLabel: entityLabelFor(key, item),
        action: "DELETE",
        before: item
      });
    }
  }
}

async function normalizeExistingMovementAudits() {
  try {
    // Converte os registros antigos de movimentação, que guardavam o objeto inteiro
    // em "Depois", para o formato legível Campo=Posto / Antes=origem / Depois=destino.
    const moves = await pool.query(`
      SELECT id, user_id, user_name, entity_label, after_value, created_at
      FROM audit_logs
      WHERE action = 'MOVE'
        AND entity_type = 'movimentacoes'
        AND (field_name IS NULL OR field_name <> 'Posto')
      ORDER BY id
    `);

    for (const row of moves.rows) {
      let data = null;
      try { data = JSON.parse(row.after_value || ""); } catch {}
      if (!data || typeof data !== "object") continue;

      const qtd = Number(data.quantidade) || 1;
      const baseLabel = data.equipamentoNome || row.entity_label || "Equipamento";
      const label = qtd > 1 ? `${baseLabel} (${qtd} unidades)` : baseLabel;
      const origem = data.postoOrigemNome || "Estoque / sem posto";
      const destino = data.postoDestinoNome || "—";

      await pool.query(
        `UPDATE audit_logs
         SET entity_label = $1,
             field_name = 'Posto',
             before_value = $2,
             after_value = $3,
             metadata = $4::jsonb
         WHERE id = $5`,
        [label, origem, destino, JSON.stringify(data), row.id]
      );

      // Remove os registros duplicados antigos de postoAtualId gerados segundos antes/depois
      // para o mesmo usuário e equipamento.
      await pool.query(
        `DELETE FROM audit_logs
         WHERE action = 'UPDATE'
           AND entity_type = 'equipamentos'
           AND field_name = 'postoAtualId'
           AND user_name = $1
           AND entity_label = $2
           AND created_at BETWEEN ($3::timestamptz - interval '90 seconds')
                              AND ($3::timestamptz + interval '90 seconds')`,
        [row.user_name, baseLabel, row.created_at]
      );
    }

    // Se sobrou alguma troca de posto antiga sem um registro de movimentação correspondente,
    // ela continua sendo tratada semanticamente como movimentação.
    await pool.query(`
      UPDATE audit_logs
      SET action = 'MOVE',
          field_name = 'Posto'
      WHERE entity_type = 'equipamentos'
        AND action = 'UPDATE'
        AND field_name = 'postoAtualId'
    `);
  } catch (error) {
    console.error("Falha ao normalizar auditoria de movimentações:", error);
  }
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

  await pool.query(`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NULL,
      user_name TEXT NOT NULL,
      user_email TEXT NULL,
      entity_type TEXT NOT NULL,
      entity_id TEXT NULL,
      entity_label TEXT NULL,
      action TEXT NOT NULL,
      field_name TEXT NULL,
      before_value TEXT NULL,
      after_value TEXT NULL,
      metadata JSONB NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query("CREATE INDEX IF NOT EXISTS audit_logs_created_at_idx ON audit_logs(created_at DESC)");
  await pool.query("CREATE INDEX IF NOT EXISTS audit_logs_entity_idx ON audit_logs(entity_type, entity_id)");

  await normalizeExistingMovementAudits();

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
    await addAudit({
      user,
      entityType: "usuarios",
      entityId: user.id,
      entityLabel: user.nome,
      action: "CREATE",
      after: { nome: user.nome, email: user.email, role: user.role, ativo: user.ativo }
    });
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
    const created = publicUser(result.rows[0]);
    await addAudit({
      user: req.user,
      entityType: "usuarios",
      entityId: created.id,
      entityLabel: created.nome,
      action: "CREATE",
      after: { nome: created.nome, email: created.email, role: created.role, ativo: created.ativo }
    });
    res.json({ user: created });
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

    const beforeResult = await pool.query(
      "SELECT id, nome, email, role, ativo, created_at FROM users WHERE id = $1",
      [targetId]
    );
    if (!beforeResult.rowCount) return res.status(404).json({ error: "not_found" });
    const beforeUser = publicUser(beforeResult.rows[0]);

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
    const updated = publicUser(result.rows[0]);

    if (beforeUser.role !== updated.role) {
      await addAudit({
        user: req.user,
        entityType: "usuarios",
        entityId: updated.id,
        entityLabel: updated.nome,
        action: "UPDATE",
        field: "role",
        before: beforeUser.role,
        after: updated.role
      });
    }
    if (beforeUser.ativo !== updated.ativo) {
      await addAudit({
        user: req.user,
        entityType: "usuarios",
        entityId: updated.id,
        entityLabel: updated.nome,
        action: "UPDATE",
        field: "ativo",
        before: beforeUser.ativo,
        after: updated.ativo
      });
    }
    if (password !== undefined) {
      await addAudit({
        user: req.user,
        entityType: "usuarios",
        entityId: updated.id,
        entityLabel: updated.nome,
        action: "UPDATE",
        field: "senha",
        before: "[protegido]",
        after: "[alterada]"
      });
    }

    res.json({ user: updated });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "database_error" });
  }
});

app.get("/api/audit", authRequired, requireRole("admin"), async (req, res) => {
  try {
    const limit = Math.min(Math.max(Number(req.query.limit) || 300, 1), 1000);
    const entity = String(req.query.entity || "").trim();
    const action = String(req.query.action || "").trim();
    const user = String(req.query.user || "").trim();
    const q = String(req.query.q || "").trim();

    const where = [];
    const params = [];

    if (entity) {
      params.push(entity);
      where.push(`entity_type = $${params.length}`);
    }
    if (action) {
      params.push(action);
      where.push(`action = $${params.length}`);
    }
    if (user) {
      params.push(`%${user}%`);
      where.push(`user_name ILIKE $${params.length}`);
    }
    if (q) {
      params.push(`%${q}%`);
      where.push(`(
        COALESCE(entity_label,'') ILIKE $${params.length}
        OR COALESCE(field_name,'') ILIKE $${params.length}
        OR COALESCE(before_value,'') ILIKE $${params.length}
        OR COALESCE(after_value,'') ILIKE $${params.length}
      )`);
    }

    params.push(limit);
    const sql = `
      SELECT id, user_id, user_name, user_email, entity_type, entity_id,
             entity_label, action, field_name, before_value, after_value,
             metadata, created_at
      FROM audit_logs
      ${where.length ? "WHERE " + where.join(" AND ") : ""}
      ORDER BY created_at DESC, id DESC
      LIMIT $${params.length}
    `;

    const result = await pool.query(sql, params);
    res.json({ logs: result.rows });
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
    const previousResult = await pool.query(
      "SELECT value FROM app_storage WHERE key = $1",
      [req.params.key]
    );
    const previousValue = previousResult.rowCount ? previousResult.rows[0].value : null;

    await pool.query(
      `INSERT INTO app_storage (key, value, updated_at)
       VALUES ($1, $2, NOW())
       ON CONFLICT (key)
       DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`,
      [req.params.key, value]
    );

    try {
      await auditStorageChange(req.user, req.params.key, previousValue, value);
    } catch (auditError) {
      console.error("Falha ao registrar auditoria:", auditError);
    }

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

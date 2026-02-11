const path = require("path");
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");
const pgSession = require("connect-pg-simple")(session);

const app = express();

const DATABASE_URL = process.env.DATABASE_URL;

// Debug (Render): show if env is present without printing secrets
console.log("ENV CHECK:", {
  hasDatabaseUrl: !!process.env.DATABASE_URL,
  nodeEnv: process.env.NODE_ENV || null,
  hasSessionSecret: !!process.env.SESSION_SECRET
});

if (!DATABASE_URL) {
  console.error("FATAL: Missing DATABASE_URL. Add DATABASE_URL in Render -> Environment.");
  process.exit(1);
}


const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS annual_entries (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      year INTEGER NOT NULL,
      payload_json JSONB NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(user_id, year)
    );
  `);
}

app.use(express.json({ limit: "1mb" }));

app.use(
  session({
    store: new pgSession({
      pool,
      tableName: "session"
    }),
    secret: process.env.SESSION_SECRET || "dev_secret_change_me",
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, sameSite: "lax" }
  })
);

app.use(express.static(path.join(__dirname, "public")));

function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: "Not authenticated" });
  next();
}

// Register
app.post("/api/register", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: "Missing email/password" });
  if (password.length < 8) return res.status(400).json({ error: "Password must be at least 8 chars" });

  const exists = await pool.query("SELECT id FROM users WHERE email=$1", [email]);
  if (exists.rowCount) return res.status(409).json({ error: "Email already exists" });

  const password_hash = bcrypt.hashSync(password, 12);
  const ins = await pool.query(
    "INSERT INTO users(email, password_hash) VALUES ($1, $2) RETURNING id",
    [email, password_hash]
  );

  req.session.userId = ins.rows[0].id;
  req.session.email = email;
  res.json({ ok: true, email });
});

// Login
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: "Missing email/password" });

  const user = await pool.query("SELECT id, password_hash FROM users WHERE email=$1", [email]);
  if (!user.rowCount) return res.status(401).json({ error: "Invalid credentials" });

  const ok = bcrypt.compareSync(password, user.rows[0].password_hash);
  if (!ok) return res.status(401).json({ error: "Invalid credentials" });

  req.session.userId = user.rows[0].id;
  req.session.email = email;
  res.json({ ok: true, email });
});

// Logout
app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

// Me
app.get("/api/me", (req, res) => {
  if (!req.session.userId) return res.json({ authenticated: false });
  res.json({ authenticated: true, email: req.session.email });
});

// Years list
app.get("/api/years", requireAuth, async (req, res) => {
  const rows = await pool.query(
    "SELECT year, updated_at FROM annual_entries WHERE user_id=$1 ORDER BY year DESC",
    [req.session.userId]
  );
  res.json({ years: rows.rows });
});

// Get entry
app.get("/api/entry/:year", requireAuth, async (req, res) => {
  const year = Number(req.params.year);
  const row = await pool.query(
    "SELECT year, payload_json, updated_at FROM annual_entries WHERE user_id=$1 AND year=$2",
    [req.session.userId, year]
  );
  if (!row.rowCount) return res.status(404).json({ error: "Not found" });
  res.json({ year: row.rows[0].year, payload: row.rows[0].payload_json, updated_at: row.rows[0].updated_at });
});

// Upsert entry
app.post("/api/entry/:year", requireAuth, async (req, res) => {
  const year = Number(req.params.year);
  const payload = req.body?.payload;
  if (!year || !payload) return res.status(400).json({ error: "Missing year/payload" });

  await pool.query(
    `
    INSERT INTO annual_entries (user_id, year, payload_json)
    VALUES ($1, $2, $3)
    ON CONFLICT (user_id, year)
    DO UPDATE SET payload_json=EXCLUDED.payload_json, updated_at=now()
    `,
    [req.session.userId, year, payload]
  );

  res.json({ ok: true });
});

const PORT = process.env.PORT || 3000;

initDb()
  .then(() => {
    app.listen(PORT, () => console.log(`Running on http://localhost:${PORT}`));
  })
  .catch((e) => {
    console.error("DB init failed:", e);
    process.exit(1);
  });

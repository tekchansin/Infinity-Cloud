CREATE TABLE IF NOT EXISTS shares (
  id         TEXT PRIMARY KEY,
  type       TEXT NOT NULL,            -- 'listening' | 'harmonic'
  name       TEXT NOT NULL,
  author     TEXT NOT NULL,
  headphone  TEXT NOT NULL DEFAULT '',
  dap        TEXT NOT NULL,            -- DapModel enum name, e.g. DX340MAX
  amp        TEXT NOT NULL DEFAULT '', -- AmpCard label, e.g. Amp16
  payload    TEXT NOT NULL,            -- app-defined JSON, validated again on import
  downloads  INTEGER NOT NULL DEFAULT 0,
  created    INTEGER NOT NULL,         -- epoch ms
  owner_hash TEXT NOT NULL,            -- sha256(owner token)
  ip_hash    TEXT NOT NULL             -- sha256(salt + ip), rate limit only
);
CREATE INDEX IF NOT EXISTS idx_shares_type_created ON shares(type, created DESC);
CREATE INDEX IF NOT EXISTS idx_shares_type_downloads ON shares(type, downloads DESC);
CREATE INDEX IF NOT EXISTS idx_shares_ip_created ON shares(ip_hash, created);

-- Website reviews (anantarultimate.com/reviews.html). Hidden until an admin approves them.
CREATE TABLE IF NOT EXISTS reviews (
  id         TEXT PRIMARY KEY,
  author     TEXT NOT NULL,
  dap        TEXT NOT NULL DEFAULT '',  -- DapModel name or '' (not given)
  headphone  TEXT NOT NULL DEFAULT '',
  text       TEXT NOT NULL,
  status     TEXT NOT NULL,             -- 'pending' | 'approved'
  created    INTEGER NOT NULL,          -- epoch ms
  ip_hash    TEXT NOT NULL              -- sha256(salt + ip), rate limit only, blanked after 1 h
);
CREATE INDEX IF NOT EXISTS idx_reviews_status_created ON reviews(status, created DESC);
CREATE INDEX IF NOT EXISTS idx_reviews_ip_created ON reviews(ip_hash, created);

-- Log reports from debug/beta app builds (Settings › Send Log Report; release builds have no button).
-- Admin-only (ADMIN_KEY), deleted after 30 days by the hourly cron.
CREATE TABLE IF NOT EXISTS logs (
  id         TEXT PRIMARY KEY,
  dap        TEXT NOT NULL,             -- DapModel name
  version    TEXT NOT NULL,             -- app versionName, e.g. 12.1-60916d1c-beta
  note       TEXT NOT NULL DEFAULT '',
  report     TEXT NOT NULL,             -- plain text: device info, scan status, thread dump, log tails
  created    INTEGER NOT NULL,          -- epoch ms
  ip_hash    TEXT NOT NULL              -- sha256(salt + ip), rate limit only, blanked after 1 h
);
CREATE INDEX IF NOT EXISTS idx_logs_created ON logs(created);
CREATE INDEX IF NOT EXISTS idx_logs_ip_created ON logs(ip_hash, created);

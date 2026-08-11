CREATE TABLE IF NOT EXISTS visitor_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT NOT NULL UNIQUE,
  observed_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  ip_ciphertext TEXT NOT NULL,
  ip_iv TEXT NOT NULL,
  encryption_key_version TEXT NOT NULL,
  ip_hmac TEXT NOT NULL,
  country_code TEXT,
  region_code TEXT,
  city TEXT,
  asn INTEGER,
  page_path TEXT NOT NULL,
  referrer_host TEXT,
  CHECK (expires_at > observed_at AND expires_at <= observed_at + 7776000000)
);

CREATE INDEX IF NOT EXISTS idx_visitor_events_expiry
  ON visitor_events (expires_at);

CREATE INDEX IF NOT EXISTS idx_visitor_events_time
  ON visitor_events (observed_at DESC);

CREATE INDEX IF NOT EXISTS idx_visitor_events_country_time
  ON visitor_events (country_code, observed_at DESC);

CREATE INDEX IF NOT EXISTS idx_visitor_events_hmac_time
  ON visitor_events (ip_hmac, observed_at DESC);

CREATE TABLE IF NOT EXISTS admin_audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  occurred_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  action TEXT NOT NULL,
  event_id TEXT,
  result_count INTEGER NOT NULL DEFAULT 0,
  CHECK (expires_at > occurred_at AND expires_at <= occurred_at + 7776000000)
);

CREATE INDEX IF NOT EXISTS idx_admin_audit_expiry
  ON admin_audit (expires_at);

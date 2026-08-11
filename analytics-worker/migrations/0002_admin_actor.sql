ALTER TABLE admin_audit ADD COLUMN actor_hash TEXT;
ALTER TABLE admin_audit ADD COLUMN auth_method TEXT NOT NULL DEFAULT 'bearer';

CREATE INDEX IF NOT EXISTS admin_audit_actor_time_idx
  ON admin_audit (actor_hash, occurred_at);

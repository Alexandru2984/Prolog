-- Optional PostgreSQL schema. The running v1 application uses JSON-file
-- persistence by default to avoid provisioning production credentials.
CREATE TABLE IF NOT EXISTS audit_sessions (
  id BIGSERIAL PRIMARY KEY,
  label TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  score INTEGER NOT NULL,
  posture TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_facts (
  id BIGSERIAL PRIMARY KEY,
  session_id BIGINT NOT NULL REFERENCES audit_sessions(id) ON DELETE CASCADE,
  fact_name TEXT NOT NULL,
  fact_value BOOLEAN NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_results (
  id BIGSERIAL PRIMARY KEY,
  session_id BIGINT NOT NULL REFERENCES audit_sessions(id) ON DELETE CASCADE,
  severity TEXT NOT NULL,
  risk_id TEXT NOT NULL,
  explanation TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_recommendations (
  id BIGSERIAL PRIMARY KEY,
  session_id BIGINT NOT NULL REFERENCES audit_sessions(id) ON DELETE CASCADE,
  recommendation_id TEXT NOT NULL,
  risk_id TEXT NOT NULL,
  recommendation_text TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_exports (
  id BIGSERIAL PRIMARY KEY,
  session_id BIGINT REFERENCES audit_sessions(id) ON DELETE SET NULL,
  export_type TEXT NOT NULL,
  file_path TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS app_settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

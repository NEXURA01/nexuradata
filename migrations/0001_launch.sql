CREATE TABLE IF NOT EXISTS cases (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  name TEXT NOT NULL,
  email TEXT NOT NULL,
  phone TEXT NOT NULL DEFAULT '',
  support TEXT NOT NULL,
  urgency TEXT NOT NULL,
  message TEXT NOT NULL,
  source_path TEXT NOT NULL DEFAULT '/',
  status TEXT NOT NULL,
  next_step TEXT NOT NULL,
  client_summary TEXT NOT NULL,
  access_code_hash TEXT NOT NULL,
  access_code_ciphertext TEXT NOT NULL DEFAULT '',
  access_code_last_sent_at TEXT NOT NULL DEFAULT '',
  status_email_last_sent_at TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_cases_updated_at ON cases(updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_cases_email ON cases(email);
CREATE INDEX IF NOT EXISTS idx_cases_name ON cases(name);

CREATE TABLE IF NOT EXISTS case_updates (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id TEXT NOT NULL,
  kind TEXT NOT NULL DEFAULT 'timeline',
  title TEXT NOT NULL,
  note TEXT NOT NULL,
  state TEXT NOT NULL,
  sort_order INTEGER NOT NULL DEFAULT 0,
  is_visible INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  created_by TEXT NOT NULL DEFAULT 'system',
  FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_case_updates_case_visible_sort
  ON case_updates(case_id, kind, is_visible, sort_order);
CREATE INDEX IF NOT EXISTS idx_case_updates_case_created
  ON case_updates(case_id, created_at DESC);

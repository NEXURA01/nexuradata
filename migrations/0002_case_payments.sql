CREATE TABLE IF NOT EXISTS case_payments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  payment_request_id TEXT NOT NULL UNIQUE,
  case_id TEXT NOT NULL,
  payment_kind TEXT NOT NULL,
  status TEXT NOT NULL,
  label TEXT NOT NULL,
  description TEXT NOT NULL,
  amount_cents INTEGER NOT NULL,
  currency TEXT NOT NULL DEFAULT 'cad',
  checkout_url TEXT NOT NULL DEFAULT '',
  stripe_checkout_session_id TEXT NOT NULL DEFAULT '',
  stripe_payment_intent_id TEXT NOT NULL DEFAULT '',
  stripe_session_status TEXT NOT NULL DEFAULT '',
  stripe_payment_status TEXT NOT NULL DEFAULT '',
  stripe_customer_email TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  sent_at TEXT NOT NULL DEFAULT '',
  paid_at TEXT NOT NULL DEFAULT '',
  expires_at TEXT NOT NULL DEFAULT '',
  created_by TEXT NOT NULL DEFAULT 'ops',
  FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_case_payments_case_created
  ON case_payments(case_id, created_at DESC);

CREATE UNIQUE INDEX IF NOT EXISTS idx_case_payments_session
  ON case_payments(stripe_checkout_session_id)
  WHERE stripe_checkout_session_id <> '';

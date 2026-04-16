-- Operations expansion: quote workflow, internal notes, handling flags, reminder tracking

ALTER TABLE cases ADD COLUMN qualification_summary TEXT NOT NULL DEFAULT '';
ALTER TABLE cases ADD COLUMN internal_notes TEXT NOT NULL DEFAULT '';
ALTER TABLE cases ADD COLUMN handling_flags TEXT NOT NULL DEFAULT '';
ALTER TABLE cases ADD COLUMN quote_status TEXT NOT NULL DEFAULT 'none';
ALTER TABLE cases ADD COLUMN quote_amount_cents INTEGER DEFAULT NULL;
ALTER TABLE cases ADD COLUMN quote_sent_at TEXT NOT NULL DEFAULT '';
ALTER TABLE cases ADD COLUMN quote_approved_at TEXT NOT NULL DEFAULT '';
ALTER TABLE cases ADD COLUMN preapproval_confirmed INTEGER NOT NULL DEFAULT 0;
ALTER TABLE cases ADD COLUMN acquisition_source TEXT NOT NULL DEFAULT '';
ALTER TABLE cases ADD COLUMN last_reminder_sent_at TEXT NOT NULL DEFAULT '';
ALTER TABLE cases ADD COLUMN last_client_contact_at TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status);
CREATE INDEX IF NOT EXISTS idx_cases_quote_status ON cases(quote_status);

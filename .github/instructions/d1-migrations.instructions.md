---
description: "Use when writing D1 SQL migrations, schema changes, or altering tables. Covers naming, DDL patterns, and migration workflow."
applyTo: "migrations/**/*.sql"
---
# D1 Migrations

## Naming

Sequential four-digit prefix with a snake_case description:

```
0001_launch.sql
0002_case_payments.sql
0003_ops_expansion.sql
0004_your_change.sql
```

## DDL Patterns

- Use `CREATE TABLE IF NOT EXISTS` and `CREATE INDEX IF NOT EXISTS` for new objects.
- Use `ALTER TABLE ... ADD COLUMN` for schema expansion — D1 does not support `DROP COLUMN`.
- New columns must have a `NOT NULL DEFAULT` value (D1 requires defaults on existing tables).
- Prefer `TEXT` for dates (ISO 8601), `INTEGER` for booleans (0/1) and monetary cents.

## Conventions

- Foreign keys reference `case_id TEXT` (the application-generated ID, e.g. `NX-20260415-A1B2C3D4`), not the autoincrement `id`.
- Always add relevant indexes — the console uses `ORDER BY updated_at DESC` and filters by `status`, `case_id`.
- Index naming: `idx_{table}_{columns}`.

## Workflow

```bash
npm run cf:d1:migrate:local    # test locally first
npm run cf:d1:migrate:remote   # apply to production
```

Always test locally before applying to production.

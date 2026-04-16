---
description: "Use when writing or editing Cloudflare Pages Functions. Covers ESM exports, _lib reuse, input normalization, error handling, auth, and secret access. Triggers on: API endpoint, function, worker, D1 query, webhook."
applyTo: "functions/**/*.js"
---
# Cloudflare Pages Functions

## Handler Pattern

Export named ESM handlers — not default exports:

```js
export const onRequestOptions = () => onOptions("POST, OPTIONS");

export const onRequestPost = async (context) => {
  // context.env     → D1 bindings, env vars, secrets
  // context.request → standard Request object
};
```

Handler names: `onRequestGet`, `onRequestPost`, `onRequestPut`, `onRequestDelete`, `onRequestOptions`.

## Shared Libraries

Import from `functions/_lib/` — never duplicate logic between endpoints.

| Module | Exports |
|--------|---------|
| `http.js` | `json()`, `onOptions()`, `parsePayload()`, `methodNotAllowed()` |
| `cases.js` | `normalizeText()`, `normalizeMultilineText()`, `validateSubmission()`, case CRUD, access code crypto |
| `email.js` | `sendClientAccessEmail()`, `sendClientStatusEmail()`, `sendLabNotificationEmail()` |
| `stripe.js` | `createHostedCheckoutSession()`, `verifyStripeWebhook()` |

## Input → Normalize → Validate → Respond

```js
const payload = await parsePayload(context.request);          // JSON + form data
const name = normalizeText(payload.name, 120);                // trim + collapse whitespace
// validate enum inputs against allow-list Sets
return json({ ok: true, caseId }, { status: 200 });           // always use json() helper
return json({ ok: false, message: "..." }, { status: 400 });
```

Wrap every handler body in try/catch — return user-safe messages, never leak internals.

## Auth & Secrets

- Protected ops endpoints (`functions/api/ops/`): call `authorizeOpsRequest(request, env)` from `_lib/cases.js`, return 403 on failure.
- Access secrets via `context.env.SECRET_NAME`. Never log, hardcode, or return them.
- Check D1 binding before querying: `if (!context.env?.INTAKE_DB)` → return 503.
- D1: parameterized queries only — never interpolate user input into SQL.

/**
 * Tests for API handlers (intake, status, stripe-webhook, ops/cases, ops/payments, ops/quotes, ops/follow-up).
 *
 * Since these handlers require a D1 database, we build lightweight mocks that
 * simulate the D1 API (prepare → bind → run/first/all) and the external
 * email/Stripe APIs.
 */
import { describe, it, before } from "node:test";
import assert from "node:assert/strict";

// ---------------------------------------------------------------------------
// Minimal D1 stub factory
// ---------------------------------------------------------------------------

/**
 * Creates a D1 stub that returns the provided row(s) for all queries.
 *
 * @param {object|null}  firstRow   - Row returned by .first()
 * @param {Array}        allRows    - Rows returned by .all()
 */
const makeDb = (firstRow = null, allRows = []) => {
  const stmt = {
    bind: (..._args) => stmt,
    first: async () => firstRow,
    all: async () => ({ results: allRows }),
    run: async () => ({})
  };
  return { prepare: (_sql) => stmt };
};

const makeEnv = (overrides = {}) => ({
  INTAKE_DB: makeDb(),
  ACCESS_CODE_SECRET: "test-secret-abc123",
  RESEND_API_KEY: "",         // empty → email not sent (not-configured)
  RESEND_FROM_EMAIL: "",
  LAB_INBOX_EMAIL: "",
  OPS_ACCESS_ALLOWED_EMAILS: "ops@nexuradata.ca",
  STRIPE_SECRET_KEY: "",
  STRIPE_WEBHOOK_SECRET: "whsec_test",
  PUBLIC_SITE_ORIGIN: "https://nexuradata.ca",
  ...overrides
});

const makeRequest = (method, url, body, contentType = "application/json", headers = {}) =>
  new Request(url, {
    method,
    headers: { "content-type": contentType, ...headers },
    body: body !== undefined ? JSON.stringify(body) : undefined
  });

// ---------------------------------------------------------------------------
// Intake handler
// ---------------------------------------------------------------------------
describe("intake handler", () => {
  let handler;
  before(async () => {
    handler = await import("../functions/api/intake.js");
  });

  it("returns 503 when INTAKE_DB is not configured", async () => {
    const ctx = {
      env: { ...makeEnv(), INTAKE_DB: undefined },
      request: makeRequest("POST", "https://nexuradata.ca/api/intake", {})
    };
    const res = await handler.onRequestPost(ctx);
    assert.equal(res.status, 503);
    const body = await res.json();
    assert.equal(body.ok, false);
    assert.equal(body.fallback, "mailto");
  });

  it("returns 503 when ACCESS_CODE_SECRET is not configured", async () => {
    const ctx = {
      env: { ...makeEnv(), ACCESS_CODE_SECRET: undefined },
      request: makeRequest("POST", "https://nexuradata.ca/api/intake", {})
    };
    const res = await handler.onRequestPost(ctx);
    assert.equal(res.status, 503);
    const body = await res.json();
    assert.equal(body.ok, false);
  });

  it("returns 400 on validation error", async () => {
    const ctx = {
      env: makeEnv(),
      request: makeRequest("POST", "https://nexuradata.ca/api/intake", {
        nom: "",
        courriel: "bad",
        support: "SSD",
        urgence: "Standard",
        message: "Test",
        consentement: true
      })
    };
    const res = await handler.onRequestPost(ctx);
    assert.equal(res.status, 400);
    const body = await res.json();
    assert.equal(body.ok, false);
  });

  it("returns 200 and caseId on valid submission", async () => {
    const ctx = {
      env: makeEnv(),
      request: makeRequest("POST", "https://nexuradata.ca/api/intake", {
        nom: "Jean Dupont",
        courriel: "jean@example.com",
        support: "SSD",
        urgence: "Standard",
        message: "Mon SSD ne répond plus depuis hier.",
        consentement: true
      })
    };
    const res = await handler.onRequestPost(ctx);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.ok, true);
    assert.match(body.caseId, /^NX-/);
    assert.equal(body.delivery.lab, "missing-lab-inbox");
    assert.equal(body.delivery.client, "not-configured");
  });

  it("OPTIONS returns 204", async () => {
    const res = handler.onRequestOptions();
    assert.equal(res.status, 204);
  });

  it("onRequest (other methods) returns 405", async () => {
    const res = handler.onRequest();
    assert.equal(res.status, 405);
  });
});

// ---------------------------------------------------------------------------
// Status handler
// ---------------------------------------------------------------------------
describe("status handler", () => {
  let handler;
  before(async () => {
    handler = await import("../functions/api/status.js");
  });

  it("returns 503 when INTAKE_DB is not configured", async () => {
    const ctx = {
      env: { ...makeEnv(), INTAKE_DB: undefined },
      request: makeRequest("POST", "https://nexuradata.ca/api/status", {})
    };
    const res = await handler.onRequestPost(ctx);
    assert.equal(res.status, 503);
  });

  it("returns 400 when caseId/accessCode are missing", async () => {
    const ctx = {
      env: makeEnv(),
      request: makeRequest("POST", "https://nexuradata.ca/api/status", {})
    };
    const res = await handler.onRequestPost(ctx);
    assert.equal(res.status, 400);
    const body = await res.json();
    assert.equal(body.ok, false);
  });

  it("returns 404 when case is not found (wrong credentials)", async () => {
    // db.first() returns null → case not found
    const ctx = {
      env: { ...makeEnv(), INTAKE_DB: makeDb(null) },
      request: makeRequest("POST", "https://nexuradata.ca/api/status", {
        caseId: "NX-20240101-ABCD1234",
        accessCode: "ABCD-EFGH"
      })
    };
    const res = await handler.onRequestPost(ctx);
    assert.equal(res.status, 404);
    const body = await res.json();
    assert.equal(body.ok, false);
  });

  it("OPTIONS returns 204", async () => {
    const res = handler.onRequestOptions();
    assert.equal(res.status, 204);
  });

  it("onRequest (other methods) returns 405", async () => {
    const res = handler.onRequest();
    assert.equal(res.status, 405);
  });
});

// ---------------------------------------------------------------------------
// stripe-webhook handler
// ---------------------------------------------------------------------------
describe("stripe-webhook handler", () => {
  let handler;
  before(async () => {
    handler = await import("../functions/api/stripe-webhook.js");
  });

  it("returns 503 when INTAKE_DB is not configured", async () => {
    const ctx = {
      env: { ...makeEnv(), INTAKE_DB: undefined },
      request: new Request("https://nexuradata.ca/api/stripe-webhook", { method: "POST", body: "{}" })
    };
    const res = await handler.onRequestPost(ctx);
    assert.equal(res.status, 503);
  });

  it("returns 400 when webhook signature is invalid", async () => {
    const ctx = {
      env: makeEnv(),
      request: new Request("https://nexuradata.ca/api/stripe-webhook", {
        method: "POST",
        headers: { "Stripe-Signature": "t=12345,v1=badsignature" },
        body: "{}"
      })
    };
    const res = await handler.onRequestPost(ctx);
    assert.equal(res.status, 400);
    const body = await res.json();
    assert.equal(body.ok, false);
  });

  it("OPTIONS returns 204", async () => {
    const res = handler.onRequestOptions();
    assert.equal(res.status, 204);
  });

  it("onRequest (other methods) returns 405", async () => {
    const res = handler.onRequest();
    assert.equal(res.status, 405);
  });
});

// ---------------------------------------------------------------------------
// ops/cases handler
// ---------------------------------------------------------------------------
describe("ops/cases handler", () => {
  let handler;
  before(async () => {
    handler = await import("../functions/api/ops/cases.js");
  });

  const opsRequest = (method, body, url = "http://localhost/api/ops/cases") =>
    new Request(url, {
      method,
      headers: { "content-type": "application/json" },
      body: body !== undefined ? JSON.stringify(body) : undefined
    });

  it("returns 503 when INTAKE_DB is not configured (GET)", async () => {
    const ctx = {
      env: { ...makeEnv(), INTAKE_DB: undefined },
      request: opsRequest("GET", undefined)
    };
    const res = await handler.onRequestGet(ctx);
    assert.equal(res.status, 503);
  });

  it("returns 503 when INTAKE_DB is not configured (POST)", async () => {
    const ctx = {
      env: { ...makeEnv(), INTAKE_DB: undefined },
      request: opsRequest("POST", { action: "update" })
    };
    const res = await handler.onRequestPost(ctx);
    assert.equal(res.status, 503);
  });

  it("returns 403 when request is not from localhost and auth fails (GET)", async () => {
    const ctx = {
      env: { ...makeEnv(), OPS_ACCESS_ALLOWED_EMAILS: "" },
      request: opsRequest("GET", undefined, "https://nexuradata.ca/api/ops/cases")
    };
    const res = await handler.onRequestGet(ctx);
    assert.equal(res.status, 403);
  });

  it("returns 403 when request is not from localhost and auth fails (POST)", async () => {
    const ctx = {
      env: { ...makeEnv(), OPS_ACCESS_ALLOWED_EMAILS: "" },
      request: opsRequest("POST", { action: "update" }, "https://nexuradata.ca/api/ops/cases")
    };
    const res = await handler.onRequestPost(ctx);
    assert.equal(res.status, 403);
  });

  it("returns list of cases on GET from localhost (no caseId)", async () => {
    const ctx = {
      env: makeEnv(),
      request: opsRequest("GET", undefined)
    };
    const res = await handler.onRequestGet(ctx);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.ok, true);
    assert.ok(Array.isArray(body.items));
  });

  it("returns 404 when case not found by caseId (GET)", async () => {
    const ctx = {
      env: { ...makeEnv(), INTAKE_DB: makeDb(null) },
      request: opsRequest("GET", undefined, "http://localhost/api/ops/cases?caseId=NX-20240101-ABCD1234")
    };
    const res = await handler.onRequestGet(ctx);
    assert.equal(res.status, 404);
  });

  it("returns 400 on unknown action (POST)", async () => {
    const ctx = {
      env: makeEnv(),
      request: opsRequest("POST", { action: "do-magic" })
    };
    const res = await handler.onRequestPost(ctx);
    assert.equal(res.status, 400);
    const body = await res.json();
    assert.equal(body.ok, false);
    assert.match(body.message, /Action opérateur inconnue/);
  });

  it("OPTIONS returns 204", async () => {
    const res = handler.onRequestOptions();
    assert.equal(res.status, 204);
  });

  it("onRequest (other methods) returns 405", async () => {
    const res = handler.onRequest();
    assert.equal(res.status, 405);
  });

  it("send-access action throws when case not found", async () => {
    const ctx = {
      env: { ...makeEnv(), INTAKE_DB: makeDb(null) },
      request: opsRequest("POST", { action: "send-access", caseId: "NX-NOTFOUND" })
    };
    const res = await handler.onRequestPost(ctx);
    assert.equal(res.status, 400);
  });

  it("send-update action throws when caseId is missing", async () => {
    const ctx = {
      env: makeEnv(),
      request: opsRequest("POST", { action: "send-update", caseId: "" })
    };
    const res = await handler.onRequestPost(ctx);
    assert.equal(res.status, 400);
  });

  it("update action throws when case does not exist", async () => {
    const ctx = {
      env: { ...makeEnv(), INTAKE_DB: makeDb(null) },
      request: opsRequest("POST", {
        action: "update",
        caseId: "NX-NOTFOUND",
        status: "En cours",
        nextStep: "Attente du client",
        clientSummary: "Le dossier est en cours d'évaluation."
      })
    };
    const res = await handler.onRequestPost(ctx);
    assert.equal(res.status, 400);
  });
});

// ---------------------------------------------------------------------------
// ops/payments handler
// ---------------------------------------------------------------------------
describe("ops/payments handler", () => {
  let handler;
  before(async () => {
    handler = await import("../functions/api/ops/payments.js");
  });

  it("returns 503 when INTAKE_DB is not configured", async () => {
    const ctx = {
      env: { ...makeEnv(), INTAKE_DB: undefined },
      request: new Request("http://localhost/api/ops/payments", { method: "GET" })
    };
    const res = await handler.onRequestGet(ctx);
    assert.equal(res.status, 503);
  });

  it("returns 403 on remote request without auth", async () => {
    const ctx = {
      env: { ...makeEnv(), OPS_ACCESS_ALLOWED_EMAILS: "" },
      request: new Request("https://nexuradata.ca/api/ops/payments", { method: "GET" })
    };
    const res = await handler.onRequestGet(ctx);
    assert.equal(res.status, 403);
  });

  it("returns 200 with items array from localhost", async () => {
    const ctx = {
      env: makeEnv(),
      request: new Request("http://localhost/api/ops/payments", { method: "GET" })
    };
    const res = await handler.onRequestGet(ctx);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.ok, true);
    assert.ok(Array.isArray(body.items));
  });

  it("OPTIONS returns 204", async () => {
    const res = handler.onRequestOptions();
    assert.equal(res.status, 204);
  });

  it("onRequest (other methods) returns 405", async () => {
    const res = handler.onRequest();
    assert.equal(res.status, 405);
  });
});

// ---------------------------------------------------------------------------
// ops/quotes handler
// ---------------------------------------------------------------------------
describe("ops/quotes handler", () => {
  let handler;
  before(async () => {
    handler = await import("../functions/api/ops/quotes.js");
  });

  it("returns 503 when INTAKE_DB is not configured", async () => {
    const ctx = {
      env: { ...makeEnv(), INTAKE_DB: undefined },
      request: new Request("http://localhost/api/ops/quotes", { method: "GET" })
    };
    const res = await handler.onRequestGet(ctx);
    assert.equal(res.status, 503);
  });

  it("returns 403 on remote request without auth", async () => {
    const ctx = {
      env: { ...makeEnv(), OPS_ACCESS_ALLOWED_EMAILS: "" },
      request: new Request("https://nexuradata.ca/api/ops/quotes", { method: "GET" })
    };
    const res = await handler.onRequestGet(ctx);
    assert.equal(res.status, 403);
  });

  it("returns 200 with items array from localhost", async () => {
    const ctx = {
      env: makeEnv(),
      request: new Request("http://localhost/api/ops/quotes", { method: "GET" })
    };
    const res = await handler.onRequestGet(ctx);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.ok, true);
    assert.ok(Array.isArray(body.items));
  });

  it("OPTIONS returns 204", async () => {
    const res = handler.onRequestOptions();
    assert.equal(res.status, 204);
  });

  it("onRequest (other methods) returns 405", async () => {
    const res = handler.onRequest();
    assert.equal(res.status, 405);
  });
});

// ---------------------------------------------------------------------------
// ops/follow-up handler
// ---------------------------------------------------------------------------
describe("ops/follow-up handler", () => {
  let handler;
  before(async () => {
    handler = await import("../functions/api/ops/follow-up.js");
  });

  it("returns 503 when INTAKE_DB is not configured", async () => {
    const ctx = {
      env: { ...makeEnv(), INTAKE_DB: undefined },
      request: new Request("http://localhost/api/ops/follow-up", { method: "GET" })
    };
    const res = await handler.onRequestGet(ctx);
    assert.equal(res.status, 503);
  });

  it("returns 403 on remote request without auth", async () => {
    const ctx = {
      env: { ...makeEnv(), OPS_ACCESS_ALLOWED_EMAILS: "" },
      request: new Request("https://nexuradata.ca/api/ops/follow-up", { method: "GET" })
    };
    const res = await handler.onRequestGet(ctx);
    assert.equal(res.status, 403);
  });

  it("returns 200 from localhost", async () => {
    const ctx = {
      env: makeEnv(),
      request: new Request("http://localhost/api/ops/follow-up", { method: "GET" })
    };
    const res = await handler.onRequestGet(ctx);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.ok, true);
  });
});

// We need `before` from node:test – already imported at the top of this file.

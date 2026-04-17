import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { json, methodNotAllowed, onOptions, parsePayload } from "../functions/_lib/http.js";

describe("json()", () => {
  it("returns a Response with JSON content-type and no-store cache", async () => {
    const res = json({ ok: true });
    assert.equal(res.headers.get("content-type"), "application/json; charset=UTF-8");
    assert.equal(res.headers.get("cache-control"), "no-store");
    const body = await res.json();
    assert.deepEqual(body, { ok: true });
  });

  it("applies a custom status code", async () => {
    const res = json({ ok: false }, { status: 400 });
    assert.equal(res.status, 400);
  });

  it("defaults to status 200", () => {
    const res = json({ ok: true });
    assert.equal(res.status, 200);
  });

  it("merges extra headers", async () => {
    const res = json({ ok: true }, { headers: { "x-custom": "yes" } });
    assert.equal(res.headers.get("x-custom"), "yes");
    assert.equal(res.headers.get("content-type"), "application/json; charset=UTF-8");
  });

  it("serializes nested objects", async () => {
    const payload = { a: { b: [1, 2, 3] } };
    const res = json(payload);
    assert.deepEqual(await res.json(), payload);
  });
});

describe("onOptions()", () => {
  it("returns 204 with default allow header", () => {
    const res = onOptions();
    assert.equal(res.status, 204);
    assert.equal(res.headers.get("allow"), "GET, POST, OPTIONS");
  });

  it("returns 204 with custom allow header", () => {
    const res = onOptions("POST, OPTIONS");
    assert.equal(res.status, 204);
    assert.equal(res.headers.get("allow"), "POST, OPTIONS");
    assert.equal(res.headers.get("access-control-allow-methods"), "POST, OPTIONS");
  });

  it("sets correct CORS headers", () => {
    const res = onOptions("GET, POST, OPTIONS");
    assert.equal(res.headers.get("access-control-allow-origin"), "https://nexuradata.ca");
    assert.equal(res.headers.get("access-control-allow-headers"), "content-type");
  });
});

describe("methodNotAllowed()", () => {
  it("returns 405 with ok false", async () => {
    const res = methodNotAllowed();
    assert.equal(res.status, 405);
    const body = await res.json();
    assert.equal(body.ok, false);
    assert.ok(body.message.length > 0);
  });
});

describe("parsePayload()", () => {
  it("parses application/json body", async () => {
    const req = new Request("https://example.com/", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ nom: "Alice" })
    });
    const result = await parsePayload(req);
    assert.deepEqual(result, { nom: "Alice" });
  });

  it("parses application/x-www-form-urlencoded body", async () => {
    const req = new Request("https://example.com/", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: "nom=Bob&email=bob%40example.com"
    });
    const result = await parsePayload(req);
    assert.equal(result.nom, "Bob");
    assert.equal(result.email, "bob@example.com");
  });

  it("parses multipart/form-data body", async () => {
    const formData = new FormData();
    formData.append("field", "value");
    const req = new Request("https://example.com/", {
      method: "POST",
      body: formData
    });
    const result = await parsePayload(req);
    assert.equal(result.field, "value");
  });

  it("throws on unsupported content-type", async () => {
    const req = new Request("https://example.com/", {
      method: "POST",
      headers: { "content-type": "text/plain" },
      body: "hello"
    });
    await assert.rejects(() => parsePayload(req), /non pris en charge/);
  });

  it("throws when content-type is absent", async () => {
    // Request with no content-type header and a body — should fall through to throw
    const req = new Request("https://example.com/", {
      method: "POST",
      body: "data"
    });
    await assert.rejects(() => parsePayload(req));
  });
});

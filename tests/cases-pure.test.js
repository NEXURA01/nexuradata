import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  normalizeText,
  normalizeMultilineText,
  normalizeCaseId,
  normalizeAccessCode,
  generateCaseId,
  generateAccessCode,
  hashAccessCode,
  encryptAccessCode,
  decryptAccessCode,
  validateSubmission,
  validateStatusLookup,
  validateTimelineSteps,
  validatePaymentRequestInput,
  authorizeOpsRequest,
  getPublicOrigin
} from "../functions/_lib/cases.js";

// ---------------------------------------------------------------------------
// normalizeText
// ---------------------------------------------------------------------------
describe("normalizeText()", () => {
  it("trims leading/trailing whitespace", () => {
    assert.equal(normalizeText("  hello  ", 100), "hello");
  });

  it("collapses internal whitespace to a single space", () => {
    assert.equal(normalizeText("hello   world", 100), "hello world");
  });

  it("truncates to maxLength", () => {
    assert.equal(normalizeText("abcdef", 4), "abcd");
  });

  it("returns empty string for non-string values", () => {
    assert.equal(normalizeText(null, 100), "");
    assert.equal(normalizeText(undefined, 100), "");
    assert.equal(normalizeText(42, 100), "");
  });

  it("returns empty string for empty string input", () => {
    assert.equal(normalizeText("", 100), "");
  });
});

// ---------------------------------------------------------------------------
// normalizeMultilineText
// ---------------------------------------------------------------------------
describe("normalizeMultilineText()", () => {
  it("trims leading/trailing whitespace", () => {
    assert.equal(normalizeMultilineText("  hello  ", 100), "hello");
  });

  it("normalizes CRLF to LF", () => {
    assert.equal(normalizeMultilineText("a\r\nb", 100), "a\nb");
  });

  it("collapses 3+ consecutive newlines to 2", () => {
    assert.equal(normalizeMultilineText("a\n\n\n\nb", 100), "a\n\nb");
  });

  it("truncates to maxLength", () => {
    assert.equal(normalizeMultilineText("abcdef", 4), "abcd");
  });

  it("returns empty string for non-string", () => {
    assert.equal(normalizeMultilineText(null, 100), "");
  });
});

// ---------------------------------------------------------------------------
// normalizeCaseId / normalizeAccessCode
// ---------------------------------------------------------------------------
describe("normalizeCaseId()", () => {
  it("uppercases and strips invalid characters", () => {
    assert.equal(normalizeCaseId("nx-20240101-abcd1234"), "NX-20240101-ABCD1234");
  });

  it("strips special characters other than A-Z, 0-9, hyphen", () => {
    assert.equal(normalizeCaseId("NX!20240101#AB"), "NX20240101AB");
  });

  it("truncates to 40 chars", () => {
    const long = "A".repeat(50);
    assert.equal(normalizeCaseId(long).length, 40);
  });
});

describe("normalizeAccessCode()", () => {
  it("uppercases and strips non-alphanumeric/hyphen", () => {
    assert.equal(normalizeAccessCode("abcd-efgh"), "ABCD-EFGH");
  });

  it("truncates to 24 chars", () => {
    assert.equal(normalizeAccessCode("A".repeat(30)).length, 24);
  });
});

// ---------------------------------------------------------------------------
// generateCaseId
// ---------------------------------------------------------------------------
describe("generateCaseId()", () => {
  it("returns a string starting with NX-", () => {
    assert.match(generateCaseId(), /^NX-\d{8}-[A-F0-9]{8}$/i);
  });

  it("produces unique IDs on successive calls", () => {
    const a = generateCaseId();
    const b = generateCaseId();
    assert.notEqual(a, b);
  });
});

// ---------------------------------------------------------------------------
// generateAccessCode
// ---------------------------------------------------------------------------
describe("generateAccessCode()", () => {
  it("returns a code matching XXXX-XXXX pattern from the alphabet", () => {
    const code = generateAccessCode();
    assert.match(code, /^[A-Z2-9]{4}-[A-Z2-9]{4}$/);
  });

  it("produces unique codes on successive calls", () => {
    const codes = new Set(Array.from({ length: 20 }, generateAccessCode));
    assert.ok(codes.size > 1);
  });
});

// ---------------------------------------------------------------------------
// hashAccessCode / encryptAccessCode / decryptAccessCode
// ---------------------------------------------------------------------------
describe("hashAccessCode()", () => {
  const env = { ACCESS_CODE_SECRET: "test-secret-1234" };

  it("returns a hex string of 64 chars (SHA-256)", async () => {
    const hash = await hashAccessCode("ABCD-EFGH", env);
    assert.match(hash, /^[0-9a-f]{64}$/);
  });

  it("is deterministic for the same input and env", async () => {
    const h1 = await hashAccessCode("ABCD-EFGH", env);
    const h2 = await hashAccessCode("ABCD-EFGH", env);
    assert.equal(h1, h2);
  });

  it("differs for different access codes", async () => {
    const h1 = await hashAccessCode("ABCD-EFGH", env);
    const h2 = await hashAccessCode("WXYZ-1234", env);
    assert.notEqual(h1, h2);
  });

  it("differs when the secret changes", async () => {
    const h1 = await hashAccessCode("ABCD-EFGH", { ACCESS_CODE_SECRET: "secret-a" });
    const h2 = await hashAccessCode("ABCD-EFGH", { ACCESS_CODE_SECRET: "secret-b" });
    assert.notEqual(h1, h2);
  });
});

describe("encryptAccessCode() / decryptAccessCode()", () => {
  const env = { ACCESS_CODE_SECRET: "encrypt-secret-xyz" };

  it("round-trips correctly", async () => {
    const code = "TEST-1234";
    const cipher = await encryptAccessCode(code, env);
    const recovered = await decryptAccessCode(cipher, env);
    assert.equal(recovered, code);
  });

  it("returns empty string when secret is missing for encrypt", async () => {
    const result = await encryptAccessCode("ABCD-EFGH", {});
    assert.equal(result, "");
  });

  it("returns empty string when ciphertext is empty for decrypt", async () => {
    const result = await decryptAccessCode("", env);
    assert.equal(result, "");
  });

  it("returns empty string when secret is missing for decrypt", async () => {
    const env2 = { ACCESS_CODE_SECRET: "one" };
    const cipher = await encryptAccessCode("TEST", env2);
    const result = await decryptAccessCode(cipher, {});
    assert.equal(result, "");
  });

  it("returns empty string on corrupted ciphertext", async () => {
    const result = await decryptAccessCode("notvalidbase64.notvalid", env);
    assert.equal(result, "");
  });

  it("returns empty string when ciphertext has no dot separator", async () => {
    const result = await decryptAccessCode("nodothere", env);
    assert.equal(result, "");
  });

  it("produces different ciphertexts on each call (fresh IV)", async () => {
    const c1 = await encryptAccessCode("ABCD-EFGH", env);
    const c2 = await encryptAccessCode("ABCD-EFGH", env);
    assert.notEqual(c1, c2);
  });
});

// ---------------------------------------------------------------------------
// getPublicOrigin
// ---------------------------------------------------------------------------
describe("getPublicOrigin()", () => {
  it("uses PUBLIC_SITE_ORIGIN env var when set", () => {
    const env = { PUBLIC_SITE_ORIGIN: "https://example.ca" };
    assert.equal(getPublicOrigin(env, "https://irrelevant.ca/path"), "https://example.ca");
  });

  it("strips trailing slash from env var", () => {
    const env = { PUBLIC_SITE_ORIGIN: "https://example.ca/" };
    assert.equal(getPublicOrigin(env), "https://example.ca");
  });

  it("falls back to request URL origin", () => {
    assert.equal(getPublicOrigin({}, "https://nexuradata.ca/foo/bar"), "https://nexuradata.ca");
  });

  it("uses default URL when no args provided", () => {
    // Default request URL is https://nexuradata.ca/
    assert.equal(getPublicOrigin({}), "https://nexuradata.ca");
  });
});

// ---------------------------------------------------------------------------
// validateSubmission
// ---------------------------------------------------------------------------
describe("validateSubmission()", () => {
  const valid = {
    nom: "Alice Tremblay",
    courriel: "alice@example.com",
    telephone: "514-555-0001",
    support: "SSD",
    urgence: "Standard",
    message: "Mon disque ne répond plus.",
    consentement: true
  };

  it("returns normalized fields for a valid submission", () => {
    const result = validateSubmission(valid);
    assert.equal(result.nom, "Alice Tremblay");
    assert.equal(result.courriel, "alice@example.com");
    assert.equal(result.support, "SSD");
  });

  it("lowercases the email", () => {
    const result = validateSubmission({ ...valid, courriel: "ALICE@EXAMPLE.COM" });
    assert.equal(result.courriel, "alice@example.com");
  });

  it("defaults sourcePath to /", () => {
    const result = validateSubmission({ ...valid, sourcePath: "" });
    assert.equal(result.sourcePath, "/");
  });

  it("accepts consentement as string 'true'", () => {
    assert.doesNotThrow(() => validateSubmission({ ...valid, consentement: "true" }));
  });

  it("accepts consentement as string 'on'", () => {
    assert.doesNotThrow(() => validateSubmission({ ...valid, consentement: "on" }));
  });

  it("throws when honeypot field is filled", () => {
    assert.throws(() => validateSubmission({ ...valid, website: "spam" }), /rejetée/);
  });

  it("throws when nom is missing", () => {
    assert.throws(() => validateSubmission({ ...valid, nom: "" }), /requis/);
  });

  it("throws when courriel is missing", () => {
    assert.throws(() => validateSubmission({ ...valid, courriel: "" }), /requis/);
  });

  it("throws when message is missing", () => {
    assert.throws(() => validateSubmission({ ...valid, message: "" }), /requis/);
  });

  it("throws when consentement is false", () => {
    assert.throws(() => validateSubmission({ ...valid, consentement: false }), /requis/);
  });

  it("throws on invalid email format", () => {
    assert.throws(() => validateSubmission({ ...valid, courriel: "not-an-email" }), /courriel invalide/);
  });

  it("throws on invalid support value", () => {
    assert.throws(() => validateSubmission({ ...valid, support: "Betamax" }), /Support invalide/);
  });

  it("throws on invalid urgence value", () => {
    assert.throws(() => validateSubmission({ ...valid, urgence: "Interstellaire" }), /urgence invalide/);
  });

  it("accepts all valid support values", () => {
    const supports = ["Disque dur", "SSD", "RAID / NAS / serveur", "Téléphone / mobile", "USB / carte mémoire", "Je ne sais pas"];
    for (const support of supports) {
      assert.doesNotThrow(() => validateSubmission({ ...valid, support }));
    }
  });

  it("accepts all valid urgence values", () => {
    const urgencies = ["Standard", "Rapide", "Urgent", "Très sensible"];
    for (const urgence of urgencies) {
      assert.doesNotThrow(() => validateSubmission({ ...valid, urgence }));
    }
  });
});

// ---------------------------------------------------------------------------
// validateStatusLookup
// ---------------------------------------------------------------------------
describe("validateStatusLookup()", () => {
  it("accepts caseId and accessCode fields", () => {
    const result = validateStatusLookup({ caseId: "NX-20240101-ABCD1234", accessCode: "ABCD-EFGH" });
    assert.equal(result.caseId, "NX-20240101-ABCD1234");
    assert.equal(result.accessCode, "ABCD-EFGH");
  });

  it("accepts dossier and code aliases", () => {
    const result = validateStatusLookup({ dossier: "NX-20240101-ABCD1234", code: "WXYZ-1234" });
    assert.equal(result.caseId, "NX-20240101-ABCD1234");
  });

  it("throws when caseId is missing", () => {
    assert.throws(() => validateStatusLookup({ accessCode: "ABCD-EFGH" }), /valides/);
  });

  it("throws when accessCode is missing", () => {
    assert.throws(() => validateStatusLookup({ caseId: "NX-20240101-ABCD1234" }), /valides/);
  });

  it("throws when both are missing", () => {
    assert.throws(() => validateStatusLookup({}), /valides/);
  });
});

// ---------------------------------------------------------------------------
// validateTimelineSteps
// ---------------------------------------------------------------------------
describe("validateTimelineSteps()", () => {
  const step = (overrides = {}) => ({
    title: "Étape test",
    note: "Ceci est une note.",
    state: "pending",
    ...overrides
  });

  it("returns null when steps is undefined", () => {
    assert.equal(validateTimelineSteps(undefined), null);
  });

  it("validates 1 to 8 steps", () => {
    const result = validateTimelineSteps([step()]);
    assert.equal(result.length, 1);
    assert.equal(result[0].sortOrder, 0);
  });

  it("assigns sortOrder based on array index", () => {
    const result = validateTimelineSteps([step(), step({ title: "Étape 2" })]);
    assert.equal(result[0].sortOrder, 0);
    assert.equal(result[1].sortOrder, 1);
  });

  it("throws when steps is not an array", () => {
    assert.throws(() => validateTimelineSteps("not-an-array"), /1 et 8 étapes/);
  });

  it("throws when steps is an empty array", () => {
    assert.throws(() => validateTimelineSteps([]), /1 et 8 étapes/);
  });

  it("throws when steps has more than 8 items", () => {
    const steps = Array.from({ length: 9 }, () => step());
    assert.throws(() => validateTimelineSteps(steps), /1 et 8 étapes/);
  });

  it("accepts all valid step states", () => {
    for (const state of ["pending", "active", "complete"]) {
      assert.doesNotThrow(() => validateTimelineSteps([step({ state })]));
    }
  });

  it("throws on invalid step state", () => {
    assert.throws(() => validateTimelineSteps([step({ state: "unknown" })]), /Étape invalide/);
  });

  it("throws when step title is missing", () => {
    assert.throws(() => validateTimelineSteps([step({ title: "" })]), /Étape invalide/);
  });

  it("throws when step note is missing", () => {
    assert.throws(() => validateTimelineSteps([step({ note: "" })]), /Étape invalide/);
  });
});

// ---------------------------------------------------------------------------
// validatePaymentRequestInput
// ---------------------------------------------------------------------------
describe("validatePaymentRequestInput()", () => {
  const valid = {
    caseId: "NX-20240101-ABCD1234",
    paymentKind: "deposit",
    label: "Acompte initial",
    description: "Paiement de l'acompte.",
    currency: "cad",
    amount: "250.00",
    sendEmail: false
  };

  it("returns parsed payment input for valid data", () => {
    const result = validatePaymentRequestInput(valid);
    assert.equal(result.caseId, "NX-20240101-ABCD1234");
    assert.equal(result.amountCents, 25000);
    assert.equal(result.currency, "cad");
    assert.equal(result.sendEmail, false);
  });

  it("accepts amount with comma decimal separator", () => {
    const result = validatePaymentRequestInput({ ...valid, amount: "250,50" });
    assert.equal(result.amountCents, 25050);
  });

  it("defaults currency to cad", () => {
    const { currency: _c, ...rest } = valid;
    const result = validatePaymentRequestInput(rest);
    assert.equal(result.currency, "cad");
  });

  it("accepts kind alias for paymentKind", () => {
    const { paymentKind: _pk, ...rest } = valid;
    const result = validatePaymentRequestInput({ ...rest, kind: "final" });
    assert.equal(result.paymentKind, "final");
  });

  it("defaults paymentKind to custom when missing", () => {
    const { paymentKind: _pk, ...rest } = valid;
    const result = validatePaymentRequestInput(rest);
    assert.equal(result.paymentKind, "custom");
  });

  it("accepts sendEmail as string 'true'", () => {
    const result = validatePaymentRequestInput({ ...valid, sendEmail: "true" });
    assert.equal(result.sendEmail, true);
  });

  it("throws when caseId is missing", () => {
    assert.throws(() => validatePaymentRequestInput({ ...valid, caseId: "" }), /dossier invalide/);
  });

  it("throws on invalid paymentKind", () => {
    assert.throws(() => validatePaymentRequestInput({ ...valid, paymentKind: "fantasy" }), /Type de paiement invalide/);
  });

  it("throws when label is missing", () => {
    assert.throws(() => validatePaymentRequestInput({ ...valid, label: "" }), /libellé/);
  });

  it("throws when description is missing", () => {
    assert.throws(() => validatePaymentRequestInput({ ...valid, description: "" }), /description/);
  });

  it("throws on invalid amount format", () => {
    assert.throws(() => validatePaymentRequestInput({ ...valid, amount: "abc" }), /Montant invalide/);
  });

  it("throws on amount below minimum (< 1.00)", () => {
    assert.throws(() => validatePaymentRequestInput({ ...valid, amount: "0.50" }), /Montant hors limites/);
  });

  it("throws on amount above maximum", () => {
    assert.throws(() => validatePaymentRequestInput({ ...valid, amount: "100001.00" }), /Montant hors limites/);
  });

  it("accepts all valid payment kinds", () => {
    for (const paymentKind of ["deposit", "final", "custom"]) {
      assert.doesNotThrow(() => validatePaymentRequestInput({ ...valid, paymentKind }));
    }
  });
});

// ---------------------------------------------------------------------------
// authorizeOpsRequest
// ---------------------------------------------------------------------------
describe("authorizeOpsRequest()", () => {
  const makeRequest = (email, hostname = "nexuradata.ca") =>
    new Request(`https://${hostname}/api/ops/cases`, {
      headers: email ? { "Cf-Access-Authenticated-User-Email": email } : {}
    });

  it("allows any request from localhost without credentials", () => {
    const req = makeRequest("", "localhost");
    const result = authorizeOpsRequest(req, {});
    assert.equal(result.ok, true);
    assert.equal(result.actor, "local-dev");
  });

  it("uses email as actor on localhost when provided", () => {
    const req = makeRequest("dev@example.com", "localhost");
    const result = authorizeOpsRequest(req, {});
    assert.equal(result.ok, true);
    assert.equal(result.actor, "dev@example.com");
  });

  it("rejects when no email list or domain is configured", () => {
    const req = makeRequest("user@example.com");
    const result = authorizeOpsRequest(req, {});
    assert.equal(result.ok, false);
  });

  it("rejects when authenticated email is missing", () => {
    const req = makeRequest("");
    const result = authorizeOpsRequest(req, { OPS_ACCESS_ALLOWED_EMAILS: "admin@nexuradata.ca" });
    assert.equal(result.ok, false);
  });

  it("allows when email is in the allowed emails list", () => {
    const req = makeRequest("admin@nexuradata.ca");
    const result = authorizeOpsRequest(req, { OPS_ACCESS_ALLOWED_EMAILS: "admin@nexuradata.ca,other@nexuradata.ca" });
    assert.equal(result.ok, true);
    assert.equal(result.actor, "admin@nexuradata.ca");
  });

  it("is case-insensitive for email matching", () => {
    const req = makeRequest("ADMIN@NEXURADATA.CA");
    const result = authorizeOpsRequest(req, { OPS_ACCESS_ALLOWED_EMAILS: "admin@nexuradata.ca" });
    assert.equal(result.ok, true);
  });

  it("allows when email domain matches allowed domain", () => {
    const req = makeRequest("anyone@nexuradata.ca");
    const result = authorizeOpsRequest(req, { OPS_ACCESS_ALLOWED_DOMAIN: "nexuradata.ca" });
    assert.equal(result.ok, true);
    assert.equal(result.actor, "anyone@nexuradata.ca");
  });

  it("rejects when email domain does not match", () => {
    const req = makeRequest("attacker@evil.com");
    const result = authorizeOpsRequest(req, { OPS_ACCESS_ALLOWED_DOMAIN: "nexuradata.ca" });
    assert.equal(result.ok, false);
  });

  it("rejects when email only ends with domain but has extra prefix", () => {
    // e.g. "evil.com" appended — should fail since endsWith checks "@domain"
    const req = makeRequest("evil@nexuradata.caevil.com");
    const result = authorizeOpsRequest(req, { OPS_ACCESS_ALLOWED_DOMAIN: "nexuradata.ca" });
    assert.equal(result.ok, false);
  });
});

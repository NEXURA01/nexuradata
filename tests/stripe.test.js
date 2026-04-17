import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { verifyStripeWebhook, createHostedCheckoutSession } from "../functions/_lib/stripe.js";

// ---------------------------------------------------------------------------
// Helpers to build a valid Stripe-Signature header for testing
// ---------------------------------------------------------------------------
const toHex = (buffer) =>
  Array.from(new Uint8Array(buffer), (byte) => byte.toString(16).padStart(2, "0")).join("");

const buildStripeSignature = async (secret, timestamp, rawBody) => {
  const signedPayload = `${timestamp}.${rawBody}`;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const digest = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(signedPayload));
  const signature = toHex(digest);
  return `t=${timestamp},v1=${signature}`;
};

// ---------------------------------------------------------------------------
// verifyStripeWebhook
// ---------------------------------------------------------------------------
describe("verifyStripeWebhook()", () => {
  const webhookSecret = "whsec_test_secret_1234567890";
  const validBody = JSON.stringify({ type: "checkout.session.completed", data: { object: { id: "cs_test" } } });

  it("throws when STRIPE_WEBHOOK_SECRET is not configured", async () => {
    const req = new Request("https://example.com/", { method: "POST", body: validBody });
    await assert.rejects(() => verifyStripeWebhook({}, req), /webhook Stripe/);
  });

  it("throws when Stripe-Signature header is missing", async () => {
    const req = new Request("https://example.com/", { method: "POST", body: validBody });
    await assert.rejects(
      () => verifyStripeWebhook({ STRIPE_WEBHOOK_SECRET: webhookSecret }, req),
      /Signature Stripe absente/
    );
  });

  it("throws when signature header is malformed (no timestamp)", async () => {
    const req = new Request("https://example.com/", {
      method: "POST",
      headers: { "Stripe-Signature": "v1=abc123" },
      body: validBody
    });
    await assert.rejects(
      () => verifyStripeWebhook({ STRIPE_WEBHOOK_SECRET: webhookSecret }, req),
      /Signature Stripe absente/
    );
  });

  it("throws when timestamp is too old (>5 min)", async () => {
    const oldTimestamp = Math.floor(Date.now() / 1000) - 400;
    const sig = await buildStripeSignature(webhookSecret, `${oldTimestamp}`, validBody);
    const req = new Request("https://example.com/", {
      method: "POST",
      headers: { "Stripe-Signature": sig },
      body: validBody
    });
    await assert.rejects(
      () => verifyStripeWebhook({ STRIPE_WEBHOOK_SECRET: webhookSecret }, req),
      /expirée/
    );
  });

  it("throws when timestamp is in the far future (>5 min)", async () => {
    const futureTimestamp = Math.floor(Date.now() / 1000) + 400;
    const sig = await buildStripeSignature(webhookSecret, `${futureTimestamp}`, validBody);
    const req = new Request("https://example.com/", {
      method: "POST",
      headers: { "Stripe-Signature": sig },
      body: validBody
    });
    await assert.rejects(
      () => verifyStripeWebhook({ STRIPE_WEBHOOK_SECRET: webhookSecret }, req),
      /expirée/
    );
  });

  it("throws when signature does not match", async () => {
    const timestamp = Math.floor(Date.now() / 1000);
    const sig = `t=${timestamp},v1=deadbeefdeadbeef`;
    const req = new Request("https://example.com/", {
      method: "POST",
      headers: { "Stripe-Signature": sig },
      body: validBody
    });
    await assert.rejects(
      () => verifyStripeWebhook({ STRIPE_WEBHOOK_SECRET: webhookSecret }, req),
      /non valide/
    );
  });

  it("returns parsed JSON body when signature is valid", async () => {
    const timestamp = Math.floor(Date.now() / 1000);
    const sig = await buildStripeSignature(webhookSecret, `${timestamp}`, validBody);
    const req = new Request("https://example.com/", {
      method: "POST",
      headers: { "Stripe-Signature": sig },
      body: validBody
    });
    const result = await verifyStripeWebhook({ STRIPE_WEBHOOK_SECRET: webhookSecret }, req);
    assert.equal(result.type, "checkout.session.completed");
  });

  it("accepts lowercase stripe-signature header", async () => {
    const timestamp = Math.floor(Date.now() / 1000);
    const sig = await buildStripeSignature(webhookSecret, `${timestamp}`, validBody);
    const req = new Request("https://example.com/", {
      method: "POST",
      headers: { "stripe-signature": sig },
      body: validBody
    });
    const result = await verifyStripeWebhook({ STRIPE_WEBHOOK_SECRET: webhookSecret }, req);
    assert.ok(result);
  });

  it("accepts multiple v1 signatures (any matching is sufficient)", async () => {
    const timestamp = Math.floor(Date.now() / 1000);
    const validSig = await buildStripeSignature(webhookSecret, `${timestamp}`, validBody);
    // Extract just the valid signature hex
    const validHex = validSig.split("v1=")[1];
    const combinedSig = `t=${timestamp},v1=deadbeef,v1=${validHex}`;
    const req = new Request("https://example.com/", {
      method: "POST",
      headers: { "Stripe-Signature": combinedSig },
      body: validBody
    });
    const result = await verifyStripeWebhook({ STRIPE_WEBHOOK_SECRET: webhookSecret }, req);
    assert.ok(result);
  });

  it("throws when timestamp is not a finite number", async () => {
    const sig = `t=notanumber,v1=abc`;
    const req = new Request("https://example.com/", {
      method: "POST",
      headers: { "Stripe-Signature": sig },
      body: validBody
    });
    await assert.rejects(
      () => verifyStripeWebhook({ STRIPE_WEBHOOK_SECRET: webhookSecret }, req),
      /Horodatage Stripe invalide/
    );
  });
});

// ---------------------------------------------------------------------------
// createHostedCheckoutSession
// ---------------------------------------------------------------------------
describe("createHostedCheckoutSession()", () => {
  it("throws when STRIPE_SECRET_KEY is not configured", async () => {
    await assert.rejects(
      () =>
        createHostedCheckoutSession({}, {
          caseId: "NX-TEST",
          paymentRequestId: "PAY-TEST",
          paymentKind: "deposit",
          label: "Test",
          description: "Test desc",
          amountCents: 5000,
          currency: "cad",
          customerEmail: "test@example.com",
          successUrl: "https://example.com/success",
          cancelUrl: "https://example.com/cancel"
        }),
      /Stripe/
    );
  });
});

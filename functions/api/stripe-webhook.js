import { syncPaymentRequestFromStripe } from "../_lib/cases.js";
import { json, methodNotAllowed, onOptions } from "../_lib/http.js";
import { verifyStripeWebhook } from "../_lib/stripe.js";

export const onRequestOptions = () => onOptions("POST, OPTIONS");

export const onRequestPost = async (context) => {
  try {
    if (!context.env?.INTAKE_DB) {
      return json({ ok: false, message: "Service temporairement indisponible." }, { status: 503 });
    }
    const event = await verifyStripeWebhook(context.env, context.request);
    const payment = await syncPaymentRequestFromStripe(context.env, event);

    return json({
      ok: true,
      received: true,
      paymentRequestId: payment?.paymentRequestId || null
    });
  } catch {
    return json(
      {
        ok: false,
        message: "Événement non traité."
      },
      { status: 400 }
    );
  }
};

export const onRequest = methodNotAllowed;

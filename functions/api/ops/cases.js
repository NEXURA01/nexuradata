import {
  authorizeOpsRequest,
  createCasePaymentRequest,
  getCaseDetail,
  getResendableAccessCode,
  listCases,
  logReminder,
  normalizeCaseId,
  recordCaseEvent,
  regenerateCaseAccessCode,
  updateCaseRecord,
  updateQuoteStatus
} from "../../_lib/cases.js";
import { sendClientAccessEmail, sendClientPaymentLinkEmail, sendClientStatusEmail } from "../../_lib/email.js";
import { json, methodNotAllowed, onOptions, parsePayload } from "../../_lib/http.js";

const authorizeOrReject = (request, env) => {
  const auth = authorizeOpsRequest(request, env);

  if (!auth.ok) {
    return json(
      {
        ok: false,
        message: "Accès opérateur refusé."
      },
      { status: 403 }
    );
  }

  return auth;
};

export const onRequestOptions = () => onOptions("GET, POST, OPTIONS");

export const onRequestGet = async (context) => {
  if (!context.env?.INTAKE_DB) {
    return json({ ok: false, message: "Service temporairement indisponible." }, { status: 503 });
  }

  const auth = authorizeOrReject(context.request, context.env);

  if (auth instanceof Response) {
    return auth;
  }

  try {
    const url = new URL(context.request.url);
    const caseId = normalizeCaseId(url.searchParams.get("caseId"));

    if (caseId) {
      const detail = await getCaseDetail(context.env, caseId);

      if (!detail) {
        return json(
          {
            ok: false,
            message: "Dossier introuvable."
          },
          { status: 404 }
        );
      }

      return json({
        ok: true,
        case: detail
      });
    }

    const items = await listCases(context.env, url.searchParams.get("query") || "", {
      status: url.searchParams.get("status") || "",
      quoteStatus: url.searchParams.get("quoteStatus") || "",
      urgency: url.searchParams.get("urgency") || ""
    });
    return json({
      ok: true,
      items
    });
  } catch (error) {
    return json(
      {
        ok: false,
        message: error instanceof Error ? error.message : "Erreur opérateur."
      },
      { status: 400 }
    );
  }
};

export const onRequestPost = async (context) => {
  if (!context.env?.INTAKE_DB) {
    return json({ ok: false, message: "Service temporairement indisponible." }, { status: 503 });
  }

  const auth = authorizeOrReject(context.request, context.env);

  if (auth instanceof Response) {
    return auth;
  }

  try {
    const payload = await parsePayload(context.request);
    const action = `${payload.action || ""}`.trim();

    if (action === "update") {
      const detail = await updateCaseRecord(context.env, payload, auth.actor);
      const shouldNotifyClient = payload.notifyClient === true || payload.notifyClient === "true";
      let clientDelivery = { sent: false, reason: "not-requested" };

      if (shouldNotifyClient) {
        const statusDelivery = await sendClientStatusEmail(context.env, detail.caseId, context.request.url, auth.actor);
        clientDelivery = statusDelivery.delivery;
      }

      return json({
        ok: true,
        case: detail,
        delivery: clientDelivery.sent ? "sent" : clientDelivery.reason
      });
    }

    if (action === "send-update") {
      const caseId = normalizeCaseId(payload.caseId);

      if (!caseId) {
        throw new Error("Numéro de dossier invalide.");
      }

      const statusDelivery = await sendClientStatusEmail(context.env, caseId, context.request.url, auth.actor);
      return json({
        ok: true,
        case: statusDelivery.detail,
        delivery: statusDelivery.delivery.sent ? "sent" : statusDelivery.delivery.reason
      });
    }

    if (action === "send-access") {
      const detail = await getResendableAccessCode(context.env, payload.caseId);
      const delivery = await sendClientAccessEmail(context.env, detail, context.request.url, "resent");

      if (!delivery.sent) {
        await recordCaseEvent(context.env, detail.caseId, auth.actor, "Renvoi du code impossible", `Échec d'envoi: ${delivery.reason}`);
      }

      return json({
        ok: true,
        caseId: detail.caseId,
        delivery: delivery.sent ? "sent" : delivery.reason
      });
    }

    if (action === "regenerate-access") {
      const detail = await regenerateCaseAccessCode(context.env, payload.caseId, auth.actor);
      const delivery = await sendClientAccessEmail(context.env, detail, context.request.url, "regenerated");

      if (!delivery.sent) {
        await recordCaseEvent(context.env, detail.caseId, auth.actor, "Nouveau code non envoyé", `Échec d'envoi: ${delivery.reason}`);
      }

      return json({
        ok: true,
        caseId: detail.caseId,
        accessCode: detail.accessCode,
        delivery: delivery.sent ? "sent" : delivery.reason
      });
    }

    if (action === "create-payment") {
      const payment = await createCasePaymentRequest(context.env, payload, auth.actor, context.request.url);
      let delivery = { sent: false, reason: "not-requested" };

      if (payload.sendEmail === true || payload.sendEmail === "true") {
        delivery = await sendClientPaymentLinkEmail(context.env, payment, context.request.url, auth.actor);
      }

      return json({
        ok: true,
        case: await getCaseDetail(context.env, payment.caseId),
        payment,
        delivery: delivery.sent ? "sent" : delivery.reason
      });
    }

    if (action === "quote-send" || action === "quote-approve" || action === "quote-expire" || action === "quote-decline") {
      const quoteStatusMap = {
        "quote-send": "sent",
        "quote-approve": "approved",
        "quote-expire": "expired",
        "quote-decline": "declined"
      };

      const detail = await updateQuoteStatus(context.env, {
        caseId: payload.caseId,
        quoteStatus: quoteStatusMap[action],
        quoteAmount: payload.quoteAmount
      }, auth.actor);

      return json({
        ok: true,
        case: detail
      });
    }

    if (action === "log-reminder") {
      const detail = await logReminder(context.env, payload, auth.actor);

      return json({
        ok: true,
        case: detail
      });
    }

    throw new Error("Action opérateur inconnue.");
  } catch (error) {
    return json(
      {
        ok: false,
        message: error instanceof Error ? error.message : "Erreur opérateur."
      },
      { status: 400 }
    );
  }
};

export const onRequest = methodNotAllowed;

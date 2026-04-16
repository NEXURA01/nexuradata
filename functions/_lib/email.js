import {
  getCaseDetail,
  getPublicOrigin,
  markAccessEmailSent,
  markPaymentRequestSent,
  markStatusEmailSent,
  normalizeText,
  recordCaseEvent
} from "./cases.js";

const escapeHtml = (value) =>
  `${value ?? ""}`
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");

const formatTextLines = (lines) => lines.filter(Boolean).join("\n");

const formatCurrency = (amountCents, currency = "cad") =>
  new Intl.NumberFormat("fr-CA", {
    style: "currency",
    currency: `${currency || "cad"}`.toUpperCase()
  }).format((Number(amountCents) || 0) / 100);

const sendResendEmail = async (env, payload, idempotencyKey) => {
  const apiKey = normalizeText(env?.RESEND_API_KEY, 256);
  const from = normalizeText(env?.RESEND_FROM_EMAIL, 200);

  if (!apiKey || !from) {
    return {
      sent: false,
      reason: "not-configured"
    };
  }

  try {
    const response = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "content-type": "application/json",
        ...(idempotencyKey ? { "Idempotency-Key": idempotencyKey } : {})
      },
      body: JSON.stringify({
        from,
        ...payload
      })
    });

    if (!response.ok) {
      return {
        sent: false,
        reason: `api-${response.status}`,
        error: await response.text()
      };
    }

    return {
      sent: true,
      ...(await response.json())
    };
  } catch (error) {
    return {
      sent: false,
      reason: "network-error",
      error: error instanceof Error ? error.message : "Unknown error"
    };
  }
};

export const sendLabNotificationEmail = async (env, intakeRecord, requestUrl) => {
  const inbox = normalizeText(env?.LAB_INBOX_EMAIL, 200);

  if (!inbox) {
    return {
      sent: false,
      reason: "missing-lab-inbox"
    };
  }

  const portalUrl = `${getPublicOrigin(env, requestUrl)}/operations/`;
  const subject = `Nouveau dossier ${intakeRecord.caseId} - ${intakeRecord.support} - ${intakeRecord.urgence}`;
  const text = formatTextLines([
    `Dossier: ${intakeRecord.caseId}`,
    `Nom: ${intakeRecord.nom}`,
    `Courriel: ${intakeRecord.courriel}`,
    `Téléphone: ${intakeRecord.telephone || "Non fourni"}`,
    `Support: ${intakeRecord.support}`,
    `Urgence: ${intakeRecord.urgence}`,
    `Code d'accès initial: ${intakeRecord.accessCode}`,
    `Source: ${intakeRecord.sourcePath}`,
    "",
    "Description du problème:",
    intakeRecord.message,
    "",
    `Console interne: ${portalUrl}`
  ]);
  const html = `
    <h1>Nouveau dossier ${escapeHtml(intakeRecord.caseId)}</h1>
    <p><strong>Nom:</strong> ${escapeHtml(intakeRecord.nom)}</p>
    <p><strong>Courriel:</strong> ${escapeHtml(intakeRecord.courriel)}</p>
    <p><strong>Téléphone:</strong> ${escapeHtml(intakeRecord.telephone || "Non fourni")}</p>
    <p><strong>Support:</strong> ${escapeHtml(intakeRecord.support)}</p>
    <p><strong>Urgence:</strong> ${escapeHtml(intakeRecord.urgence)}</p>
    <p><strong>Code d'accès initial:</strong> ${escapeHtml(intakeRecord.accessCode)}</p>
    <p><strong>Source:</strong> ${escapeHtml(intakeRecord.sourcePath)}</p>
    <h2>Description</h2>
    <p>${escapeHtml(intakeRecord.message).replace(/\n/g, "<br>")}</p>
    <p><a href="${escapeHtml(portalUrl)}">Ouvrir la console interne</a></p>
  `;

  return sendResendEmail(
    env,
    {
      to: [inbox],
      subject,
      text,
      html
    },
    `lab-intake-${intakeRecord.caseId}`
  );
};

export const sendClientAccessEmail = async (env, record, requestUrl, reason = "initial") => {
  const statusUrl = `${getPublicOrigin(env, requestUrl)}/suivi-dossier-client-montreal.html`;
  const subject =
    reason === "regenerated"
      ? `Nouveau code d'accès pour votre dossier ${record.caseId}`
      : reason === "resent"
        ? `Rappel du code d'accès pour votre dossier ${record.caseId}`
      : `Dossier ${record.caseId} ouvert chez NEXURADATA`;
  const intro =
    reason === "regenerated"
      ? "Un nouveau code d'accès a été généré pour votre dossier."
      : reason === "resent"
        ? "Voici à nouveau le code d'accès actuel de votre dossier."
      : "Votre demande a été reçue et un dossier initial a été ouvert.";
  const text = formatTextLines([
    `Bonjour ${record.name || ""},`,
    "",
    intro,
    `Numéro de dossier: ${record.caseId}`,
    `Code d'accès: ${record.accessCode}`,
    `Statut actuel: ${record.status}`,
    `Prochaine étape: ${record.nextStep}`,
    "",
    `Portail client: ${statusUrl}`,
    "",
    "Conservez ce courriel. Ce code permet d'afficher l'état utile du dossier sans exposer de détails sensibles.",
    "",
    "NEXURADATA"
  ]);
  const html = `
    <p>Bonjour ${escapeHtml(record.name || "")},</p>
    <p>${escapeHtml(intro)}</p>
    <p><strong>Numéro de dossier:</strong> ${escapeHtml(record.caseId)}</p>
    <p><strong>Code d'accès:</strong> ${escapeHtml(record.accessCode)}</p>
    <p><strong>Statut actuel:</strong> ${escapeHtml(record.status)}</p>
    <p><strong>Prochaine étape:</strong> ${escapeHtml(record.nextStep)}</p>
    <p><a href="${escapeHtml(statusUrl)}">Ouvrir le portail client</a></p>
    <p>Conservez ce courriel. Ce code permet d'afficher l'état utile du dossier sans exposer de détails sensibles.</p>
    <p>NEXURADATA</p>
  `;

  const delivery = await sendResendEmail(
    env,
    {
      to: [record.email],
      subject,
      text,
      html
    },
    `${reason}-access-${record.caseId}`
  );

  if (delivery.sent) {
    await markAccessEmailSent(env, record.caseId);
    await recordCaseEvent(
      env,
      record.caseId,
      "system",
      reason === "regenerated" ? "Code d'accès régénéré et envoyé" : "Code d'accès envoyé",
      `Un courriel d'accès client a été envoyé à ${record.email}.`
    );
  }

  return delivery;
};

export const sendClientStatusEmail = async (env, caseId, requestUrl, actor = "ops") => {
  const detail = await getCaseDetail(env, caseId);

  if (!detail) {
    throw new Error("Dossier introuvable.");
  }

  const statusUrl = `${getPublicOrigin(env, requestUrl)}/suivi-dossier-client-montreal.html`;
  const text = formatTextLines([
    `Bonjour ${detail.name},`,
    "",
    `Le dossier ${detail.caseId} a été mis à jour.`,
    `Statut: ${detail.status}`,
    `Prochaine étape: ${detail.nextStep}`,
    "",
    detail.clientSummary,
    "",
    `Portail client: ${statusUrl}`,
    "",
    "NEXURADATA"
  ]);
  const html = `
    <p>Bonjour ${escapeHtml(detail.name)},</p>
    <p>Le dossier <strong>${escapeHtml(detail.caseId)}</strong> a été mis à jour.</p>
    <p><strong>Statut:</strong> ${escapeHtml(detail.status)}</p>
    <p><strong>Prochaine étape:</strong> ${escapeHtml(detail.nextStep)}</p>
    <p>${escapeHtml(detail.clientSummary).replace(/\n/g, "<br>")}</p>
    <p><a href="${escapeHtml(statusUrl)}">Ouvrir le portail client</a></p>
    <p>NEXURADATA</p>
  `;

  const delivery = await sendResendEmail(
    env,
    {
      to: [detail.email],
      subject: `Mise à jour du dossier ${detail.caseId}`,
      text,
      html
    },
    `status-update-${detail.caseId}-${detail.updatedAt}`
  );

  if (delivery.sent) {
    await markStatusEmailSent(env, detail.caseId);
    await recordCaseEvent(env, detail.caseId, actor, "Mise à jour envoyée au client", `Un courriel de suivi a été envoyé à ${detail.email}.`);
  }

  return {
    detail,
    delivery
  };
};

export const sendClientPaymentLinkEmail = async (env, payment, requestUrl, actor = "ops") => {
  if (!payment?.customerEmail || !payment?.checkoutUrl) {
    throw new Error("Demande de paiement incomplète.");
  }

  const statusUrl = `${getPublicOrigin(env, requestUrl)}/suivi-dossier-client-montreal.html`;
  const amount = formatCurrency(payment.amountCents, payment.currency);
  const subject = `${payment.label} - ${amount} - ${payment.caseId}`;
  const text = formatTextLines([
    "Bonjour,",
    "",
    `Un lien de paiement a été préparé pour le dossier ${payment.caseId}.`,
    `Libellé: ${payment.label}`,
    `Montant: ${amount}`,
    "",
    payment.description,
    "",
    `Paiement sécurisé: ${payment.checkoutUrl}`,
    `Suivi du dossier: ${statusUrl}`,
    "",
    "NEXURADATA"
  ]);
  const html = `
    <p>Bonjour,</p>
    <p>Un lien de paiement a été préparé pour le dossier <strong>${escapeHtml(payment.caseId)}</strong>.</p>
    <p><strong>Libellé:</strong> ${escapeHtml(payment.label)}</p>
    <p><strong>Montant:</strong> ${escapeHtml(amount)}</p>
    <p>${escapeHtml(payment.description).replace(/\n/g, "<br>")}</p>
    <p><a href="${escapeHtml(payment.checkoutUrl)}">Ouvrir le paiement sécurisé</a></p>
    <p><a href="${escapeHtml(statusUrl)}">Accéder au suivi du dossier</a></p>
    <p>NEXURADATA</p>
  `;

  const delivery = await sendResendEmail(
    env,
    {
      to: [payment.customerEmail],
      subject,
      text,
      html
    },
    `payment-link-${payment.paymentRequestId}`
  );

  if (delivery.sent) {
    await markPaymentRequestSent(env, payment.paymentRequestId);
    await recordCaseEvent(
      env,
      payment.caseId,
      actor,
      "Lien de paiement envoyé",
      `${payment.label} transmis à ${payment.customerEmail}.`
    );
  }

  return delivery;
};

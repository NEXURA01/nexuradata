import { createHostedCheckoutSession } from "./stripe.js";

const allowedSupports = new Set([
  "Disque dur",
  "SSD",
  "RAID / NAS / serveur",
  "Téléphone / mobile",
  "USB / carte mémoire",
  "Je ne sais pas"
]);

const allowedUrgencies = new Set([
  "Standard",
  "Rapide",
  "Urgent",
  "Très sensible"
]);

const allowedStepStates = new Set(["pending", "active", "complete"]);
const allowedPaymentKinds = new Set(["deposit", "final", "custom"]);
const allowedQuoteStatuses = new Set(["none", "draft", "sent", "approved", "expired", "declined"]);
const allowedReminderTypes = new Set(["quote_follow_up", "payment_follow_up", "missing_information", "general_follow_up"]);
const accessCodeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

const encoder = new TextEncoder();
const localHostnames = new Set(["localhost", "127.0.0.1"]);

export const normalizeText = (value, maxLength) => {
  if (typeof value !== "string") {
    return "";
  }

  return value.trim().replace(/\s+/g, " ").slice(0, maxLength);
};

export const normalizeMultilineText = (value, maxLength) => {
  if (typeof value !== "string") {
    return "";
  }

  return value.trim().replace(/\r\n/g, "\n").replace(/\n{3,}/g, "\n\n").slice(0, maxLength);
};

const isValidEmail = (value) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);

const toHex = (buffer) =>
  Array.from(new Uint8Array(buffer), (byte) => byte.toString(16).padStart(2, "0")).join("");

const toBase64 = (buffer) => {
  let binary = "";

  for (const byte of new Uint8Array(buffer)) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary);
};

const fromBase64 = (value) => {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);

  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }

  return bytes;
};

const getSecretBytes = async (env) => {
  const secret = normalizeText(env?.ACCESS_CODE_SECRET, 256);
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(secret || "nexuradata-launch-v1"));
  return new Uint8Array(digest);
};

const getAesKey = async (env) =>
  crypto.subtle.importKey(
    "raw",
    await getSecretBytes(env),
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"]
  );

export const hashAccessCode = async (accessCode, env) => {
  const secretBytes = await getSecretBytes(env);
  const payload = new Uint8Array(secretBytes.length + accessCode.length + 1);
  payload.set(secretBytes);
  payload.set(encoder.encode(`:${accessCode}`), secretBytes.length);
  const digest = await crypto.subtle.digest("SHA-256", payload);
  return toHex(digest);
};

export const encryptAccessCode = async (accessCode, env) => {
  if (!normalizeText(env?.ACCESS_CODE_SECRET, 256)) {
    return "";
  }

  const key = await getAesKey(env);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cipher = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv
    },
    key,
    encoder.encode(accessCode)
  );

  return `${toBase64(iv)}.${toBase64(cipher)}`;
};

export const decryptAccessCode = async (ciphertext, env) => {
  const normalizedCiphertext = normalizeText(ciphertext, 4096);

  if (!normalizedCiphertext || !normalizeText(env?.ACCESS_CODE_SECRET, 256)) {
    return "";
  }

  const [ivBase64, encryptedBase64] = normalizedCiphertext.split(".");

  if (!ivBase64 || !encryptedBase64) {
    return "";
  }

  try {
    const key = await getAesKey(env);
    const iv = fromBase64(ivBase64);
    const payload = fromBase64(encryptedBase64);
    const decrypted = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv
      },
      key,
      payload
    );

    return new TextDecoder().decode(decrypted);
  } catch {
    return "";
  }
};

export const generateCaseId = () => {
  const now = new Date();
  const date = now.toISOString().slice(0, 10).replace(/-/g, "");
  const token = crypto.randomUUID().slice(0, 8).toUpperCase();
  return `NX-${date}-${token}`;
};

const randomCodeSegment = (length) => {
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  return Array.from(bytes, (byte) => accessCodeAlphabet[byte % accessCodeAlphabet.length]).join("");
};

export const generateAccessCode = () => `${randomCodeSegment(4)}-${randomCodeSegment(4)}`;

export const normalizeCaseId = (value) => normalizeText(value, 40).toUpperCase().replace(/[^A-Z0-9-]/g, "");
export const normalizeAccessCode = (value) => normalizeText(value, 24).toUpperCase().replace(/[^A-Z0-9-]/g, "");

export const validateSubmission = (payload) => {
  const nom = normalizeText(payload.nom, 120);
  const courriel = normalizeText(payload.courriel, 160).toLowerCase();
  const telephone = normalizeText(payload.telephone, 40);
  const support = normalizeText(payload.support, 60);
  const urgence = normalizeText(payload.urgence, 40);
  const message = normalizeMultilineText(payload.message, 3000);
  const sourcePath = normalizeText(payload.sourcePath, 160) || "/";
  const honeypot = normalizeText(payload.website, 120);
  const consentement = payload.consentement === true || payload.consentement === "true" || payload.consentement === "on";

  if (honeypot) {
    throw new Error("Requête rejetée.");
  }

  if (!nom || !courriel || !support || !urgence || !message || !consentement) {
    throw new Error("Complétez tous les champs requis.");
  }

  if (!isValidEmail(courriel)) {
    throw new Error("Adresse courriel invalide.");
  }

  if (!allowedSupports.has(support)) {
    throw new Error("Support invalide.");
  }

  if (!allowedUrgencies.has(urgence)) {
    throw new Error("Niveau d'urgence invalide.");
  }

  return {
    nom,
    courriel,
    telephone,
    support,
    urgence,
    message,
    sourcePath
  };
};

export const validateStatusLookup = (payload) => {
  const caseId = normalizeCaseId(payload.caseId || payload.dossier);
  const accessCode = normalizeAccessCode(payload.accessCode || payload.code);

  if (!caseId || !accessCode) {
    throw new Error("Entrez un numéro de dossier et un code d'accès valides.");
  }

  return {
    caseId,
    accessCode
  };
};

const normalizeStep = (step, index) => {
  const title = normalizeText(step?.title, 80);
  const note = normalizeMultilineText(step?.note, 220);
  const state = normalizeText(step?.state, 20).toLowerCase();

  if (!title || !note || !allowedStepStates.has(state)) {
    throw new Error(`Étape invalide à la position ${index + 1}.`);
  }

  return {
    title,
    note,
    state,
    sortOrder: index
  };
};

export const validateTimelineSteps = (steps) => {
  if (typeof steps === "undefined") {
    return null;
  }

  if (!Array.isArray(steps) || steps.length === 0 || steps.length > 8) {
    throw new Error("Fournissez entre 1 et 8 étapes visibles.");
  }

  return steps.map(normalizeStep);
};

const parseAmountToCents = (value) => {
  const normalized = normalizeText(`${value ?? ""}`, 32).replace(",", ".");

  if (!/^\d+(\.\d{1,2})?$/.test(normalized)) {
    throw new Error("Montant invalide.");
  }

  const amount = Math.round(Number(normalized) * 100);

  if (!Number.isFinite(amount) || amount < 100 || amount > 10000000) {
    throw new Error("Montant hors limites.");
  }

  return amount;
};

const formatCurrency = (amountCents, currency = "cad") =>
  new Intl.NumberFormat("fr-CA", {
    style: "currency",
    currency: `${currency || "cad"}`.toUpperCase()
  }).format((Number(amountCents) || 0) / 100);

const generatePaymentRequestId = () => {
  const now = new Date();
  const date = now.toISOString().slice(0, 10).replace(/-/g, "");
  const token = crypto.randomUUID().slice(0, 6).toUpperCase();
  return `PAY-${date}-${token}`;
};

const normalizePaymentKind = (value) => normalizeText(value, 20).toLowerCase();

export const validatePaymentRequestInput = (payload) => {
  const caseId = normalizeCaseId(payload.caseId);
  const paymentKind = normalizePaymentKind(payload.paymentKind || payload.kind || "custom");
  const label = normalizeText(payload.label, 120);
  const description = normalizeMultilineText(payload.description, 300);
  const currency = normalizeText(payload.currency || "cad", 12).toLowerCase() || "cad";
  const amountCents = parseAmountToCents(payload.amount);
  const sendEmail = payload.sendEmail === true || payload.sendEmail === "true" || payload.sendEmail === "on";

  if (!caseId) {
    throw new Error("Numéro de dossier invalide.");
  }

  if (!allowedPaymentKinds.has(paymentKind)) {
    throw new Error("Type de paiement invalide.");
  }

  if (!label) {
    throw new Error("Ajoutez un libellé de paiement.");
  }

  if (!description) {
    throw new Error("Ajoutez une description de paiement.");
  }

  return {
    caseId,
    paymentKind,
    label,
    description,
    currency,
    amountCents,
    sendEmail
  };
};

const ensureDb = (env) => {
  if (!env?.INTAKE_DB) {
    throw new Error("La base D1 n'est pas configurée.");
  }

  return env.INTAKE_DB;
};

const nowIso = () => new Date().toISOString();

const buildInitialTimeline = () => [
  {
    title: "Dossier reçu",
    note: "La demande a été enregistrée et qualifiée pour une première lecture.",
    state: "complete",
    sortOrder: 0
  },
  {
    title: "Évaluation en cours",
    note: "Lecture initiale du support et qualification du niveau de risque.",
    state: "active",
    sortOrder: 1
  },
  {
    title: "Soumission",
    note: "Cadre d'intervention et prochaines étapes transmis après l'évaluation.",
    state: "pending",
    sortOrder: 2
  },
  {
    title: "Traitement",
    note: "Commence après autorisation explicite du client.",
    state: "pending",
    sortOrder: 3
  }
];

export const getPublicOrigin = (env, requestUrl = "https://nexuradata.ca/") => {
  const configuredOrigin = normalizeText(env?.PUBLIC_SITE_ORIGIN, 200);

  if (configuredOrigin) {
    return configuredOrigin.replace(/\/+$/, "");
  }

  return new URL(requestUrl).origin.replace(/\/+$/, "");
};

export const createCase = async (env, submission) => {
  const db = ensureDb(env);
  const createdAt = nowIso();
  const caseId = generateCaseId();
  const accessCode = generateAccessCode();
  const accessCodeHash = await hashAccessCode(accessCode, env);
  const accessCodeCiphertext = await encryptAccessCode(accessCode, env);
  const timeline = buildInitialTimeline();
  const status = "Dossier reçu";
  const nextStep = "Lecture initiale du cas et qualification technique.";
  const clientSummary = "Votre demande a été reçue. Un dossier initial a été ouvert et le laboratoire prépare maintenant l'évaluation du cas.";

  await db
    .prepare(
      `INSERT INTO cases (
        case_id,
        created_at,
        updated_at,
        name,
        email,
        phone,
        support,
        urgency,
        message,
        source_path,
        status,
        next_step,
        client_summary,
        access_code_hash,
        access_code_ciphertext,
        access_code_last_sent_at,
        status_email_last_sent_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      caseId,
      createdAt,
      createdAt,
      submission.nom,
      submission.courriel,
      submission.telephone,
      submission.support,
      submission.urgence,
      submission.message,
      submission.sourcePath,
      status,
      nextStep,
      clientSummary,
      accessCodeHash,
      accessCodeCiphertext,
      "",
      ""
    )
    .run();

  for (const step of timeline) {
    await db
      .prepare(
        `INSERT INTO case_updates (
          case_id,
          kind,
          title,
          note,
          state,
          sort_order,
          is_visible,
          created_at,
          updated_at,
          created_by
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(caseId, "timeline", step.title, step.note, step.state, step.sortOrder, 1, createdAt, createdAt, "system")
      .run();
  }

  await recordCaseEvent(env, caseId, "system", "Dossier ouvert", "Demande initiale reçue via le formulaire public.");

  return {
    caseId,
    accessCode,
    createdAt,
    status,
    nextStep,
    clientSummary,
    ...submission
  };
};

export const recordCaseEvent = async (env, caseId, actor, title, note) => {
  const db = ensureDb(env);
  const timestamp = nowIso();

  await db
    .prepare(
      `INSERT INTO case_updates (
        case_id,
        kind,
        title,
        note,
        state,
        sort_order,
        is_visible,
        created_at,
        updated_at,
        created_by
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(caseId, "event", title, note, "complete", 0, 0, timestamp, timestamp, normalizeText(actor, 120) || "system")
    .run();
};

export const markAccessEmailSent = async (env, caseId) => {
  const db = ensureDb(env);
  const timestamp = nowIso();

  await db
    .prepare("UPDATE cases SET updated_at = ?, access_code_last_sent_at = ? WHERE case_id = ?")
    .bind(timestamp, timestamp, caseId)
    .run();
};

export const markStatusEmailSent = async (env, caseId) => {
  const db = ensureDb(env);
  const timestamp = nowIso();

  await db
    .prepare("UPDATE cases SET updated_at = ?, status_email_last_sent_at = ? WHERE case_id = ?")
    .bind(timestamp, timestamp, caseId)
    .run();
};

const mapTimelineStep = (row) => ({
  title: row.title,
  note: row.note,
  state: row.state
});

export const getVisibleTimeline = async (env, caseId) => {
  const db = ensureDb(env);
  const { results } = await db
    .prepare(
      `SELECT title, note, state
       FROM case_updates
       WHERE case_id = ? AND kind = 'timeline' AND is_visible = 1
       ORDER BY sort_order ASC, id ASC`
    )
    .bind(caseId)
    .all();

  return (results || []).map(mapTimelineStep);
};

const getCaseRow = async (env, caseId) => {
  const db = ensureDb(env);
  return db
    .prepare(
      `SELECT
        case_id,
        created_at,
        updated_at,
        name,
        email,
        phone,
        support,
        urgency,
        message,
        source_path,
        status,
        next_step,
        client_summary,
        access_code_hash,
        access_code_ciphertext,
        access_code_last_sent_at,
        status_email_last_sent_at,
        qualification_summary,
        internal_notes,
        handling_flags,
        quote_status,
        quote_amount_cents,
        quote_sent_at,
        quote_approved_at,
        preapproval_confirmed,
        acquisition_source,
        last_reminder_sent_at,
        last_client_contact_at
      FROM cases
      WHERE case_id = ?`
    )
    .bind(caseId)
    .first();
};

const mapPaymentRow = (row) => ({
  paymentRequestId: row.payment_request_id,
  caseId: row.case_id,
  paymentKind: row.payment_kind,
  status: row.status,
  label: row.label,
  description: row.description,
  amountCents: row.amount_cents,
  amountFormatted: formatCurrency(row.amount_cents, row.currency),
  currency: row.currency,
  checkoutUrl: row.checkout_url,
  stripeCheckoutSessionId: row.stripe_checkout_session_id,
  stripePaymentIntentId: row.stripe_payment_intent_id,
  stripeSessionStatus: row.stripe_session_status,
  stripePaymentStatus: row.stripe_payment_status,
  customerEmail: row.stripe_customer_email,
  createdAt: row.created_at,
  updatedAt: row.updated_at,
  sentAt: row.sent_at,
  paidAt: row.paid_at,
  expiresAt: row.expires_at,
  createdBy: row.created_by
});

const mapPublicPayment = (payment) => {
  const status = normalizeText(payment.status, 24).toLowerCase() || "open";
  const isPayable = status === "open" && normalizeText(payment.checkoutUrl, 2000);

  return {
    paymentRequestId: payment.paymentRequestId,
    paymentKind: payment.paymentKind,
    status,
    label: payment.label,
    description: payment.description,
    amountCents: payment.amountCents,
    amountFormatted: payment.amountFormatted,
    currency: payment.currency,
    checkoutUrl: isPayable ? payment.checkoutUrl : "",
    createdAt: payment.createdAt,
    sentAt: payment.sentAt,
    paidAt: payment.paidAt,
    expiresAt: payment.expiresAt
  };
};

export const listCasePayments = async (env, caseId) => {
  const db = ensureDb(env);
  const normalizedCaseId = normalizeCaseId(caseId);

  if (!normalizedCaseId) {
    return [];
  }

  const { results } = await db
    .prepare(
      `SELECT
        payment_request_id,
        case_id,
        payment_kind,
        status,
        label,
        description,
        amount_cents,
        currency,
        checkout_url,
        stripe_checkout_session_id,
        stripe_payment_intent_id,
        stripe_session_status,
        stripe_payment_status,
        stripe_customer_email,
        created_at,
        updated_at,
        sent_at,
        paid_at,
        expires_at,
        created_by
      FROM case_payments
      WHERE case_id = ?
      ORDER BY created_at DESC, id DESC`
    )
    .bind(normalizedCaseId)
    .all();

  return (results || []).map(mapPaymentRow);
};

export const getPublicCaseByCredentials = async (env, caseId, accessCode) => {
  const row = await getCaseRow(env, caseId);

  if (!row) {
    return null;
  }

  const hashed = await hashAccessCode(accessCode, env);

  if (hashed !== row.access_code_hash) {
    return null;
  }

  const payments = await listCasePayments(env, row.case_id);

  return {
    caseId: row.case_id,
    updatedAt: row.updated_at,
    support: row.support,
    status: row.status,
    nextStep: row.next_step,
    summary: row.client_summary,
    steps: await getVisibleTimeline(env, row.case_id),
    payments: payments.map(mapPublicPayment)
  };
};

export const listCases = async (env, rawQuery = "", filters = {}) => {
  const db = ensureDb(env);
  const query = normalizeText(rawQuery, 160);
  const conditions = [];
  const params = [];

  if (query) {
    const like = `%${query}%`;
    conditions.push("(case_id LIKE ? OR name LIKE ? OR email LIKE ? OR support LIKE ?)");
    params.push(like, like, like, like);
  }

  const filterStatus = normalizeText(filters.status || "", 80);
  const filterQuoteStatus = normalizeText(filters.quoteStatus || "", 40);
  const filterUrgency = normalizeText(filters.urgency || "", 40);

  if (filterStatus) {
    conditions.push("status = ?");
    params.push(filterStatus);
  }

  if (filterQuoteStatus) {
    conditions.push("quote_status = ?");
    params.push(filterQuoteStatus);
  }

  if (filterUrgency) {
    conditions.push("urgency = ?");
    params.push(filterUrgency);
  }

  const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";
  const sql = `SELECT
      case_id,
      created_at,
      updated_at,
      name,
      email,
      support,
      urgency,
      status,
      next_step,
      quote_status
    FROM cases
    ${whereClause}
    ORDER BY updated_at DESC
    LIMIT 25`;

  const stmt = db.prepare(sql);
  const { results } = params.length > 0 ? await stmt.bind(...params).all() : await stmt.all();
  return results || [];
};

export const getCaseDetail = async (env, caseId) => {
  const db = ensureDb(env);
  const normalizedCaseId = normalizeCaseId(caseId);
  const row = await getCaseRow(env, normalizedCaseId);

  if (!row) {
    return null;
  }

  const currentSteps = await getVisibleTimeline(env, normalizedCaseId);
  const payments = await listCasePayments(env, normalizedCaseId);
  const { results: history } = await db
    .prepare(
      `SELECT
        kind,
        title,
        note,
        state,
        is_visible,
        created_at,
        created_by
      FROM case_updates
      WHERE case_id = ?
      ORDER BY created_at DESC, id DESC
      LIMIT 20`
    )
    .bind(normalizedCaseId)
    .all();

  return {
    caseId: row.case_id,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    name: row.name,
    email: row.email,
    phone: row.phone,
    support: row.support,
    urgency: row.urgency,
    message: row.message,
    sourcePath: row.source_path,
    status: row.status,
    nextStep: row.next_step,
    clientSummary: row.client_summary,
    accessCodeLastSentAt: row.access_code_last_sent_at,
    statusEmailLastSentAt: row.status_email_last_sent_at,
    qualificationSummary: row.qualification_summary,
    internalNotes: row.internal_notes,
    handlingFlags: row.handling_flags,
    quoteStatus: row.quote_status,
    quoteAmountCents: row.quote_amount_cents,
    quoteSentAt: row.quote_sent_at,
    quoteApprovedAt: row.quote_approved_at,
    preapprovalConfirmed: Boolean(row.preapproval_confirmed),
    acquisitionSource: row.acquisition_source,
    lastReminderSentAt: row.last_reminder_sent_at,
    lastClientContactAt: row.last_client_contact_at,
    steps: currentSteps,
    payments,
    history: (history || []).map((entry) => ({
      kind: entry.kind,
      title: entry.title,
      note: entry.note,
      state: entry.state,
      isVisible: Boolean(entry.is_visible),
      createdAt: entry.created_at,
      createdBy: entry.created_by
    }))
  };
};

export const updateCaseRecord = async (env, payload, actor) => {
  const db = ensureDb(env);
  const caseId = normalizeCaseId(payload.caseId);
  const status = normalizeText(payload.status, 80);
  const nextStep = normalizeText(payload.nextStep, 180);
  const clientSummary = normalizeMultilineText(payload.clientSummary, 800);
  const qualificationSummary = normalizeMultilineText(payload.qualificationSummary ?? "", 1200);
  const internalNotes = normalizeMultilineText(payload.internalNotes ?? "", 3000);
  const handlingFlags = normalizeText(payload.handlingFlags ?? "", 400);
  const acquisitionSource = normalizeText(payload.acquisitionSource ?? "", 120);
  const quoteAmountCents = payload.quoteAmount !== undefined && payload.quoteAmount !== null && payload.quoteAmount !== ""
    ? parseAmountToCents(payload.quoteAmount)
    : null;
  const preapprovalConfirmed = payload.preapprovalConfirmed === true || payload.preapprovalConfirmed === "true" ? 1 : 0;
  const steps = validateTimelineSteps(payload.steps);

  if (!caseId || !status || !nextStep || !clientSummary) {
    throw new Error("Complétez le statut, la prochaine étape et le résumé client.");
  }

  const existing = await getCaseRow(env, caseId);

  if (!existing) {
    throw new Error("Dossier introuvable.");
  }

  const timestamp = nowIso();

  await db
    .prepare(
      `UPDATE cases
       SET updated_at = ?,
           status = ?,
           next_step = ?,
           client_summary = ?,
           qualification_summary = ?,
           internal_notes = ?,
           handling_flags = ?,
           acquisition_source = ?,
           quote_amount_cents = ?,
           preapproval_confirmed = ?
       WHERE case_id = ?`
    )
    .bind(
      timestamp,
      status,
      nextStep,
      clientSummary,
      qualificationSummary,
      internalNotes,
      handlingFlags,
      acquisitionSource,
      quoteAmountCents,
      preapprovalConfirmed,
      caseId
    )
    .run();

  if (steps) {
    await db
      .prepare(
        `UPDATE case_updates
         SET is_visible = 0, updated_at = ?
         WHERE case_id = ? AND kind = 'timeline' AND is_visible = 1`
      )
      .bind(timestamp, caseId)
      .run();

    for (const step of steps) {
      await db
        .prepare(
          `INSERT INTO case_updates (
            case_id,
            kind,
            title,
            note,
            state,
            sort_order,
            is_visible,
            created_at,
            updated_at,
            created_by
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .bind(caseId, "timeline", step.title, step.note, step.state, step.sortOrder, 1, timestamp, timestamp, normalizeText(actor, 120) || "ops")
        .run();
    }
  }

  await recordCaseEvent(env, caseId, actor, "Dossier mis à jour", `Statut défini sur "${status}".`);

  return getCaseDetail(env, caseId);
};

export const regenerateCaseAccessCode = async (env, caseId, actor) => {
  const db = ensureDb(env);
  const normalizedCaseId = normalizeCaseId(caseId);
  const row = await getCaseRow(env, normalizedCaseId);

  if (!row) {
    throw new Error("Dossier introuvable.");
  }

  const accessCode = generateAccessCode();
  const accessCodeHash = await hashAccessCode(accessCode, env);
  const accessCodeCiphertext = await encryptAccessCode(accessCode, env);
  const timestamp = nowIso();

  await db
    .prepare(
      `UPDATE cases
       SET updated_at = ?, access_code_hash = ?, access_code_ciphertext = ?, access_code_last_sent_at = ?
       WHERE case_id = ?`
    )
    .bind(timestamp, accessCodeHash, accessCodeCiphertext, "", normalizedCaseId)
    .run();

  await recordCaseEvent(env, normalizedCaseId, actor, "Code d'accès régénéré", "Un nouveau code d'accès client a été généré.");

  return {
    caseId: normalizedCaseId,
    accessCode,
    email: row.email,
    name: row.name,
    status: row.status,
    nextStep: row.next_step,
    clientSummary: row.client_summary
  };
};

export const getResendableAccessCode = async (env, caseId) => {
  const row = await getCaseRow(env, normalizeCaseId(caseId));

  if (!row) {
    throw new Error("Dossier introuvable.");
  }

  const accessCode = await decryptAccessCode(row.access_code_ciphertext, env);

  if (!accessCode) {
    throw new Error("Le code actuel n'est pas récupérable. Générez-en un nouveau.");
  }

  return {
    caseId: row.case_id,
    accessCode,
    email: row.email,
    name: row.name,
    status: row.status,
    nextStep: row.next_step,
    clientSummary: row.client_summary
  };
};

const getPaymentRequestRow = async (env, paymentRequestId) => {
  const db = ensureDb(env);

  return db
    .prepare(
      `SELECT
        payment_request_id,
        case_id,
        payment_kind,
        status,
        label,
        description,
        amount_cents,
        currency,
        checkout_url,
        stripe_checkout_session_id,
        stripe_payment_intent_id,
        stripe_session_status,
        stripe_payment_status,
        stripe_customer_email,
        created_at,
        updated_at,
        sent_at,
        paid_at,
        expires_at,
        created_by
      FROM case_payments
      WHERE payment_request_id = ?`
    )
    .bind(normalizeText(paymentRequestId, 60))
    .first();
};

export const markPaymentRequestSent = async (env, paymentRequestId) => {
  const db = ensureDb(env);
  const normalizedRequestId = normalizeText(paymentRequestId, 60);
  const timestamp = nowIso();

  await db
    .prepare(
      `UPDATE case_payments
       SET updated_at = ?, sent_at = ?
       WHERE payment_request_id = ?`
    )
    .bind(timestamp, timestamp, normalizedRequestId)
    .run();

  return getPaymentRequestRow(env, normalizedRequestId);
};

export const createCasePaymentRequest = async (env, payload, actor, requestUrl) => {
  const db = ensureDb(env);
  const input = validatePaymentRequestInput(payload);
  const row = await getCaseRow(env, input.caseId);

  if (!row) {
    throw new Error("Dossier introuvable.");
  }

  const paymentRequestId = generatePaymentRequestId();
  const createdAt = nowIso();
  const successUrl = `${getPublicOrigin(env, requestUrl)}/paiement-reussi.html?caseId=${encodeURIComponent(input.caseId)}&paymentRequestId=${encodeURIComponent(paymentRequestId)}`;
  const cancelUrl = `${getPublicOrigin(env, requestUrl)}/paiement-annule.html?caseId=${encodeURIComponent(input.caseId)}&paymentRequestId=${encodeURIComponent(paymentRequestId)}`;
  const session = await createHostedCheckoutSession(env, {
    caseId: input.caseId,
    paymentRequestId,
    paymentKind: input.paymentKind,
    label: input.label,
    description: input.description,
    amountCents: input.amountCents,
    currency: input.currency,
    customerEmail: row.email,
    successUrl,
    cancelUrl
  });
  const localStatus = `${session?.payment_status || ""}`.toLowerCase() === "paid" ? "paid" : "open";
  const expiresAt = Number.isFinite(Number(session?.expires_at))
    ? new Date(Number(session.expires_at) * 1000).toISOString()
    : "";

  await db
    .prepare(
      `INSERT INTO case_payments (
        payment_request_id,
        case_id,
        payment_kind,
        status,
        label,
        description,
        amount_cents,
        currency,
        checkout_url,
        stripe_checkout_session_id,
        stripe_payment_intent_id,
        stripe_session_status,
        stripe_payment_status,
        stripe_customer_email,
        created_at,
        updated_at,
        sent_at,
        paid_at,
        expires_at,
        created_by
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      paymentRequestId,
      input.caseId,
      input.paymentKind,
      localStatus,
      input.label,
      input.description,
      input.amountCents,
      input.currency,
      normalizeText(session?.url, 2000),
      normalizeText(session?.id, 120),
      normalizeText(`${session?.payment_intent || ""}`, 120),
      normalizeText(`${session?.status || ""}`, 40).toLowerCase(),
      normalizeText(`${session?.payment_status || ""}`, 40).toLowerCase(),
      row.email,
      createdAt,
      createdAt,
      "",
      localStatus === "paid" ? createdAt : "",
      expiresAt,
      normalizeText(actor, 120) || "ops"
    )
    .run();

  await recordCaseEvent(
    env,
    input.caseId,
    actor,
    "Demande de paiement créée",
    `${input.label} · ${formatCurrency(input.amountCents, input.currency)}.`
  );

  const saved = await getPaymentRequestRow(env, paymentRequestId);
  return saved ? mapPaymentRow(saved) : null;
};

export const updateQuoteStatus = async (env, payload, actor) => {
  const db = ensureDb(env);
  const caseId = normalizeCaseId(payload.caseId);
  const targetStatus = normalizeText(payload.quoteStatus, 20).toLowerCase();

  if (!caseId) {
    throw new Error("Numéro de dossier invalide.");
  }

  if (!allowedQuoteStatuses.has(targetStatus) || targetStatus === "none") {
    throw new Error("Statut de soumission invalide.");
  }

  const row = await getCaseRow(env, caseId);

  if (!row) {
    throw new Error("Dossier introuvable.");
  }

  const timestamp = nowIso();
  const updates = [`updated_at = ?`, `quote_status = ?`];
  const params = [timestamp, targetStatus];

  if (targetStatus === "sent") {
    updates.push(`quote_sent_at = ?`);
    params.push(timestamp);

    if (payload.quoteAmount !== undefined && payload.quoteAmount !== null && payload.quoteAmount !== "") {
      updates.push(`quote_amount_cents = ?`);
      params.push(parseAmountToCents(payload.quoteAmount));
    }
  }

  if (targetStatus === "approved") {
    updates.push(`quote_approved_at = ?`);
    params.push(timestamp);
  }

  params.push(caseId);

  await db
    .prepare(`UPDATE cases SET ${updates.join(", ")} WHERE case_id = ?`)
    .bind(...params)
    .run();

  const titleMap = {
    sent: "Soumission envoyée",
    approved: "Soumission approuvée",
    expired: "Soumission expirée",
    declined: "Soumission refusée",
    draft: "Soumission en brouillon"
  };

  await recordCaseEvent(env, caseId, actor, titleMap[targetStatus] || "Soumission mise à jour", `Statut de la soumission défini sur "${targetStatus}".`);

  return getCaseDetail(env, caseId);
};

export const logReminder = async (env, payload, actor) => {
  const db = ensureDb(env);
  const caseId = normalizeCaseId(payload.caseId);
  const reminderType = normalizeText(payload.reminderType, 40).toLowerCase();
  const message = normalizeMultilineText(payload.message || "", 500);

  if (!caseId) {
    throw new Error("Numéro de dossier invalide.");
  }

  if (!allowedReminderTypes.has(reminderType)) {
    throw new Error("Type de relance invalide.");
  }

  const row = await getCaseRow(env, caseId);

  if (!row) {
    throw new Error("Dossier introuvable.");
  }

  const timestamp = nowIso();

  await db
    .prepare(
      `UPDATE cases SET updated_at = ?, last_reminder_sent_at = ?, last_client_contact_at = ? WHERE case_id = ?`
    )
    .bind(timestamp, timestamp, timestamp, caseId)
    .run();

  const typeLabels = {
    quote_follow_up: "Relance soumission",
    payment_follow_up: "Relance paiement",
    missing_information: "Demande d'information",
    general_follow_up: "Relance générale"
  };

  await recordCaseEvent(env, caseId, actor, typeLabels[reminderType] || "Relance envoyée", message || `Type: ${reminderType}`);

  return getCaseDetail(env, caseId);
};

export const syncPaymentRequestFromStripe = async (env, event) => {
  const db = ensureDb(env);
  const session = event?.data?.object;

  if (!session || session.object !== "checkout.session") {
    return null;
  }

  const paymentRequestId = normalizeText(session?.metadata?.payment_request_id || session?.client_reference_id, 60);

  if (!paymentRequestId) {
    return null;
  }

  const existing = await getPaymentRequestRow(env, paymentRequestId);

  if (!existing) {
    return null;
  }

  const eventType = normalizeText(event?.type, 80);
  let localStatus = existing.status || "open";

  if (eventType === "checkout.session.completed" || eventType === "checkout.session.async_payment_succeeded") {
    localStatus = "paid";
  } else if (eventType === "checkout.session.expired") {
    localStatus = "expired";
  } else if (eventType === "checkout.session.async_payment_failed") {
    localStatus = "failed";
  }

  const timestamp = nowIso();
  const paidAt = localStatus === "paid" ? existing.paid_at || timestamp : existing.paid_at || "";
  const expiresAt = Number.isFinite(Number(session?.expires_at))
    ? new Date(Number(session.expires_at) * 1000).toISOString()
    : existing.expires_at || "";

  await db
    .prepare(
      `UPDATE case_payments
       SET
         updated_at = ?,
         status = ?,
         checkout_url = ?,
         stripe_checkout_session_id = ?,
         stripe_payment_intent_id = ?,
         stripe_session_status = ?,
         stripe_payment_status = ?,
         paid_at = ?,
         expires_at = ?
       WHERE payment_request_id = ?`
    )
    .bind(
      timestamp,
      localStatus,
      normalizeText(session?.url || existing.checkout_url, 2000),
      normalizeText(session?.id || existing.stripe_checkout_session_id, 120),
      normalizeText(`${session?.payment_intent || existing.stripe_payment_intent_id || ""}`, 120),
      normalizeText(`${session?.status || existing.stripe_session_status || ""}`, 40).toLowerCase(),
      normalizeText(`${session?.payment_status || existing.stripe_payment_status || ""}`, 40).toLowerCase(),
      paidAt,
      expiresAt,
      paymentRequestId
    )
    .run();

  if (localStatus !== existing.status) {
    const title =
      localStatus === "paid"
        ? "Paiement reçu"
        : localStatus === "expired"
          ? "Lien de paiement expiré"
          : "Paiement non complété";
    const note =
      localStatus === "paid"
        ? `${existing.label} réglé pour ${formatCurrency(existing.amount_cents, existing.currency)}.`
        : localStatus === "expired"
          ? `Le lien de paiement ${paymentRequestId} a expiré.`
          : `Le paiement ${paymentRequestId} n'a pas abouti.`;

    await recordCaseEvent(env, existing.case_id, "stripe-webhook", title, note);
  }

  const updated = await getPaymentRequestRow(env, paymentRequestId);
  return updated ? mapPaymentRow(updated) : null;
};

export const authorizeOpsRequest = (request, env) => {
  const configuredEmails = normalizeText(env?.OPS_ACCESS_ALLOWED_EMAILS, 500)
    .split(",")
    .map((entry) => entry.trim().toLowerCase())
    .filter(Boolean);
  const configuredDomain = normalizeText(env?.OPS_ACCESS_ALLOWED_DOMAIN, 120).toLowerCase();
  const authenticatedEmail = normalizeText(
    request.headers.get("Cf-Access-Authenticated-User-Email") || request.headers.get("cf-access-authenticated-user-email"),
    160
  ).toLowerCase();
  const hostname = new URL(request.url).hostname;
  const isLocal = localHostnames.has(hostname);

  if (isLocal) {
    return {
      ok: true,
      actor: authenticatedEmail || "local-dev"
    };
  }

  if (configuredEmails.length === 0 && !configuredDomain) {
    return {
      ok: false
    };
  }

  if (!authenticatedEmail) {
    return {
      ok: false
    };
  }

  if (configuredEmails.includes(authenticatedEmail)) {
    return {
      ok: true,
      actor: authenticatedEmail
    };
  }

  if (configuredDomain && authenticatedEmail.endsWith(`@${configuredDomain}`)) {
    return {
      ok: true,
      actor: authenticatedEmail
    };
  }

  return {
    ok: false
  };
};

export const listQuotes = async (env, filters = {}) => {
  const db = ensureDb(env);
  const conditions = [];
  const params = [];

  conditions.push("quote_status != 'none'");

  const filterQuoteStatus = normalizeText(filters.quoteStatus || "", 40);
  const filterQuery = normalizeText(filters.query || "", 160);

  if (filterQuoteStatus) {
    conditions.push("quote_status = ?");
    params.push(filterQuoteStatus);
  }

  if (filterQuery) {
    const like = `%${filterQuery}%`;
    conditions.push("(case_id LIKE ? OR name LIKE ? OR email LIKE ?)");
    params.push(like, like, like);
  }

  const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";
  const sql = `SELECT
      case_id,
      name,
      email,
      status,
      next_step,
      quote_status,
      quote_amount_cents,
      quote_sent_at,
      quote_approved_at,
      preapproval_confirmed,
      last_reminder_sent_at,
      updated_at
    FROM cases
    ${whereClause}
    ORDER BY
      CASE quote_status WHEN 'sent' THEN 0 WHEN 'draft' THEN 1 WHEN 'approved' THEN 2 WHEN 'expired' THEN 3 WHEN 'declined' THEN 4 ELSE 5 END,
      updated_at DESC
    LIMIT 50`;

  const stmt = db.prepare(sql);
  const { results } = params.length > 0 ? await stmt.bind(...params).all() : await stmt.all();

  return (results || []).map((row) => {
    let reminderDue = "";

    if (row.quote_status === "sent" && row.quote_sent_at) {
      const sentDate = new Date(row.quote_sent_at);
      const daysSinceSent = Math.floor((Date.now() - sentDate.getTime()) / (1000 * 60 * 60 * 24));

      if (daysSinceSent >= 7) {
        reminderDue = "urgente";
      } else if (daysSinceSent >= 3) {
        reminderDue = "suggérée";
      }
    }

    return {
      caseId: row.case_id,
      clientName: row.name,
      clientEmail: row.email,
      caseStatus: row.status,
      nextStep: row.next_step,
      quoteStatus: row.quote_status,
      quoteAmountCents: row.quote_amount_cents,
      quoteAmountFormatted: row.quote_amount_cents ? formatCurrency(row.quote_amount_cents) : "",
      quoteSentAt: row.quote_sent_at,
      quoteApprovedAt: row.quote_approved_at,
      preapprovalConfirmed: Boolean(row.preapproval_confirmed),
      lastReminderSentAt: row.last_reminder_sent_at,
      reminderDue,
      updatedAt: row.updated_at
    };
  });
};

export const listAllPayments = async (env, filters = {}) => {
  const db = ensureDb(env);
  const conditions = [];
  const params = [];

  const filterStatus = normalizeText(filters.status || "", 40);
  const filterKind = normalizeText(filters.kind || "", 40);
  const filterQuery = normalizeText(filters.query || "", 160);

  if (filterStatus) {
    conditions.push("cp.status = ?");
    params.push(filterStatus);
  }

  if (filterKind) {
    conditions.push("cp.payment_kind = ?");
    params.push(filterKind);
  }

  if (filterQuery) {
    const like = `%${filterQuery}%`;
    conditions.push("(cp.case_id LIKE ? OR c.name LIKE ? OR c.email LIKE ? OR cp.payment_request_id LIKE ?)");
    params.push(like, like, like, like);
  }

  const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";
  const sql = `SELECT
      cp.payment_request_id,
      cp.case_id,
      c.name,
      c.email,
      cp.payment_kind,
      cp.status,
      cp.label,
      cp.amount_cents,
      cp.currency,
      cp.created_at,
      cp.sent_at,
      cp.paid_at,
      cp.expires_at
    FROM case_payments cp
    LEFT JOIN cases c ON cp.case_id = c.case_id
    ${whereClause}
    ORDER BY
      CASE cp.status WHEN 'open' THEN 0 WHEN 'paid' THEN 1 WHEN 'expired' THEN 2 WHEN 'failed' THEN 3 ELSE 4 END,
      cp.created_at DESC
    LIMIT 50`;

  const stmt = db.prepare(sql);
  const { results } = params.length > 0 ? await stmt.bind(...params).all() : await stmt.all();

  return (results || []).map((row) => ({
    paymentRequestId: row.payment_request_id,
    caseId: row.case_id,
    clientName: row.name,
    clientEmail: row.email,
    paymentKind: row.payment_kind,
    status: row.status,
    label: row.label,
    amountCents: row.amount_cents,
    amountFormatted: formatCurrency(row.amount_cents, row.currency),
    currency: row.currency,
    createdAt: row.created_at,
    sentAt: row.sent_at,
    paidAt: row.paid_at,
    expiresAt: row.expires_at
  }));
};

export const listFollowUps = async (env, filters = {}) => {
  const db = ensureDb(env);
  const conditions = [];
  const params = [];

  conditions.push("status NOT IN ('completed', 'closed')");

  const filterReason = normalizeText(filters.reason || "", 60);
  const filterQuery = normalizeText(filters.query || "", 160);
  const daysSince = Number(filters.daysSinceLastContact) || 0;

  if (filterReason === "quote_pending") {
    conditions.push("quote_status = 'sent'");
  } else if (filterReason === "payment_open") {
    conditions.push("case_id IN (SELECT case_id FROM case_payments WHERE status = 'open')");
  } else if (filterReason === "awaiting_authorization") {
    conditions.push("quote_status = 'approved'");
    conditions.push("preapproval_confirmed = 0");
  } else if (filterReason === "missing_information") {
    conditions.push("status IN ('awaiting_client', 'En attente du client')");
    conditions.push("quote_status IN ('none', 'draft')");
  } else if (filterReason === "dormant") {
    conditions.push("status IN ('awaiting_client', 'paused', 'En attente du client', 'En pause')");
    conditions.push("updated_at < datetime('now', '-7 days')");
  } else if (filterReason === "new_unqualified") {
    conditions.push("status IN ('new', 'Dossier reçu')");
  }

  if (daysSince > 0) {
    conditions.push("(last_client_contact_at = '' OR last_client_contact_at < datetime('now', '-' || ? || ' days'))");
    params.push(String(daysSince));
  }

  if (filterQuery) {
    const like = `%${filterQuery}%`;
    conditions.push("(case_id LIKE ? OR name LIKE ? OR email LIKE ?)");
    params.push(like, like, like);
  }

  const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";
  const sql = `SELECT
      case_id,
      name,
      email,
      status,
      next_step,
      quote_status,
      last_reminder_sent_at,
      last_client_contact_at,
      updated_at,
      (SELECT cp.status FROM case_payments cp WHERE cp.case_id = cases.case_id ORDER BY cp.created_at DESC LIMIT 1) AS latest_payment_status
    FROM cases
    ${whereClause}
    ORDER BY
      CASE WHEN last_client_contact_at = '' THEN 0 ELSE 1 END,
      last_client_contact_at ASC,
      updated_at ASC
    LIMIT 50`;

  const stmt = db.prepare(sql);
  const { results } = params.length > 0 ? await stmt.bind(...params).all() : await stmt.all();

  return (results || []).map((row) => ({
    caseId: row.case_id,
    clientName: row.name,
    clientEmail: row.email,
    status: row.status,
    nextStep: row.next_step,
    quoteStatus: row.quote_status,
    latestPaymentStatus: row.latest_payment_status || "none",
    lastReminderSentAt: row.last_reminder_sent_at,
    lastClientContactAt: row.last_client_contact_at,
    updatedAt: row.updated_at
  }));
};

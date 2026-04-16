import { createCase, validateSubmission } from "../_lib/cases.js";
import { sendClientAccessEmail, sendLabNotificationEmail } from "../_lib/email.js";
import { json, methodNotAllowed, onOptions, parsePayload } from "../_lib/http.js";

export const onRequestOptions = () => onOptions("POST, OPTIONS");

export const onRequestPost = async (context) => {
  try {
    if (!context.env?.INTAKE_DB) {
      return json(
        {
          ok: false,
          fallback: "mailto",
          message: "Le backend de prise en charge n'est pas encore configuré. Le formulaire bascule vers le courriel préparé."
        },
        { status: 503 }
      );
    }

    if (!context.env?.ACCESS_CODE_SECRET) {
      return json(
        {
          ok: false,
          message: "Configuration incomplète. Contactez l'administrateur."
        },
        { status: 503 }
      );
    }

    const payload = await parsePayload(context.request);
    const submission = validateSubmission(payload);
    const intakeRecord = await createCase(context.env, submission);
    const [labDelivery, clientDelivery] = await Promise.all([
      sendLabNotificationEmail(context.env, intakeRecord, context.request.url),
      sendClientAccessEmail(
        context.env,
        {
          caseId: intakeRecord.caseId,
          accessCode: intakeRecord.accessCode,
          email: intakeRecord.courriel,
          name: intakeRecord.nom,
          status: intakeRecord.status,
          nextStep: intakeRecord.nextStep
        },
        context.request.url,
        "initial"
      )
    ]);

    return json({
      ok: true,
      caseId: intakeRecord.caseId,
      message: "Demande reçue. Un numéro de dossier initial a été généré.",
      nextStep: "Le laboratoire peut maintenant qualifier le cas et préparer la suite.",
      delivery: {
        lab: labDelivery.sent ? "sent" : labDelivery.reason,
        client: clientDelivery.sent ? "sent" : clientDelivery.reason
      }
    });
  } catch (error) {
    return json(
      {
        ok: false,
        message: error instanceof Error ? error.message : "Erreur de traitement."
      },
      { status: 400 }
    );
  }
};

export const onRequest = methodNotAllowed;

import { getPublicCaseByCredentials, validateStatusLookup } from "../_lib/cases.js";
import { json, methodNotAllowed, onOptions, parsePayload } from "../_lib/http.js";

const genericErrorMessage = "Aucun dossier n'a été trouvé avec cet accès. Vérifiez les identifiants transmis par NEXURADATA ou demandez une mise à jour.";

export const onRequestOptions = () => onOptions("POST, OPTIONS");

export const onRequestPost = async (context) => {
  try {
    if (!context.env?.INTAKE_DB) {
      return json({ ok: false, message: "Service temporairement indisponible." }, { status: 503 });
    }
    const payload = await parsePayload(context.request);
    const { caseId, accessCode } = validateStatusLookup(payload);
    const detail = await getPublicCaseByCredentials(context.env, caseId, accessCode);

    if (!detail) {
      return json(
        {
          ok: false,
          message: genericErrorMessage
        },
        { status: 404 }
      );
    }

    return json({
      ok: true,
      caseId: detail.caseId,
      status: detail.status,
      updatedAt: detail.updatedAt,
      support: detail.support,
      nextStep: detail.nextStep,
      summary: detail.summary,
      steps: detail.steps,
      payments: detail.payments
    });
  } catch (error) {
    const message = error instanceof Error && error.message.includes("numéro de dossier")
      ? error.message
      : genericErrorMessage;

    return json(
      {
        ok: false,
        message
      },
      { status: 400 }
    );
  }
};

export const onRequest = methodNotAllowed;

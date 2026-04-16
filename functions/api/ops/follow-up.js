import { authorizeOpsRequest, listFollowUps } from "../../_lib/cases.js";
import { json, methodNotAllowed, onOptions } from "../../_lib/http.js";

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

export const onRequestOptions = () => onOptions("GET, OPTIONS");

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
    const items = await listFollowUps(context.env, {
      reason: url.searchParams.get("reason") || "",
      daysSinceLastContact: url.searchParams.get("days") || "",
      query: url.searchParams.get("query") || ""
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

export const onRequest = methodNotAllowed;

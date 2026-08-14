import {
  addChatMessage,
  addEscrowAsClient,
  addPaymentAsAdmin,
  deleteChatMessage,
  deletePaymentAsAdmin,
  deleteUserAsAdmin,
  deleteWorkLog,
  editChatMessage,
  editPaymentAsAdmin,
  getPortalData,
  refreshPortal,
  requestEmailVerification,
  requestPasswordReset,
  resetPassword,
  savePaymentMethod,
  saveProfile,
  saveWorkLog,
  setUserPasswordAsAdmin,
  signIn,
  signUp,
  verifyEmail,
  updateUserAsAdmin,
} from "../lib/portal-store.js";

function allowedOrigins() {
  return (process.env.ALLOWED_ORIGINS || "")
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean);
}

function setCors(request, response) {
  const origin = request.headers.origin;
  const origins = allowedOrigins();

  if (origin && (!origins.length || origins.includes(origin))) {
    response.setHeader("Access-Control-Allow-Origin", origin);
  } else if (!origin && !origins.length) {
    response.setHeader("Access-Control-Allow-Origin", "*");
  }

  response.setHeader("Vary", "Origin");
  response.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  response.setHeader("Access-Control-Allow-Headers", "Content-Type");
}

function sendJson(response, status, payload) {
  response.statusCode = status;
  response.setHeader("Content-Type", "application/json");
  response.end(JSON.stringify(payload));
}

function errorResponse(response, error, status = 400) {
  const message = error instanceof Error ? error.message : "Unexpected error";
  sendJson(response, status, { error: message });
}

async function readJson(request) {
  if (request.body && typeof request.body === "object") {
    return request.body;
  }

  if (typeof request.body === "string") {
    return request.body ? JSON.parse(request.body) : {};
  }

  const chunks = [];
  for await (const chunk of request) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }

  const rawBody = Buffer.concat(chunks).toString("utf8").trim();
  return rawBody ? JSON.parse(rawBody) : {};
}

export default async function handler(request, response) {
  setCors(request, response);

  if (request.method === "OPTIONS") {
    response.statusCode = 204;
    response.end();
    return;
  }

  if (request.method === "GET") {
    try {
      const url = new URL(request.url || "/", "http://localhost");
      const email = url.searchParams.get("email") || "";
      const sessionToken = url.searchParams.get("sessionToken") || "";
      if (!email) {
        return errorResponse(response, new Error("Email is required."), 400);
      }

      return sendJson(response, 200, await getPortalData(email, sessionToken));
    } catch (error) {
      return errorResponse(response, error, 500);
    }
  }

  if (request.method === "POST") {
    try {
      const payload = await readJson(request);
      const action = typeof payload.action === "string" ? payload.action : "";
      const email = typeof payload.email === "string" ? payload.email : "";

      if (!email) {
        return errorResponse(response, new Error("Email is required."), 400);
      }

      switch (action) {
        case "refreshPortal":
          return sendJson(response, 200, await refreshPortal(email, typeof payload.sessionToken === "string" ? payload.sessionToken : ""));
        case "requestPasswordReset":
          return sendJson(response, 200, await requestPasswordReset(email));
        case "resetPassword":
          return sendJson(
            response,
            200,
            await resetPassword(
              email,
              typeof payload.resetToken === "string" ? payload.resetToken : "",
              typeof payload.password === "string" ? payload.password : ""
            )
          );
        case "verifyEmail":
          return sendJson(response, 200, await verifyEmail(email, typeof payload.verifyToken === "string" ? payload.verifyToken : ""));
        case "signIn":
          return sendJson(
            response,
            200,
            await signIn(
              email,
              typeof payload.password === "string" ? payload.password : "",
              typeof payload.name === "string" ? payload.name : undefined
            )
          );
        case "signUp":
          return sendJson(
            response,
            200,
            await signUp(
              email,
              typeof payload.name === "string" ? payload.name : undefined,
              typeof payload.password === "string" ? payload.password : "",
              typeof payload.role === "string" ? payload.role : "bidder"
            )
          );
        case "updateUser":
          return sendJson(response, 200, await updateUserAsAdmin(email, payload));
        case "setUserPassword":
          return sendJson(response, 200, await setUserPasswordAsAdmin(email, payload));
        case "deleteUser":
          return sendJson(response, 200, await deleteUserAsAdmin(email, payload));
        case "requestEmailVerification":
          return sendJson(response, 200, await requestEmailVerification(email, payload));
        case "saveProfile":
          return sendJson(response, 200, await saveProfile(email, payload));
        case "addEscrow":
          return sendJson(response, 200, await addEscrowAsClient(email, payload));
        case "savePaymentMethod":
          return sendJson(response, 200, await savePaymentMethod(email, payload));
        case "saveWorkLog":
          return sendJson(response, 200, await saveWorkLog(email, payload));
        case "deleteWorkLog":
          return sendJson(response, 200, await deleteWorkLog(email, payload));
        case "addPayment":
          return sendJson(response, 200, await addPaymentAsAdmin(email, payload));
        case "editPayment":
          return sendJson(response, 200, await editPaymentAsAdmin(email, payload));
        case "deletePayment":
          return sendJson(response, 200, await deletePaymentAsAdmin(email, payload));
        case "addChatMessage":
          return sendJson(response, 200, await addChatMessage(email, payload));
        case "editChatMessage":
          return sendJson(response, 200, await editChatMessage(email, payload));
        case "deleteChatMessage":
          return sendJson(response, 200, await deleteChatMessage(email, payload));
        default:
          return errorResponse(response, new Error("Unknown action."), 400);
      }
    } catch (error) {
      return errorResponse(response, error, 500);
    }
  }

  response.setHeader("Allow", "GET,POST,OPTIONS");
  return errorResponse(response, new Error("Method not allowed."), 405);
}

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import portalHandler from "../api/portal.js";

test("declares the MongoDB portal API", async () => {
  const [api, store, packageJson, envExample] = await Promise.all([
    readFile(new URL("../api/portal.js", import.meta.url), "utf8"),
    readFile(new URL("../lib/portal-store.js", import.meta.url), "utf8"),
    readFile(new URL("../package.json", import.meta.url), "utf8"),
    readFile(new URL("../.env.local.example", import.meta.url), "utf8"),
  ]);

  for (const action of [
    "refreshPortal",
    "requestPasswordReset",
    "resetPassword",
    "verifyEmail",
    "signIn",
    "signUp",
    "updateUser",
    "setUserPassword",
    "requestEmailVerification",
    "savePaymentMethod",
    "saveWorkLog",
    "deleteWorkLog",
    "addPayment",
    "editPayment",
    "addChatMessage",
    "editChatMessage",
    "deleteChatMessage",
  ]) {
    assert.match(api, new RegExp(action));
    assert.match(store, new RegExp(action));
  }

  for (const collection of [
    "portal_users",
    "portal_payment_methods",
    "portal_work_logs",
    "portal_payments",
    "portal_chat_messages",
    "portal_sessions",
    "portal_auth_tokens",
    "portal_email_events",
  ]) {
    assert.match(store, new RegExp(collection));
  }

  const parsedPackage = JSON.parse(packageJson);
  assert.equal(parsedPackage.dependencies.mongodb.startsWith("^"), true);
  assert.match(store, /MONGODB_URI/);
  assert.match(store, /PORTAL_MODE/);
  assert.match(store, /hashPassword/);
  assert.match(store, /verifyPassword/);
  assert.match(store, /createSession/);
  assert.match(store, /passwordHash/);
  assert.match(store, /paidPaymentCoversDate/);
  assert.match(store, /paidPaymentCoversPayDate/);
  assert.match(store, /paymentFrequency/);
  assert.match(store, /paymentWeekday/);
  assert.match(store, /nextOpenPaymentDate/);
  assert.match(store, /Payment link is required for paid records/);
  assert.match(store, /needsEmailVerification/);
  assert.match(store, /Verify your email before signing in/);
  assert.match(store, /Paid work logs cannot be deleted/);
  assert.match(store, /workLogId/);
  assert.match(store, /BREVO_API_KEY/);
  assert.match(store, /EMAIL_FROM/);
  assert.match(store, /APP_BASE_URL/);
  assert.match(store, /emailVerifiedAt/);
  assert.match(store, /MAX_CHAT_ATTACHMENT_BYTES/);
  assert.match(store, /authorTimeZone/);
  assert.match(store, /deletedAt/);
  assert.match(envExample, /MONGODB_URI/);
  assert.match(envExample, /PORTAL_MODE/);
  assert.match(envExample, /APP_BASE_URL/);
  assert.match(envExample, /EMAIL_FROM/);
  assert.match(envExample, /BREVO_API_KEY/);
  assert.match(store, /Demo accounts are disabled in live mode/);
  assert.match(store, /firstLiveUser/);
  assert.match(api, /Access-Control-Allow-Origin/);
  assert.doesNotMatch(`${api}\n${store}\n${packageJson}`, /stripe|@neondatabase|drizzle|DATABASE_URL|cloudflare:workers|env\.DB/i);
});

test("handles CORS preflight without touching MongoDB", async () => {
  const headers = new Map();
  const response = {
    statusCode: 0,
    setHeader(key, value) {
      headers.set(key, value);
    },
    end() {},
  };

  await portalHandler({ method: "OPTIONS", headers: { origin: "http://localhost:3000" } }, response);

  assert.equal(response.statusCode, 204);
  assert.equal(headers.get("Access-Control-Allow-Methods"), "GET,POST,OPTIONS");
});

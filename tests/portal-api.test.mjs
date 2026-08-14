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
    "deleteUser",
    "requestEmailVerification",
    "saveProfile",
    "addEscrow",
    "createCreditDeposit",
    "addManualCredit",
    "markNotificationsRead",
    "releasePayment",
    "savePaymentMethod",
    "saveWorkLog",
    "deleteWorkLog",
    "addPayment",
    "editPayment",
    "deletePayment",
    "addChatMessage",
    "editChatMessage",
    "deleteChatMessage",
    "handleCryptomusWebhook",
  ]) {
    assert.match(api, new RegExp(action));
    assert.match(store, new RegExp(action));
  }

  for (const collection of [
    "portal_users",
    "portal_payment_methods",
    "portal_work_logs",
    "portal_payments",
    "portal_escrows",
    "portal_client_deposits",
    "portal_notifications",
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
  assert.match(store, /SUPER_ADMIN_EMAIL/);
  assert.match(store, /SUPER_ADMIN_PASSWORD/);
  assert.match(store, /super_admin/);
  assert.match(store, /client@portal\.local/);
  assert.match(store, /canonicalRole/);
  assert.match(store, /assignedAdminId/);
  assert.match(store, /visibleUsersForCurrentUser/);
  assert.match(store, /profileCompletedAt/);
  assert.match(store, /clientStats/);
  assert.match(store, /attachUserStats/);
  assert.match(store, /escrowFeeFor/);
  assert.match(store, /feeAmount/);
  assert.match(store, /hashPassword/);
  assert.match(store, /verifyPassword/);
  assert.match(store, /createSession/);
  assert.match(store, /passwordHash/);
  assert.match(store, /paidPaymentCoversDate/);
  assert.match(store, /paidPaymentCoversPayDate/);
  assert.match(store, /releasedPaymentOverlapsPeriod/);
  assert.match(store, /paymentFrequency/);
  assert.match(store, /paymentWeekday/);
  assert.match(store, /nextOpenPaymentDate/);
  assert.match(store, /Client does not have enough credits for this payment/);
  assert.match(store, /This bidder is contracted with another client/);
  assert.match(store, /needsEmailVerification/);
  assert.match(store, /Verify your email before signing in/);
  assert.match(store, /Verify your email before using the portal/);
  assert.match(store, /Password reset\. Check your email to verify your account before signing in/);
  assert.match(store, /Paid work logs cannot be deleted/);
  assert.match(store, /workLogId/);
  assert.match(store, /BREVO_API_KEY/);
  assert.match(store, /EMAIL_FROM/);
  assert.match(store, /APP_BASE_URL/);
  assert.match(store, /API_BASE_URL/);
  assert.match(store, /emailVerifiedAt/);
  assert.match(store, /MAX_CHAT_ATTACHMENT_BYTES/);
  assert.match(store, /authorTimeZone/);
  assert.match(store, /deletedAt/);
  assert.match(store, /chatContacts/);
  assert.match(store, /recipientId/);
  assert.match(store, /conversationId/);
  assert.match(store, /directMessageFilterForUser/);
  assert.match(store, /Select a valid inbox recipient/);
  assert.match(store, /Only super admins can delete inbox messages/);
  assert.match(store, /allowDirectMessages/);
  assert.match(store, /not accepting direct messages/);
  assert.match(store, /methodId/);
  assert.match(store, /CRYPTOMUS_MERCHANT_UUID/);
  assert.match(store, /CRYPTOMUS_PAYMENT_KEY/);
  assert.match(store, /CRYPTOMUS_PAYOUT_KEY/);
  assert.match(store, /CRYPTOMUS_API_BASE_URL/);
  assert.match(store, /CRYPTOMUS_CALLBACK_URL/);
  assert.match(store, /CRYPTOMUS_PAYOUT_TEST_MODE/);
  assert.match(store, /cryptomusSign/);
  assert.match(store, /createCryptomusPayout/);
  assert.match(store, /handleCryptomusPayoutWebhook/);
  assert.match(store, /Only clients can release bidder payments/);
  assert.match(store, /Bidder must save a crypto payout wallet first/);
  assert.match(store, /portal_client_deposits/);
  assert.match(store, /portal_notifications/);
  assert.match(store, /clientCreditBalance/);
  assert.match(store, /createSuperAdminCreditNotification/);
  assert.match(store, /Only super admins can add manual client credits/);
  assert.match(store, /Client credit added/);
  assert.match(envExample, /MONGODB_URI/);
  assert.match(envExample, /PORTAL_MODE/);
  assert.match(envExample, /SUPER_ADMIN_EMAIL/);
  assert.match(envExample, /SUPER_ADMIN_PASSWORD/);
  assert.match(envExample, /APP_BASE_URL/);
  assert.match(envExample, /API_BASE_URL/);
  assert.match(envExample, /EMAIL_FROM/);
  assert.match(envExample, /BREVO_API_KEY/);
  assert.match(envExample, /CRYPTOMUS_MERCHANT_UUID/);
  assert.match(envExample, /CRYPTOMUS_PAYMENT_KEY/);
  assert.match(envExample, /CRYPTOMUS_PAYOUT_KEY/);
  assert.match(envExample, /CRYPTOMUS_API_BASE_URL/);
  assert.match(envExample, /CRYPTOMUS_PAYOUT_TEST_MODE/);
  assert.match(store, /Demo accounts are disabled in live mode/);
  assert.match(store, /Account not found\. Please sign up first/);
  assert.doesNotMatch(store, /firstLiveUser/);
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

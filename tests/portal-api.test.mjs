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
    "createUser",
    "updateUser",
    "setUserPassword",
    "deleteUser",
    "requestEmailVerification",
    "saveProfile",
    "updateOwnEmail",
    "updateOwnPassword",
    "saveBidProfile",
    "deleteBidProfile",
    "assignBidProfile",
    "addEscrow",
    "createCreditDeposit",
    "adjustCredit",
    "addManualCredit",
    "convertMoneyToPostCredit",
    "createPost",
    "updatePost",
    "updatePostStatus",
    "deletePost",
    "createContract",
    "updateContract",
    "updateContractStatus",
    "updateContractPayday",
    "createDispute",
    "updateDispute",
    "addDisputeUpdate",
    "markNotificationsRead",
    "releasePayment",
    "completePayment",
    "requestWithdrawal",
    "savePaymentMethod",
    "saveWorkLog",
    "deleteWorkLog",
    "reviewWorkLog",
    "addPayment",
    "editPayment",
    "deletePayment",
    "addChatMessage",
    "addSupportMessage",
    "markChatConversationRead",
    "editChatMessage",
    "deleteChatMessage",
    "deleteChatConversation",
    "handleCryptomusWebhook",
  ]) {
    assert.match(api, new RegExp(action));
    assert.match(store, new RegExp(action));
  }
  assert.match(api, /publicPortal/);

  for (const collection of [
    "portal_users",
    "portal_payment_methods",
    "portal_work_logs",
    "portal_payments",
    "portal_escrows",
    "portal_client_deposits",
    "portal_credit_ledger",
    "portal_contracts",
    "portal_posts",
    "portal_bid_profiles",
    "portal_disputes",
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
  assert.match(store, /MANAGED_ROLES/);
  assert.match(store, /cleanManagedRole/);
  assert.match(store, /createUserAsAdmin/);
  assert.match(store, /Only super admins can add people/);
  assert.match(store, /assignedAdminId/);
  assert.match(store, /visibleUsersForCurrentUser/);
  assert.match(store, /profileCompletedAt/);
  assert.match(store, /publicId/);
  assert.match(store, /PUBLIC_USER_ID_PREFIX/);
  assert.match(store, /ensurePublicUserIds/);
  assert.match(store, /getUserByPublicId/);
  assert.match(store, /publicMarketplaceUser/);
  assert.match(store, /getPublicPortalData/);
  assert.match(store, /clientStats/);
  assert.match(store, /attachUserStats/);
  assert.match(store, /SIGNUP_POST_CREDIT/);
  assert.match(store, /POST_CREDIT_COST/);
  assert.match(store, /POST_CREDIT_MONEY_PRICE/);
  assert.match(store, /cleanPostCreditAmount/);
  assert.match(store, /creditBalancesForUser/);
  assert.match(store, /spendPostingCredit/);
  assert.match(store, /postCreditBalance/);
  assert.match(store, /monthly_post_credit/);
  assert.match(store, /rawPostCreditBalance/);
  assert.match(store, /convertMoneyToPostCredit/);
  assert.match(store, /money_to_post_credit/);
  assert.match(store, /profileCompleteForUser/);
  assert.match(store, /Complete your profile before using the portal/);
  assert.match(store, /saveBidProfile/);
  assert.match(store, /deleteBidProfile/);
  assert.match(store, /assignBidProfile/);
  assert.match(store, /notifyBidProfileAssigned/);
  assert.match(store, /bid_profile_assigned/);
  assert.match(store, /New bid profile assigned/);
  assert.match(store, /Bid profile updated/);
  assert.match(store, /lastFourSsn/);
  assert.match(store, /resumeUrl/);
  assert.match(store, /veteranStatus/);
  assert.match(store, /assignedBidderIds/);
  assert.match(store, /Only clients can attach bid profiles to bidders/);
  assert.match(store, /Select active bidders assigned to this client/);
  assert.match(store, /adjustCreditAsSuperAdmin/);
  assert.match(store, /contractFilterForUser/);
  assert.match(store, /postFilterForUser/);
  assert.match(store, /createContract/);
  assert.match(store, /targetUserPublicId/);
  assert.match(store, /CONTRACT_PAYMENT_STYLES/);
  assert.match(store, /contractPaymentTermsFromPayload/);
  assert.match(store, /paymentStyle/);
  assert.match(store, /fixedBudget/);
  assert.match(store, /hourlyRate/);
  assert.match(store, /regularSalary/);
  assert.match(store, /endDate/);
  assert.match(store, /Contract end date must be after the start date/);
  assert.match(store, /updateContract/);
  assert.match(store, /Only the client can edit contract content/);
  assert.match(store, /Only open contracts can be edited/);
  assert.match(store, /updateContractStatus/);
  assert.match(store, /CONTRACT_END_TYPES/);
  assert.match(store, /contractHasReleasedPayment/);
  assert.match(store, /endFeedback/);
  assert.match(store, /endReason/);
  assert.match(store, /paidBeforeEnding/);
  assert.match(store, /Add a short note about how the work went/);
  assert.match(store, /Add a reason before ending this unpaid contract/);
  assert.match(store, /contract_ended/);
  assert.match(store, /updateContractPayday/);
  assert.match(store, /contractNextPaymentDateFromPayload/);
  assert.match(store, /syncActiveContractNextPaymentDate/);
  assert.match(store, /addContractChatMessage/);
  assert.match(store, /contract_created/);
  assert.match(store, /contract_accepted/);
  assert.match(store, /relatedContractId/);
  assert.match(store, /Only the client can set the contract next payday/);
  assert.match(store, /Select a valid next payday/);
  assert.match(store, /createPost/);
  assert.match(store, /updatePost/);
  assert.match(store, /updatePostStatus/);
  assert.match(store, /deletePost/);
  assert.match(store, /repostPost/);
  assert.match(store, /You can only edit your own posts/);
  assert.match(store, /You can only delete\/close your own posts/);
  assert.match(store, /Free signup posting credit/);
  assert.match(store, /You need 1 post credit or \$0\.10 money credit to publish a post/);
  assert.match(store, /Only clients and bidders can publish posts/);
  assert.match(store, /Only clients can open disputes/);
  assert.match(store, /Only super admins can resolve disputes/);
  assert.match(store, /addDisputeUpdate/);
  assert.match(store, /Closed disputes cannot be updated/);
  assert.match(store, /dispute_updated/);
  assert.match(store, /escrowFeeFor/);
  assert.match(store, /feeAmount/);
  assert.match(store, /hashPassword/);
  assert.match(store, /verifyPassword/);
  assert.match(store, /createSession/);
  assert.match(store, /SESSION_MS = 4 \* 60 \* 60 \* 1000/);
  assert.match(store, /REMEMBERED_SESSION_MS = 5 \* 24 \* 60 \* 60 \* 1000/);
  assert.match(store, /sessionDurationMs/);
  assert.match(store, /rememberMe/);
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
  assert.match(store, /user_approval_requested/);
  assert.match(store, /New access approval request/);
  assert.match(store, /Verify your email before signing in/);
  assert.match(store, /Verify your email before using the portal/);
  assert.match(store, /Password reset\. Check your email to verify your account before signing in/);
  assert.match(store, /Email changed\. Check your email to verify the new address before signing in/);
  assert.match(store, /Current password is incorrect/);
  assert.match(store, /Paid work logs cannot be deleted/);
  assert.match(store, /workLogId/);
  assert.match(store, /WORK_LOG_REVIEW_STATUSES/);
  assert.match(store, /reviewStatus/);
  assert.match(store, /reviewNote/);
  assert.match(store, /reviewedByUserId/);
  assert.match(store, /notifyAssignedClientForWorkLog/);
  assert.match(store, /work_log_submitted/);
  assert.match(store, /work_log_updated/);
  assert.match(store, /work_log_approved/);
  assert.match(store, /work_log_changes_requested/);
  assert.match(store, /Only active clients can review work logs/);
  assert.match(store, /Add a suggestion before requesting edits/);
  assert.match(store, /BREVO_API_KEY/);
  assert.match(store, /EMAIL_FROM/);
  assert.match(store, /APP_BASE_URL/);
  assert.match(store, /API_BASE_URL/);
  assert.match(store, /emailVerifiedAt/);
  assert.match(store, /MAX_CHAT_ATTACHMENT_BYTES/);
  assert.match(store, /MAX_PROFILE_IMAGE_DATA_URL_LENGTH/);
  assert.match(store, /cleanProfileImageDataUrl/);
  assert.match(store, /profileImageDataUrl/);
  assert.match(store, /authorTimeZone/);
  assert.match(store, /deletedAt/);
  assert.match(store, /chatContacts/);
  assert.match(store, /recipientId/);
  assert.match(store, /conversationId/);
  assert.match(store, /relatedPostId/);
  assert.match(store, /Related post must belong to one of the inbox members/);
  assert.match(store, /directMessageFilterForUser/);
  assert.match(store, /supportMessageFilterForUser/);
  assert.match(store, /supportContactsForCurrentUser/);
  assert.match(store, /supportConversationId/);
  assert.match(store, /supportMessages/);
  assert.match(store, /Only active users can send support messages/);
  assert.match(store, /Select a valid support member/);
  assert.match(store, /markChatConversationRead/);
  assert.match(store, /readAt/);
  assert.match(store, /readByUserId/);
  assert.match(store, /Only direct participants can mark inbox messages read/);
  assert.match(store, /Select a valid inbox recipient/);
  assert.match(store, /Only super admins can delete inbox messages/);
  assert.match(store, /deleteChatConversation/);
  assert.match(store, /Only super admins can delete inbox conversations/);
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
  assert.match(store, /CLIENT_RELEASE_PAYMENT_TYPE/);
  assert.match(store, /recordBidderPaymentCredit/);
  assert.match(store, /client_release/);
  assert.match(store, /completePaymentAsSuperAdmin/);
  assert.match(store, /Only super admins can mark payments completed/);
  assert.match(store, /Only processing payments can be marked completed/);
  assert.match(store, /Payment link is required to mark completed/);
  assert.match(store, /completedAt/);
  assert.match(store, /completedByUserId/);
  assert.match(store, /sourcePaymentId/);
  assert.match(store, /baseAmount/);
  assert.match(store, /Select a valid scheduled payment to release/);
  assert.match(store, /Only approved work logs can be released/);
  assert.match(store, /requestWithdrawal/);
  assert.match(store, /WITHDRAWAL_PAYMENT_TYPE/);
  assert.match(store, /recordWithdrawalCreditHold/);
  assert.match(store, /withdrawal_request/);
  assert.match(store, /withdrawal_requested/);
  assert.match(store, /withdrawal_completed/);
  assert.match(store, /Super admins can monitor inbox conversations but cannot send direct messages/);
  assert.match(store, /Inbox messages are only for client-bidder communication/);
  assert.match(store, /target\.assignedAdminId === actor\.id/);
  assert.match(store, /Save a crypto payout wallet before requesting a withdrawal/);
  assert.match(store, /portal_client_deposits/);
  assert.match(store, /portal_notifications/);
  assert.match(store, /recipientUserId/);
  assert.match(store, /clientCreditBalance/);
  assert.match(store, /createSuperAdminCreditNotification/);
  assert.match(store, /Only super admins can adjust credits/);
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

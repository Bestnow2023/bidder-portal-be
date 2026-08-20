import { createHash, randomBytes, randomUUID, scrypt as scryptCallback, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";
import { MongoClient } from "mongodb";

const ADMIN_EMAIL = "admin@portal.local";
const CLIENT_EMAIL = "client@portal.local";
const DEFAULT_DB_NAME = "bidder_portal";
const DEMO_PASSWORD = "demo1234";
const DEMO_EMAILS = new Set([ADMIN_EMAIL, CLIENT_EMAIL, "maya.bidder@example.com", "pending.bidder@example.com"]);
const CLIENT_ROLES = new Set(["admin", "client"]);
const SIGNUP_ROLES = new Set(["client", "bidder", "developer"]);
const CHAT_ATTACHMENT_LIMIT = 3;
const MAX_CHAT_ATTACHMENT_BYTES = 2 * 1024 * 1024;
const MAX_CHAT_ATTACHMENT_DATA_URL_LENGTH = Math.ceil(MAX_CHAT_ATTACHMENT_BYTES * 1.4) + 250;
const BLOCKED_CHAT_ATTACHMENT_TYPES = new Set(["image/svg+xml", "text/html", "application/xhtml+xml"]);
const SESSION_DAYS = 14;
const SESSION_MS = SESSION_DAYS * 24 * 60 * 60 * 1000;
const RESET_TOKEN_MS = 60 * 60 * 1000;
const VERIFY_TOKEN_MS = 24 * 60 * 60 * 1000;
const EMAIL_VERIFICATION_SIGN_IN_ERROR = "Verify your email before signing in.";
const EMAIL_VERIFICATION_PORTAL_ERROR = "Verify your email before using the portal.";
const SIGNUP_POST_CREDIT = 10;
const POST_CREDIT_COST = 1;
const OPEN_CONTRACT_STATUSES = ["requested", "active"];
const CONTRACT_STATUSES = new Set(["requested", "active", "rejected", "ended"]);
const POST_STATUSES = new Set(["active", "closed"]);
const DISPUTE_STATUSES = new Set(["open", "reviewing", "resolved", "closed"]);
const WORK_LOG_REVIEW_STATUSES = new Set(["pending", "approved", "changes_requested"]);
const PUBLIC_USER_PROJECTION = { _id: 0, passwordHash: 0 };
const PAYMENT_FREQUENCIES = new Set(["weekly", "biweekly", "monthly"]);
const PAYMENT_WEEKDAYS = ["monday", "tuesday", "wednesday", "thursday", "friday"];
const CREDIT_CURRENCY = "USD";
const WEEKDAY_INDEX = {
  sunday: 0,
  monday: 1,
  tuesday: 2,
  wednesday: 3,
  thursday: 4,
  friday: 5,
  saturday: 6,
};

const scryptAsync = promisify(scryptCallback);

let mongoCache;
let activeDatabaseKey = "";
let schemaReady = false;
let schemaPromise = null;

function now() {
  return new Date().toISOString();
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function cleanText(value, fallback = "") {
  return typeof value === "string" ? value.trim() : fallback;
}

function cleanNumber(value, fallback = 0) {
  const number = Number(value);
  return Number.isFinite(number) && number >= 0 ? number : fallback;
}

function cleanSignedNumber(value, fallback = 0) {
  const number = Number(value);
  return Number.isFinite(number) ? number : fallback;
}

function createId(prefix) {
  return `${prefix}_${randomUUID()}`;
}

function cleanMimeType(value) {
  return cleanText(value, "application/octet-stream").toLowerCase().slice(0, 120) || "application/octet-stream";
}

function cleanPassword(value) {
  return typeof value === "string" ? value : "";
}

function canonicalRole(value) {
  const role = cleanText(value).toLowerCase();
  return role === "admin" ? "client" : role;
}

function cleanRole(value, fallback = "bidder") {
  const role = canonicalRole(value);
  return SIGNUP_ROLES.has(role) ? role : fallback;
}

function cleanProfileSkills(value) {
  const parts = Array.isArray(value) ? value : cleanText(value).split(",");
  return parts
    .map((part) => cleanText(part).slice(0, 60))
    .filter(Boolean)
    .slice(0, 12);
}

function cleanExtraFields(value) {
  return (Array.isArray(value) ? value : [])
    .map((field) => ({
      label: cleanText(field?.label).slice(0, 60),
      value: cleanText(field?.value).slice(0, 240),
    }))
    .filter((field) => field.label || field.value)
    .slice(0, 12);
}

function escrowFeeFor(amount) {
  return Math.round(amount * 0.05 * 100) / 100;
}

function roundMoney(amount) {
  return Math.round(cleanNumber(amount) * 100) / 100;
}

function roundSignedMoney(amount) {
  return Math.round(cleanSignedNumber(amount) * 100) / 100;
}

function cryptomusPaymentKey() {
  return cleanText(process.env.CRYPTOMUS_PAYMENT_KEY);
}

function cryptomusPayoutKey() {
  return cleanText(process.env.CRYPTOMUS_PAYOUT_KEY);
}

function cryptomusMerchantUuid() {
  return cleanText(process.env.CRYPTOMUS_MERCHANT_UUID);
}

function cryptomusApiBaseUrl() {
  return (cleanText(process.env.CRYPTOMUS_API_BASE_URL) || "https://api.cryptomus.com").replace(/\/$/, "");
}

function cryptomusCallbackUrl() {
  const explicitCallback = cleanText(process.env.CRYPTOMUS_CALLBACK_URL);
  if (explicitCallback) {
    return explicitCallback;
  }

  const apiBaseUrl = cleanText(process.env.API_BASE_URL).replace(/\/$/, "");
  return apiBaseUrl ? `${apiBaseUrl}/api/portal` : "";
}

function cryptomusSign(payload, paymentKey = cryptomusPaymentKey()) {
  const body = JSON.stringify(payload || {});
  return createHash("md5").update(`${Buffer.from(body).toString("base64")}${paymentKey}`).digest("hex");
}

function cryptomusPayoutTestMode() {
  return process.env.CRYPTOMUS_PAYOUT_TEST_MODE === "true" || (!isLiveMode() && !cryptomusPayoutKey());
}

function assertCryptomusConfigured() {
  if (!cryptomusPaymentKey() || !cryptomusMerchantUuid()) {
    throw new Error("Cryptomus is not configured.");
  }
}

function assertCryptomusPayoutConfigured() {
  if (cryptomusPayoutTestMode()) {
    return;
  }
  if (!cryptomusPayoutKey() || !cryptomusMerchantUuid()) {
    throw new Error("Cryptomus payout is not configured.");
  }
}

function validatePassword(password) {
  if (!password || password.length < 8) {
    throw new Error("Password must be at least 8 characters.");
  }
}

async function hashPassword(password) {
  validatePassword(password);
  const salt = randomBytes(16).toString("hex");
  const derivedKey = await scryptAsync(password, salt, 64);
  return `scrypt:${salt}:${derivedKey.toString("hex")}`;
}

async function verifyPassword(password, storedHash) {
  if (!storedHash || typeof storedHash !== "string") {
    return false;
  }

  const [algorithm, salt, key] = storedHash.split(":");
  if (algorithm !== "scrypt" || !salt || !key) {
    return false;
  }

  const derivedKey = await scryptAsync(password, salt, 64);
  const storedKey = Buffer.from(key, "hex");
  return storedKey.length === derivedKey.length && timingSafeEqual(storedKey, derivedKey);
}

function hashSessionToken(token) {
  return createHash("sha256").update(token).digest("hex");
}

function appBaseUrl() {
  return (process.env.APP_BASE_URL || process.env.FRONTEND_URL || "http://localhost:3000").replace(/\/$/, "");
}

function emailFromAddress() {
  return process.env.EMAIL_FROM?.trim() || "";
}

function brevoApiKey() {
  return process.env.BREVO_API_KEY?.trim() || "";
}

function superAdminEmail() {
  return normalizeEmail(process.env.SUPER_ADMIN_EMAIL || "");
}

function superAdminPassword() {
  return cleanPassword(process.env.SUPER_ADMIN_PASSWORD || "");
}

function superAdminName() {
  return cleanText(process.env.SUPER_ADMIN_NAME, "Super Admin");
}

function parseEmailSender(value) {
  const input = cleanText(value);
  const match = input.match(/^(.*)<([^>]+)>$/);
  if (match) {
    return {
      name: cleanText(match[1]),
      email: cleanText(match[2]),
    };
  }

  return {
    name: "Bidder Portal",
    email: input,
  };
}

function displayNameFromEmail(email) {
  const local = email.split("@")[0] || "User";
  return local
    .split(/[._-]+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function cleanChatAttachments(value) {
  if (!Array.isArray(value)) {
    return [];
  }

  if (value.length > CHAT_ATTACHMENT_LIMIT) {
    throw new Error(`Send up to ${CHAT_ATTACHMENT_LIMIT} files per message.`);
  }

  return value.map((attachment) => {
    if (!attachment || typeof attachment !== "object") {
      throw new Error("Attachment is invalid.");
    }

    const name = cleanText(attachment.name, "attachment").slice(0, 140) || "attachment";
    const type = cleanMimeType(attachment.type);
    const size = Math.round(cleanNumber(attachment.size));
    const dataUrl = cleanText(attachment.dataUrl);

    if (!dataUrl.startsWith("data:")) {
      throw new Error("Attachment data is invalid.");
    }
    if (BLOCKED_CHAT_ATTACHMENT_TYPES.has(type)) {
      throw new Error("This attachment type is not allowed.");
    }
    if (size > MAX_CHAT_ATTACHMENT_BYTES || dataUrl.length > MAX_CHAT_ATTACHMENT_DATA_URL_LENGTH) {
      throw new Error("Each chat file must be 2 MB or smaller.");
    }

    return {
      id: createId("chat_file"),
      name,
      type,
      size,
      dataUrl,
    };
  });
}

function isClientRole(role) {
  return CLIENT_ROLES.has(role);
}

function cleanWorkLogReviewStatus(value) {
  const status = cleanText(value).toLowerCase();
  return WORK_LOG_REVIEW_STATUSES.has(status) ? status : "pending";
}

function isSuperAdmin(user) {
  return canonicalRole(user?.role) === "super_admin";
}

function canViewManagedRecords(user) {
  return isSuperAdmin(user) || isClientRole(user?.role);
}

function canManageChatMessage(user, message) {
  return isSuperAdmin(user) || message.userId === user.id;
}

function chatConversationId(userId, recipientId) {
  return [userId, recipientId].sort().join("__");
}

function directMessageFilterForUser(user) {
  if (isSuperAdmin(user)) {
    return { recipientId: { $exists: true, $ne: "" } };
  }

  return {
    recipientId: { $exists: true, $ne: "" },
    $or: [{ userId: user.id }, { recipientId: user.id }],
  };
}

async function paidPaymentCoversDate(portal, userId, workDate) {
  return Boolean(
    await portal.payments.findOne(
      {
        userId,
        status: { $in: ["paid", "processing"] },
        periodStart: { $lte: workDate },
        periodEnd: { $gte: workDate },
      },
      { projection: { _id: 1 } }
    )
  );
}

async function releasedPaymentOverlapsPeriod(portal, userId, periodStart, periodEnd, excludePaymentId = "") {
  return Boolean(
    await portal.payments.findOne(
      {
        userId,
        ...(excludePaymentId ? { id: { $ne: excludePaymentId } } : {}),
        status: { $in: ["paid", "processing"] },
        periodStart: { $lte: periodEnd },
        periodEnd: { $gte: periodStart },
      },
      { projection: { _id: 1 } }
    )
  );
}

async function paidPaymentCoversPayDate(portal, userId, paymentDate) {
  return Boolean(
    await portal.payments.findOne(
      {
        userId,
        status: { $in: ["paid", "processing"] },
        $or: [
          { scheduledDate: paymentDate },
          {
            periodStart: { $lte: paymentDate },
            periodEnd: { $gte: paymentDate },
          },
        ],
      },
      { projection: { _id: 1 } }
    )
  );
}

function normalizePaymentFrequency(value) {
  const frequency = cleanText(value).toLowerCase();
  return PAYMENT_FREQUENCIES.has(frequency) ? frequency : "";
}

function normalizePaymentWeekday(value) {
  const weekday = cleanText(value).toLowerCase();
  return PAYMENT_WEEKDAYS.includes(weekday) ? weekday : "";
}

function parsePaymentSchedule(value) {
  const schedule = cleanText(value).toLowerCase();
  const frequency = schedule.includes("biweekly")
    ? "biweekly"
    : schedule.includes("monthly")
      ? "monthly"
      : schedule.includes("weekly")
        ? "weekly"
        : "";
  const weekday = PAYMENT_WEEKDAYS.find((day) => schedule.includes(day)) || "";

  return { frequency, weekday };
}

function titleCase(value) {
  return value.charAt(0).toUpperCase() + value.slice(1);
}

function paymentScheduleLabel(frequencyInput, weekdayInput) {
  const frequency = normalizePaymentFrequency(frequencyInput);
  const weekday = normalizePaymentWeekday(weekdayInput);
  if (!frequency || !weekday) {
    return "";
  }

  const frequencyLabel = frequency === "biweekly" ? "Biweekly" : titleCase(frequency);
  return `${frequencyLabel} on ${titleCase(weekday)}`;
}

function dateToIso(date) {
  return date.toISOString().slice(0, 10);
}

function parseIsoDate(value) {
  const [year, month, day] = cleanText(value).split("-").map(Number);
  if (!year || !month || !day) {
    return null;
  }

  const date = new Date(Date.UTC(year, month - 1, day));
  return Number.isNaN(date.getTime()) ? null : date;
}

function addDays(date, days) {
  const next = new Date(date);
  next.setUTCDate(next.getUTCDate() + days);
  return next;
}

function addMonths(date, months) {
  const next = new Date(date);
  const day = next.getUTCDate();
  next.setUTCDate(1);
  next.setUTCMonth(next.getUTCMonth() + months);
  const lastDay = new Date(Date.UTC(next.getUTCFullYear(), next.getUTCMonth() + 1, 0)).getUTCDate();
  next.setUTCDate(Math.min(day, lastDay));
  return next;
}

function nextWeekdayOnOrAfter(date, weekdayInput) {
  const weekday = normalizePaymentWeekday(weekdayInput);
  if (!weekday) {
    return null;
  }

  const offset = (WEEKDAY_INDEX[weekday] - date.getUTCDay() + 7) % 7;
  return addDays(date, offset);
}

function paymentDateMatchesWeekday(value, weekdayInput) {
  const date = parseIsoDate(value);
  const weekday = normalizePaymentWeekday(weekdayInput);
  return Boolean(date && weekday && date.getUTCDay() === WEEKDAY_INDEX[weekday]);
}

function nextPaymentDateFromSchedule(frequencyInput, weekdayInput, baseDateInput = dateToIso(new Date()), advance = false) {
  const frequency = normalizePaymentFrequency(frequencyInput);
  const weekday = normalizePaymentWeekday(weekdayInput);
  const baseDate = parseIsoDate(baseDateInput) || parseIsoDate(dateToIso(new Date()));
  if (!frequency || !weekday || !baseDate) {
    return "";
  }

  let searchDate = baseDate;
  if (advance) {
    if (frequency === "weekly") {
      searchDate = addDays(baseDate, 1);
    } else if (frequency === "biweekly") {
      searchDate = addDays(baseDate, 14);
    } else {
      searchDate = addMonths(baseDate, 1);
    }
  }

  const nextDate = nextWeekdayOnOrAfter(searchDate, weekday);
  return nextDate ? dateToIso(nextDate) : "";
}

function paymentScheduleFromUser(user) {
  const parsedSchedule = parsePaymentSchedule(user?.paymentSchedule);
  return {
    frequency: normalizePaymentFrequency(user?.paymentFrequency) || parsedSchedule.frequency,
    weekday: normalizePaymentWeekday(user?.paymentWeekday) || parsedSchedule.weekday,
  };
}

async function nextOpenPaymentDate(portal, userId, frequencyInput, weekdayInput, preferredDate = "") {
  const frequency = normalizePaymentFrequency(frequencyInput);
  const weekday = normalizePaymentWeekday(weekdayInput);
  if (!frequency || !weekday) {
    return "";
  }

  let candidate =
    cleanText(preferredDate) && paymentDateMatchesWeekday(preferredDate, weekday)
      ? cleanText(preferredDate)
      : nextPaymentDateFromSchedule(frequency, weekday);

  for (let guard = 0; candidate && guard < 36; guard += 1) {
    if (!(await paidPaymentCoversPayDate(portal, userId, candidate))) {
      return candidate;
    }

    candidate = nextPaymentDateFromSchedule(frequency, weekday, candidate, true);
  }

  return candidate;
}

function stripMongoId(doc) {
  if (!doc) {
    return null;
  }

  const record = { ...doc };
  delete record._id;
  return record;
}

function stripMongoIds(docs) {
  return docs.map(stripMongoId).filter(Boolean);
}

function publicUser(user) {
  if (!user) {
    return null;
  }

  const record = { ...user };
  record.role = canonicalRole(record.role);
  record.passwordSet = Boolean(record.passwordHash);
  record.passwordUpdatedAt = record.passwordUpdatedAt || "";
  record.emailVerifiedAt = record.emailVerifiedAt || "";
  record.emailVerificationSentAt = record.emailVerificationSentAt || "";
  record.passwordResetSentAt = record.passwordResetSentAt || "";
  record.assignedAdminId = record.assignedAdminId || "";
  record.profileTitle = record.profileTitle || "";
  record.profileBio = record.profileBio || "";
  record.profileSkills = cleanProfileSkills(record.profileSkills || []);
  record.profileLocation = record.profileLocation || "";
  record.companyName = record.companyName || "";
  record.country = record.country || record.profileLocation || "";
  record.clientPreferences = cleanProfileSkills(record.clientPreferences || []);
  record.profileLanguages = cleanProfileSkills(record.profileLanguages || []);
  record.profileTimeZone = record.profileTimeZone || "";
  record.profileCompletedAt = record.profileCompletedAt || "";
  record.allowDirectMessages = record.allowDirectMessages !== false;
  record.clientRating = cleanNumber(record.clientRating, 0);
  const schedule = paymentScheduleFromUser(record);
  record.paymentFrequency = schedule.frequency;
  record.paymentWeekday = schedule.weekday;
  record.paymentSchedule = paymentScheduleLabel(schedule.frequency, schedule.weekday) || record.paymentSchedule || "";
  delete record.passwordHash;
  return record;
}

function profileCompleteForUser(user) {
  if (!user) {
    return false;
  }
  if (isSuperAdmin(user)) {
    return true;
  }

  const role = canonicalRole(user.role);
  const name = cleanText(user.name);
  const country = cleanText(user.country || user.profileLocation);
  const timeZone = cleanText(user.profileTimeZone);
  if (!name || !country || !timeZone) {
    return false;
  }

  if (isClientRole(role)) {
    return cleanProfileSkills(user.clientPreferences || []).length > 0;
  }

  if (role === "bidder" || role === "developer") {
    return cleanProfileSkills(user.profileSkills || []).length > 0 &&
      cleanProfileSkills(user.profileLanguages || []).length > 0;
  }

  return true;
}

function assertProfileCompleteForPortalUse(user) {
  if (user?.status === "approved" && !profileCompleteForUser(user)) {
    throw new Error("Complete your profile before using the portal.");
  }
}

function portalMode() {
  return process.env.PORTAL_MODE?.trim().toLowerCase() === "live" ? "live" : "dev";
}

function isLiveMode() {
  return portalMode() === "live";
}

function validateEmail(email) {
  if (!email || !email.includes("@")) {
    throw new Error("Enter a valid email address.");
  }
}

function assertDemoAccountAllowed(email) {
  if (isLiveMode() && DEMO_EMAILS.has(email)) {
    throw new Error("Demo accounts are disabled in live mode. Please sign up with a real email.");
  }
}

function getMongoUri() {
  const uri = process.env.MONGODB_URI?.trim() || "";
  if (!uri) {
    throw new Error(
      "MONGODB_URI is not configured. Add it to .env.local locally and to the Vercel project environment before using the portal."
    );
  }

  return uri;
}

function getMongoDbName(uri) {
  const explicitName = process.env.MONGODB_DB?.trim();
  if (explicitName) {
    return explicitName;
  }

  try {
    const dbName = new URL(uri).pathname.replace(/^\//, "");
    return dbName ? decodeURIComponent(dbName) : DEFAULT_DB_NAME;
  } catch {
    return DEFAULT_DB_NAME;
  }
}

async function getMongoClient(uri) {
  if (!mongoCache || mongoCache.uri !== uri) {
    mongoCache = {
      uri,
      clientPromise: new MongoClient(uri, {
        appName: "bidder-portal",
        maxPoolSize: 10,
      }).connect(),
    };
  }

  return mongoCache.clientPromise;
}

async function getDb() {
  const uri = getMongoUri();
  const dbName = getMongoDbName(uri);
  const databaseKey = `${uri}#${dbName}#${portalMode()}`;

  if (activeDatabaseKey !== databaseKey) {
    activeDatabaseKey = databaseKey;
    schemaReady = false;
    schemaPromise = null;
  }

  const client = await getMongoClient(uri);
  return client.db(dbName);
}

function collections(db) {
  return {
    users: db.collection("portal_users"),
    paymentMethods: db.collection("portal_payment_methods"),
    workLogs: db.collection("portal_work_logs"),
    payments: db.collection("portal_payments"),
    escrows: db.collection("portal_escrows"),
    deposits: db.collection("portal_client_deposits"),
    creditLedger: db.collection("portal_credit_ledger"),
    contracts: db.collection("portal_contracts"),
    posts: db.collection("portal_posts"),
    bidProfiles: db.collection("portal_bid_profiles"),
    disputes: db.collection("portal_disputes"),
    notifications: db.collection("portal_notifications"),
    chatMessages: db.collection("portal_chat_messages"),
    sessions: db.collection("portal_sessions"),
    authTokens: db.collection("portal_auth_tokens"),
    emailEvents: db.collection("portal_email_events"),
  };
}

async function initializeSchema() {
  const portal = collections(await getDb());

  await Promise.all([
    portal.users.createIndex({ email: 1 }, { unique: true }),
    portal.users.createIndex({ role: 1 }),
    portal.users.createIndex({ status: 1 }),
    portal.users.createIndex({ assignedAdminId: 1 }),
    portal.paymentMethods.createIndex({ userId: 1 }),
    portal.paymentMethods.createIndex({ userId: 1, method: 1 }, { unique: true }),
    portal.workLogs.createIndex({ userId: 1 }),
    portal.workLogs.createIndex({ userId: 1, workDate: 1 }, { unique: true }),
    portal.payments.createIndex({ userId: 1 }),
    portal.payments.createIndex({ clientId: 1 }),
    portal.payments.createIndex({ scheduledDate: 1 }),
    portal.escrows.createIndex({ clientId: 1 }),
    portal.escrows.createIndex({ createdAt: -1 }),
    portal.deposits.createIndex({ clientId: 1 }),
    portal.deposits.createIndex({ orderId: 1 }, { unique: true }),
    portal.deposits.createIndex({ status: 1 }),
    portal.creditLedger.createIndex({ userId: 1, creditType: 1 }),
    portal.creditLedger.createIndex({ userId: 1, source: 1, relatedPostId: 1 }),
    portal.contracts.createIndex({ clientId: 1, workerId: 1, status: 1 }),
    portal.contracts.createIndex({ requestedByUserId: 1 }),
    portal.posts.createIndex({ type: 1, status: 1, createdAt: -1 }),
    portal.posts.createIndex({ authorId: 1, status: 1 }),
    portal.bidProfiles.createIndex({ clientId: 1, updatedAt: -1 }),
    portal.disputes.createIndex({ clientId: 1, updatedAt: -1 }),
    portal.disputes.createIndex({ status: 1, updatedAt: -1 }),
    portal.notifications.createIndex({ recipientRole: 1, readAt: 1, createdAt: -1 }),
    portal.notifications.createIndex({ recipientUserId: 1, readAt: 1, createdAt: -1 }),
    portal.notifications.createIndex({ type: 1, relatedDepositId: 1 }),
    portal.notifications.createIndex({ type: 1, relatedWorkLogId: 1, recipientUserId: 1 }),
    portal.chatMessages.createIndex({ createdAt: 1 }),
    portal.chatMessages.createIndex({ conversationId: 1, createdAt: 1 }),
    portal.chatMessages.createIndex({ recipientId: 1 }),
    portal.sessions.createIndex({ tokenHash: 1 }, { unique: true }),
    portal.sessions.createIndex({ userId: 1 }),
    portal.sessions.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 }),
    portal.authTokens.createIndex({ tokenHash: 1 }, { unique: true }),
    portal.authTokens.createIndex({ userId: 1, type: 1 }),
    portal.authTokens.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 }),
    portal.emailEvents.createIndex({ createdAt: -1 }),
  ]);

  await portal.users.updateMany({ role: "admin" }, { $set: { role: "client", updatedAt: now() } });

  if (!isLiveMode()) {
    await seedDemoData(portal);
  }
  await syncSuperAdmin(portal);
}

export async function ensurePortalSchema() {
  if (schemaReady) {
    return;
  }

  schemaPromise ??= initializeSchema()
    .then(() => {
      schemaReady = true;
    })
    .catch((error) => {
      schemaPromise = null;
      throw error;
    });

  await schemaPromise;
}

async function seedUser(portal, user) {
  const existingUser = await portal.users.findOne({ email: user.email }, { projection: { _id: 1 } });
  if (!existingUser) {
    await portal.users.insertOne(user);
    return;
  }

  await portal.users.updateOne(
    { email: user.email },
    {
      $set: {
        name: user.name,
        role: user.role,
        status: user.status,
        assignedAdminId: user.assignedAdminId,
        profileTitle: user.profileTitle || "",
        profileBio: user.profileBio || "",
        profileSkills: cleanProfileSkills(user.profileSkills || []),
        profileLocation: user.profileLocation || "",
        profileTimeZone: user.profileTimeZone || "",
        profileCompletedAt: user.profileCompletedAt || "",
        companyName: user.companyName || "",
        country: user.country || user.profileLocation || "",
        clientPreferences: cleanProfileSkills(user.clientPreferences || []),
        profileLanguages: cleanProfileSkills(user.profileLanguages || []),
        allowDirectMessages: user.allowDirectMessages !== false,
        clientRating: cleanNumber(user.clientRating, 0),
        emailVerifiedAt: user.emailVerifiedAt || "",
        emailVerificationSentAt: user.emailVerificationSentAt || "",
        updatedAt: user.updatedAt,
      },
    }
  );
}

async function ensureSignupPostCredit(portal, userId, stamp = now()) {
  if (!userId) {
    return;
  }

  await portal.creditLedger.updateOne(
    { userId, source: "signup_bonus", relatedPostId: "" },
    {
      $setOnInsert: {
        id: createId("credit"),
        userId,
        creditType: "post",
        amount: SIGNUP_POST_CREDIT,
        source: "signup_bonus",
        relatedPostId: "",
        relatedContractId: "",
        memo: "Free signup posting credit",
        createdAt: stamp,
      },
      $set: {
        updatedAt: stamp,
      },
    },
    { upsert: true }
  );
}

async function syncSuperAdmin(portal) {
  const email = superAdminEmail();
  const password = superAdminPassword();
  if (!email && !password) {
    return;
  }

  validateEmail(email);
  validatePassword(password);
  assertDemoAccountAllowed(email);

  const existing = await portal.users.findOne({ email }, { projection: { _id: 0, id: 1, createdAt: 1 } });
  const stamp = now();
  await portal.users.updateOne(
    { email },
    {
      $set: {
        id: existing?.id || createId("user"),
        email,
        name: superAdminName(),
        role: "super_admin",
        status: "approved",
        assignedAdminId: "",
        ratePerApplication: 0,
        bonusPerInterview: 0,
        nextPaymentDate: "",
        paymentSchedule: "",
        paymentFrequency: "",
        paymentWeekday: "",
        passwordHash: await hashPassword(password),
        passwordUpdatedAt: stamp,
        emailVerifiedAt: stamp,
        emailVerificationSentAt: "",
        passwordResetSentAt: "",
        updatedAt: stamp,
      },
      $setOnInsert: {
        createdAt: existing?.createdAt || stamp,
      },
    },
    { upsert: true }
  );
}

async function seedDemoData(portal) {
  const stamp = now();
  const demoPasswordHash = await hashPassword(DEMO_PASSWORD);

  await Promise.all([
    seedUser(portal, {
      id: "user_admin",
      email: ADMIN_EMAIL,
      name: "Super Admin Owner",
      role: "super_admin",
      status: "approved",
      assignedAdminId: "",
      ratePerApplication: 0,
      bonusPerInterview: 0,
      nextPaymentDate: "",
      paymentSchedule: "",
      paymentFrequency: "",
      paymentWeekday: "",
      passwordHash: demoPasswordHash,
      passwordUpdatedAt: stamp,
      emailVerifiedAt: stamp,
      emailVerificationSentAt: "",
      passwordResetSentAt: "",
      createdAt: stamp,
      updatedAt: stamp,
    }),
    seedUser(portal, {
      id: "user_client",
      email: CLIENT_EMAIL,
      name: "Demo Client",
      role: "client",
      status: "approved",
      assignedAdminId: "",
      ratePerApplication: 0,
      bonusPerInterview: 0,
      nextPaymentDate: "",
      paymentSchedule: "",
      paymentFrequency: "",
      paymentWeekday: "",
      profileTitle: "Hiring client for bidder operations",
      profileBio: "Demo client account for reviewing assigned bidder work, payment history, and escrow records.",
      profileSkills: ["Remote hiring", "Bidder management"],
      companyName: "Digniware Demo",
      country: "United States",
      clientPreferences: ["Remote", "LinkedIn", "Indeed"],
      profileLocation: "New York, United States",
      profileTimeZone: "America/New_York",
      profileCompletedAt: stamp,
      clientRating: 4.8,
      passwordHash: demoPasswordHash,
      passwordUpdatedAt: stamp,
      emailVerifiedAt: stamp,
      emailVerificationSentAt: "",
      passwordResetSentAt: "",
      createdAt: stamp,
      updatedAt: stamp,
    }),
    seedUser(portal, {
      id: "user_maya",
      email: "maya.bidder@example.com",
      name: "Maya Bidder",
      role: "bidder",
      status: "approved",
      assignedAdminId: "user_client",
      ratePerApplication: 1.25,
      bonusPerInterview: 12,
      nextPaymentDate: "2026-08-21",
      paymentSchedule: "Weekly on Friday",
      paymentFrequency: "weekly",
      paymentWeekday: "friday",
      profileTitle: "Technical bidder for remote web roles",
      profileBio: "Experienced bidder focused on daily applications, interview scheduling, and clear client reporting.",
      profileSkills: ["Upwork", "LinkedIn", "Remote jobs"],
      country: "Philippines",
      profileLocation: "Philippines",
      profileTimeZone: "Asia/Manila",
      profileLanguages: ["English - fluent", "Tagalog - native"],
      profileCompletedAt: stamp,
      passwordHash: demoPasswordHash,
      passwordUpdatedAt: stamp,
      emailVerifiedAt: stamp,
      emailVerificationSentAt: "",
      passwordResetSentAt: "",
      createdAt: stamp,
      updatedAt: stamp,
    }),
    seedUser(portal, {
      id: "user_pending",
      email: "pending.bidder@example.com",
      name: "Pending Bidder",
      role: "bidder",
      status: "pending",
      assignedAdminId: "user_client",
      ratePerApplication: 0,
      bonusPerInterview: 0,
      nextPaymentDate: "",
      paymentSchedule: "",
      paymentFrequency: "",
      paymentWeekday: "",
      passwordHash: demoPasswordHash,
      passwordUpdatedAt: stamp,
      emailVerifiedAt: stamp,
      emailVerificationSentAt: "",
      passwordResetSentAt: "",
      createdAt: stamp,
      updatedAt: stamp,
    }),
  ]);

  await portal.users.updateMany(
    { email: { $in: Array.from(DEMO_EMAILS) }, $or: [{ passwordHash: { $exists: false } }, { passwordHash: "" }] },
    { $set: { passwordHash: demoPasswordHash, passwordUpdatedAt: stamp, updatedAt: stamp } }
  );

  await Promise.all([
    ensureSignupPostCredit(portal, "user_client", stamp),
    ensureSignupPostCredit(portal, "user_maya", stamp),
    ensureSignupPostCredit(portal, "user_pending", stamp),
    portal.paymentMethods.updateMany(
      { userId: "user_maya", method: { $ne: "USDT TRON" } },
      { $set: { isPrimary: false, updatedAt: stamp } }
    ),
    portal.paymentMethods.updateOne(
      { userId: "user_maya", method: "Wise" },
      {
        $setOnInsert: {
          id: "method_maya_wise",
          userId: "user_maya",
          method: "Wise",
          address: "maya@example.com",
          isPrimary: false,
          createdAt: stamp,
          updatedAt: stamp,
        },
      },
      { upsert: true }
    ),
    portal.paymentMethods.updateOne(
      { userId: "user_maya", method: "USDT TRON" },
      {
        $set: {
          currency: "USDT",
          network: "TRON",
          address: "TDD97yguPESTpcrJMqU6h2ozZbibv4Vaqm",
          isPrimary: true,
          updatedAt: stamp,
        },
        $setOnInsert: {
          id: "method_maya_usdt_tron",
          userId: "user_maya",
          method: "USDT TRON",
          createdAt: stamp,
        },
      },
      { upsert: true }
    ),
    portal.deposits.updateOne(
      { id: "deposit_demo_client_test_credit" },
      {
        $setOnInsert: {
          id: "deposit_demo_client_test_credit",
          clientId: "user_client",
          provider: "manual",
          orderId: "manual_demo_client_test_credit",
          invoiceUuid: "",
          amount: 1000,
          feeAmount: 0,
          creditAmount: 1000,
          currency: CREDIT_CURRENCY,
          toCurrency: CREDIT_CURRENCY,
          network: "",
          status: "paid",
          providerStatus: "test_credit",
          paymentUrl: "",
          paymentAmountUsd: 1000,
          merchantAmount: 1000,
          txid: "",
          memo: "Demo balance for testing release payments.",
          rawProvider: {},
          createdAt: stamp,
          updatedAt: stamp,
          paidAt: stamp,
        },
      },
      { upsert: true }
    ),
    portal.contracts.updateOne(
      { id: "contract_demo_client_maya" },
      {
        $setOnInsert: {
          id: "contract_demo_client_maya",
          clientId: "user_client",
          workerId: "user_maya",
          requestedByUserId: "user_client",
          title: "Weekly bidder operations",
          criteria: "Apply to qualified remote web roles, keep the Google Sheet current, and report scheduled interviews daily.",
          ratePerApplication: 1.25,
          bonusPerInterview: 12,
          paymentFrequency: "weekly",
          paymentWeekday: "friday",
          startDate: "2026-08-06",
          status: "active",
          sourcePostId: "",
          acceptedAt: stamp,
          acceptedByUserId: "user_maya",
          rejectedAt: "",
          endedAt: "",
          createdAt: stamp,
          updatedAt: stamp,
        },
      },
      { upsert: true }
    ),
    portal.posts.updateOne(
      { id: "post_demo_client" },
      {
        $setOnInsert: {
          id: "post_demo_client",
          authorId: "user_client",
          type: "client",
          title: "Need bidder for SaaS agency roles",
          criteria: "Target Upwork and LinkedIn roles for React and Node projects. Daily sheet updates required.",
          budgetAmount: 80,
          preferredRate: 1.25,
          bonusPerInterview: 12,
          paymentFrequency: "weekly",
          paymentWeekday: "friday",
          status: "active",
          postCreditUsed: 1,
          moneyCreditUsed: 0,
          createdAt: stamp,
          updatedAt: stamp,
          closedAt: "",
        },
      },
      { upsert: true }
    ),
    portal.posts.updateOne(
      { id: "post_demo_bidder" },
      {
        $setOnInsert: {
          id: "post_demo_bidder",
          authorId: "user_maya",
          type: "bidder",
          title: "Bidder available for web agency outreach",
          criteria: "Experienced with daily application logs, interview tracking, and careful project qualification.",
          budgetAmount: 0,
          preferredRate: 1.5,
          bonusPerInterview: 15,
          paymentFrequency: "weekly",
          paymentWeekday: "friday",
          status: "active",
          postCreditUsed: 1,
          moneyCreditUsed: 0,
          createdAt: stamp,
          updatedAt: stamp,
          closedAt: "",
        },
      },
      { upsert: true }
    ),
    portal.bidProfiles.updateOne(
      { id: "bid_profile_demo_react" },
      {
        $setOnInsert: {
          id: "bid_profile_demo_react",
          clientId: "user_client",
          profileName: "React SaaS Bid Profile",
          fullLegalName: "Demo Client Candidate",
          contactEmail: "client@portal.local",
          phone: "+1 555 0100",
          targetSalary: "120000",
          visaStatus: "US citizen",
          jobTitles: ["React Developer", "Node.js Developer"],
          extraFields: [
            { label: "Preferred timezone", value: "US overlap" },
            { label: "Portfolio", value: "https://digniware.com" },
          ],
          notes: "Demo bid profile for bidder outreach.",
          createdAt: stamp,
          updatedAt: stamp,
        },
      },
      { upsert: true }
    ),
    portal.creditLedger.updateOne(
      { userId: "user_client", source: "post_fee", relatedPostId: "post_demo_client", creditType: "post" },
      {
        $setOnInsert: {
          id: "credit_demo_client_post",
          userId: "user_client",
          creditType: "post",
          amount: -1,
          source: "post_fee",
          relatedPostId: "post_demo_client",
          relatedContractId: "",
          memo: "Demo post publishing fee",
          createdAt: stamp,
          updatedAt: stamp,
        },
      },
      { upsert: true }
    ),
    portal.creditLedger.updateOne(
      { userId: "user_maya", source: "post_fee", relatedPostId: "post_demo_bidder", creditType: "post" },
      {
        $setOnInsert: {
          id: "credit_demo_bidder_post",
          userId: "user_maya",
          creditType: "post",
          amount: -1,
          source: "post_fee",
          relatedPostId: "post_demo_bidder",
          relatedContractId: "",
          memo: "Demo post publishing fee",
          createdAt: stamp,
          updatedAt: stamp,
        },
      },
      { upsert: true }
    ),
    portal.workLogs.updateOne(
      { userId: "user_maya", workDate: "2026-08-13" },
      {
        $setOnInsert: {
          id: "log_maya_2026_08_13",
          userId: "user_maya",
          workDate: "2026-08-13",
          sheetLink: "https://docs.google.com/spreadsheets/d/example-maya-log",
          appliedJobs: 18,
          interviewsScheduled: 2,
          notes: "Focused on Upwork backend roles.",
          reviewStatus: "approved",
          reviewNote: "",
          reviewedByUserId: "user_client",
          reviewedAt: stamp,
          createdAt: stamp,
          updatedAt: stamp,
        },
      },
      { upsert: true }
    ),
    portal.payments.updateOne(
      { id: "payment_maya_1" },
      {
        $setOnInsert: {
          id: "payment_maya_1",
          userId: "user_maya",
          periodStart: "2026-08-06",
          periodEnd: "2026-08-12",
          scheduledDate: "2026-08-14",
          amount: 142.5,
          status: "paid",
          paymentLink: "https://pay.example.com/receipt/maya-001",
          memo: "First weekly payout",
          createdAt: stamp,
          updatedAt: stamp,
        },
      },
      { upsert: true }
    ),
    portal.chatMessages.updateOne(
      { id: "chat_welcome" },
      {
        $setOnInsert: {
          id: "chat_welcome",
          userId: "user_client",
          recipientId: "user_maya",
          conversationId: chatConversationId("user_client", "user_maya"),
          authorName: "Demo Client",
          authorRole: "client",
          body: "Hi Maya, please log daily sheet links, applied jobs, and scheduled interviews before the payment review.",
          attachments: [],
          authorTimeZone: "America/New_York",
          createdAt: stamp,
          updatedAt: stamp,
          editedAt: "",
          deletedAt: "",
        },
      },
      { upsert: true }
    ),
  ]);
}

async function getUserByEmail(email, { includeSecrets = false } = {}) {
  const portal = collections(await getDb());
  return stripMongoId(
    await portal.users.findOne(
      { email: normalizeEmail(email) },
      { projection: includeSecrets ? { _id: 0 } : PUBLIC_USER_PROJECTION }
    )
  );
}

async function getUserById(userId, { includeSecrets = false } = {}) {
  const portal = collections(await getDb());
  return stripMongoId(
    await portal.users.findOne(
      { id: userId },
      { projection: includeSecrets ? { _id: 0 } : PUBLIC_USER_PROJECTION }
    )
  );
}

async function createUser(email, nameInput, role, status, password, assignedAdminId = "") {
  const portal = collections(await getDb());
  const stamp = now();
  const passwordHash = await hashPassword(password);
  const user = {
    id: createId("user"),
    email,
    name: cleanText(nameInput) || displayNameFromEmail(email),
    role: canonicalRole(role),
    status,
    assignedAdminId,
    ratePerApplication: 0,
    bonusPerInterview: 0,
    nextPaymentDate: "",
    paymentSchedule: "",
    paymentFrequency: "",
    paymentWeekday: "",
    profileTitle: "",
    profileBio: "",
    profileSkills: [],
    profileLocation: "",
    profileTimeZone: "",
    profileCompletedAt: "",
    companyName: "",
    country: "",
    clientPreferences: [],
    profileLanguages: [],
    clientRating: 0,
    passwordHash,
    passwordUpdatedAt: stamp,
    emailVerifiedAt: "",
    emailVerificationSentAt: "",
    passwordResetSentAt: "",
    createdAt: stamp,
    updatedAt: stamp,
  };

  const result = await portal.users.updateOne({ email }, { $setOnInsert: user }, { upsert: true });
  if (result.upsertedCount) {
    await ensureSignupPostCredit(portal, user.id, stamp);
  }
  return getUserByEmail(email, { includeSecrets: true });
}

async function createSession(user) {
  const portal = collections(await getDb());
  const token = randomBytes(32).toString("base64url");
  const stamp = new Date();
  const expiresAt = new Date(stamp.getTime() + SESSION_MS);

  await portal.sessions.insertOne({
    id: createId("session"),
    userId: user.id,
    tokenHash: hashSessionToken(token),
    createdAt: stamp,
    updatedAt: stamp,
    expiresAt,
  });

  return token;
}

async function createAuthToken(portal, user, type, ttlMs) {
  const token = randomBytes(32).toString("base64url");
  const stamp = new Date();
  const expiresAt = new Date(stamp.getTime() + ttlMs);

  await portal.authTokens.insertOne({
    id: createId("auth_token"),
    userId: user.id,
    email: user.email,
    type,
    tokenHash: hashSessionToken(token),
    usedAt: "",
    createdAt: stamp,
    updatedAt: stamp,
    expiresAt,
  });

  return token;
}

async function sendPortalEmail(portal, { to, subject, text, html }) {
  const sender = parseEmailSender(emailFromAddress());
  const apiKey = brevoApiKey();
  const stamp = now();

  if (apiKey && sender.email) {
    const response = await fetch("https://api.brevo.com/v3/smtp/email", {
      method: "POST",
      headers: {
        accept: "application/json",
        "api-key": apiKey,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        sender,
        to: [{ email: to }],
        subject,
        textContent: text,
        htmlContent: html,
      }),
    });

    if (!response.ok) {
      throw new Error("Email could not be sent. Check BREVO_API_KEY and EMAIL_FROM.");
    }

    return;
  }

  if (isLiveMode()) {
    throw new Error("Email sending is not configured. Add BREVO_API_KEY, EMAIL_FROM, and APP_BASE_URL.");
  }

  await portal.emailEvents.insertOne({
    id: createId("email_event"),
    to,
    subject,
    text,
    html,
    provider: "dev-log",
    createdAt: stamp,
  });
}

async function consumeAuthToken(portal, email, token, type) {
  const authToken = await portal.authTokens.findOne(
    {
      email,
      type,
      tokenHash: hashSessionToken(cleanText(token)),
      usedAt: "",
      expiresAt: { $gt: new Date() },
    },
    { projection: { _id: 0 } }
  );

  if (!authToken) {
    throw new Error("This link is invalid or expired.");
  }

  await portal.authTokens.updateOne(
    { id: authToken.id },
    { $set: { usedAt: now(), updatedAt: new Date() } }
  );

  return authToken;
}

async function getSessionUser(emailInput, sessionTokenInput, options = {}) {
  await ensurePortalSchema();
  const email = normalizeEmail(emailInput);
  const sessionToken = cleanText(sessionTokenInput);
  validateEmail(email);
  assertDemoAccountAllowed(email);

  if (!sessionToken) {
    throw new Error("Please sign in again.");
  }

  const portal = collections(await getDb());
  const session = await portal.sessions.findOne(
    {
      tokenHash: hashSessionToken(sessionToken),
      expiresAt: { $gt: new Date() },
    },
    { projection: { _id: 0 } }
  );

  if (!session) {
    throw new Error("Session expired. Please sign in again.");
  }

  const user = await getUserById(session.userId, { includeSecrets: true });
  if (!user || user.email !== email) {
    throw new Error("Session expired. Please sign in again.");
  }

  if (!user.emailVerifiedAt) {
    await portal.sessions.deleteMany({ userId: user.id });
    throw new Error(EMAIL_VERIFICATION_PORTAL_ERROR);
  }
  if (!options.allowIncompleteProfile) {
    assertProfileCompleteForPortalUse(user);
  }

  await portal.sessions.updateOne(
    { tokenHash: session.tokenHash },
    { $set: { updatedAt: new Date(), expiresAt: new Date(Date.now() + SESSION_MS) } }
  );

  return user;
}

async function verifyOrSetPassword(user, passwordInput) {
  const password = cleanPassword(passwordInput);
  validatePassword(password);

  if (user.passwordHash) {
    const valid = await verifyPassword(password, user.passwordHash);
    if (!valid) {
      throw new Error("Email or password is incorrect.");
    }

    return user;
  }

  const stamp = now();
  const portal = collections(await getDb());
  const passwordHash = await hashPassword(password);
  await portal.users.updateOne(
    { id: user.id, $or: [{ passwordHash: { $exists: false } }, { passwordHash: "" }] },
    { $set: { passwordHash, passwordUpdatedAt: stamp, updatedAt: stamp } }
  );

  return getUserById(user.id, { includeSecrets: true });
}

export async function signUp(emailInput, nameInput, passwordInput, roleInput = "bidder") {
  await ensurePortalSchema();
  const portal = collections(await getDb());
  const email = normalizeEmail(emailInput);
  const password = cleanPassword(passwordInput);
  validateEmail(email);
  validatePassword(password);
  assertDemoAccountAllowed(email);

  const existing = await getUserByEmail(email, { includeSecrets: true });
  if (existing) {
    throw new Error("Account already exists. Please sign in.");
  }

  const requestedRole = cleanRole(roleInput);
  const user = await createUser(
    email,
    nameInput,
    requestedRole,
    "pending",
    password
  );
  await sendEmailVerificationToUser(portal, user);

  return {
    ok: true,
    needsEmailVerification: true,
    email: user.email,
    message: "Check your email to verify your account before signing in.",
  };
}

function targetVisibleInLive(user) {
  return !isLiveMode() || !DEMO_EMAILS.has(user.email);
}

function userVisibilityFilter() {
  return isLiveMode() ? { email: { $nin: Array.from(DEMO_EMAILS) } } : {};
}

function isPortalWorker(user) {
  return user && !isSuperAdmin(user) && !isClientRole(user.role);
}

async function visibleUsersForCurrentUser(portal, currentUser) {
  const baseFilter = userVisibilityFilter();
  if (isSuperAdmin(currentUser)) {
    return stripMongoIds(
      await portal.users
        .find(baseFilter, { projection: { _id: 0 } })
        .sort({ role: 1, status: 1, name: 1 })
        .toArray()
    ).map(publicUser);
  }

  if (isClientRole(currentUser.role)) {
    const workers = stripMongoIds(
      await portal.users
        .find(
          {
            ...baseFilter,
            role: { $in: ["bidder", "developer"] },
            $or: [
              { status: "approved" },
              { assignedAdminId: currentUser.id },
            ],
          },
          { projection: { _id: 0 } }
        )
        .sort({ status: 1, name: 1 })
        .toArray()
    ).map(publicUser);

    return [publicUser(currentUser), ...workers];
  }

  if (currentUser.role === "bidder") {
    const clients = stripMongoIds(
      await portal.users
        .find(
          {
            ...baseFilter,
            role: "client",
            status: "approved",
          },
          { projection: { _id: 0 } }
        )
        .sort({ createdAt: -1, name: 1 })
        .toArray()
    ).map(publicUser);

    return [publicUser(currentUser), ...clients];
  }

  return [publicUser(currentUser)];
}

async function recordUserIdsForCurrentUser(portal, currentUser, users) {
  const baseFilter = userVisibilityFilter();
  if (isSuperAdmin(currentUser)) {
    return users.filter(isPortalWorker).map((user) => user.id);
  }

  if (isClientRole(currentUser.role)) {
    return (
      await portal.users
        .find(
          {
            ...baseFilter,
            assignedAdminId: currentUser.id,
            role: { $in: ["bidder", "developer"] },
          },
          { projection: { _id: 0, id: 1 } }
        )
        .toArray()
    ).map((user) => user.id);
  }

  return [currentUser.id];
}

async function attachUserStats(portal, users, currentUser) {
  const enrichedUsers = users.map((user) => ({ ...user }));
  const clientIds = enrichedUsers.filter((user) => isClientRole(user.role)).map((user) => user.id);
  const visibleBidderIds = enrichedUsers.filter((user) => user.role === "bidder").map((user) => user.id);

  const assignedWorkers = clientIds.length
    ? stripMongoIds(
        await portal.users
          .find(
            {
              assignedAdminId: { $in: clientIds },
              role: { $in: ["bidder", "developer"] },
            },
            {
              projection: {
                _id: 0,
                id: 1,
                assignedAdminId: 1,
                role: 1,
                ratePerApplication: 1,
                bonusPerInterview: 1,
              },
            }
          )
          .toArray()
      )
    : [];
  const assignedWorkerIds = assignedWorkers.map((worker) => worker.id);
  const statBidderIds = Array.from(new Set([...visibleBidderIds, ...assignedWorkerIds]));

  const [workTotals, paymentTotals, escrowTotals] = await Promise.all([
    statBidderIds.length
      ? portal.workLogs
          .aggregate([
            { $match: { userId: { $in: statBidderIds } } },
            {
              $group: {
                _id: "$userId",
                totalApplied: { $sum: "$appliedJobs" },
                totalInterviews: { $sum: "$interviewsScheduled" },
              },
            },
          ])
          .toArray()
      : [],
    statBidderIds.length
      ? portal.payments
          .aggregate([
            { $match: { userId: { $in: statBidderIds }, status: { $in: ["paid", "processing"] } } },
            { $group: { _id: "$userId", totalPaid: { $sum: "$amount" } } },
          ])
          .toArray()
      : [],
    clientIds.length
      ? portal.escrows
          .aggregate([
            { $match: { clientId: { $in: clientIds }, status: "funded" } },
            {
              $group: {
                _id: "$clientId",
                escrowTotal: { $sum: "$amount" },
                escrowFeeTotal: { $sum: "$feeAmount" },
                escrowNetTotal: { $sum: "$netAmount" },
              },
            },
          ])
          .toArray()
      : [],
  ]);

  const workByUser = new Map(workTotals.map((total) => [total._id, total]));
  const paidByUser = new Map(paymentTotals.map((total) => [total._id, total.totalPaid || 0]));
  const escrowByClient = new Map(escrowTotals.map((total) => [total._id, total]));
  const workersByClient = new Map();
  const creditBalancesByUser = new Map(
    await Promise.all(
      enrichedUsers
        .filter((user) => canViewCreditBalance(currentUser, user))
        .map(async (user) => [user.id, await creditBalancesForUser(portal, user)])
    )
  );
  assignedWorkers.forEach((worker) => {
    const workers = workersByClient.get(worker.assignedAdminId) || [];
    workers.push(worker);
    workersByClient.set(worker.assignedAdminId, workers);
  });

  return enrichedUsers.map((user) => {
    if (isClientRole(user.role)) {
      const workers = workersByClient.get(user.id) || [];
      const bidderWorkers = workers.filter((worker) => worker.role === "bidder");
      const paidTotal = workers.reduce((total, worker) => total + (paidByUser.get(worker.id) || 0), 0);
      const escrow = escrowByClient.get(user.id) || {};
      const averageBidRate = bidderWorkers.length
        ? bidderWorkers.reduce((total, worker) => total + cleanNumber(worker.ratePerApplication), 0) / bidderWorkers.length
        : 0;
      const averageBonusGiven = bidderWorkers.length
        ? bidderWorkers.reduce((total, worker) => total + cleanNumber(worker.bonusPerInterview), 0) / bidderWorkers.length
        : 0;

      return {
        ...user,
        ...(creditBalancesByUser.has(user.id) ? { creditBalances: creditBalancesByUser.get(user.id) } : {}),
        clientStats: {
          assignedBidderCount: bidderWorkers.length,
          flaggedNoHires: bidderWorkers.length === 0,
          moneyPaid: Math.round(paidTotal * 100) / 100,
          bidderRating: cleanNumber(user.clientRating, 0),
          averageBidRate: Math.round(averageBidRate * 100) / 100,
          averageBonusGiven: Math.round(averageBonusGiven * 100) / 100,
          escrowTotal: Math.round(cleanNumber(escrow.escrowTotal) * 100) / 100,
          escrowFeeTotal: Math.round(cleanNumber(escrow.escrowFeeTotal) * 100) / 100,
          escrowNetTotal: Math.round(cleanNumber(escrow.escrowNetTotal) * 100) / 100,
        },
      };
    }

    if (user.role === "bidder") {
      const work = workByUser.get(user.id) || {};
      return {
        ...user,
        ...(creditBalancesByUser.has(user.id) ? { creditBalances: creditBalancesByUser.get(user.id) } : {}),
        bidderStats: {
          totalApplied: work.totalApplied || 0,
          totalInterviews: work.totalInterviews || 0,
          totalEarned: Math.round((paidByUser.get(user.id) || 0) * 100) / 100,
        },
      };
    }

    return {
      ...user,
      ...(creditBalancesByUser.has(user.id) ? { creditBalances: creditBalancesByUser.get(user.id) } : {}),
    };
  });
}

async function chatContactsForCurrentUser(portal, currentUser) {
  const baseFilter = userVisibilityFilter();
  let roleFilter = {};
  if (isSuperAdmin(currentUser)) {
    return [];
  }
  if (isClientRole(currentUser?.role)) {
    roleFilter = { role: { $in: ["bidder", "developer"] } };
  } else if (isPortalWorker(currentUser)) {
    roleFilter = { role: { $in: ["client", "admin"] } };
  } else {
    return [];
  }

  return stripMongoIds(
    await portal.users
      .find(
        {
          ...baseFilter,
          ...roleFilter,
          id: { $ne: currentUser.id },
          status: "approved",
        },
        { projection: PUBLIC_USER_PROJECTION }
      )
      .sort({ role: 1, name: 1 })
      .toArray()
  ).map(publicUser);
}

function contractFilterForUser(user) {
  if (isSuperAdmin(user)) {
    return {};
  }
  if (isClientRole(user?.role)) {
    return { clientId: user.id };
  }
  if (isPortalWorker(user)) {
    return { workerId: user.id };
  }
  return { id: "__none__" };
}

function postFilterForUser(user) {
  if (isSuperAdmin(user)) {
    return {};
  }
  if (isClientRole(user?.role)) {
    return {
      $or: [
        { type: "bidder", status: "active" },
      ],
    };
  }
  if (user?.role === "bidder") {
    return { authorId: user.id };
  }
  return { authorId: user?.id || "__none__" };
}

function bidProfileFilterForUser(user, users = []) {
  if (isSuperAdmin(user)) {
    return {};
  }
  if (isClientRole(user?.role)) {
    return { clientId: user.id };
  }
  if (isPortalWorker(user)) {
    const clientIds = users.filter((visibleUser) => isClientRole(visibleUser.role)).map((client) => client.id);
    return clientIds.length ? { clientId: { $in: clientIds } } : { clientId: "__none__" };
  }
  return { clientId: "__none__" };
}

function disputeFilterForUser(user) {
  if (isSuperAdmin(user)) {
    return {};
  }
  if (isClientRole(user?.role)) {
    return { clientId: user.id };
  }
  if (isPortalWorker(user)) {
    return { targetUserId: user.id };
  }
  return { id: "__none__" };
}

async function clientCreditBalance(portal, clientId, options = {}) {
  const depositTotals = await portal.deposits
    .aggregate([
      { $match: { clientId, status: "paid" } },
      { $group: { _id: "$clientId", totalCredits: { $sum: "$creditAmount" } } },
    ])
    .toArray();
  const paymentMatch = { clientId, status: { $in: ["paid", "processing"] } };
  if (options.excludePaymentId) {
    paymentMatch.id = { $ne: options.excludePaymentId };
  }
  const paymentTotals = await portal.payments
    .aggregate([
      { $match: paymentMatch },
      { $group: { _id: "$clientId", totalSpent: { $sum: "$amount" } } },
    ])
    .toArray();
  const moneyLedgerTotals = await portal.creditLedger
    .aggregate([
      { $match: { userId: clientId, creditType: "money" } },
      { $group: { _id: "$userId", totalAdjustments: { $sum: "$amount" } } },
    ])
    .toArray();

  return roundMoney(
    cleanNumber(depositTotals[0]?.totalCredits) -
      cleanNumber(paymentTotals[0]?.totalSpent) +
      cleanSignedNumber(moneyLedgerTotals[0]?.totalAdjustments)
  );
}

async function postCreditBalance(portal, userId) {
  const postTotals = await portal.creditLedger
    .aggregate([
      { $match: { userId, creditType: { $in: ["post", "gift"] } } },
      { $group: { _id: "$userId", totalPostCredit: { $sum: "$amount" } } },
    ])
    .toArray();

  return Math.max(0, roundSignedMoney(postTotals[0]?.totalPostCredit));
}

async function moneyCreditBalanceForUser(portal, user) {
  if (isClientRole(user?.role)) {
    return clientCreditBalance(portal, user.id);
  }

  const moneyLedgerTotals = await portal.creditLedger
    .aggregate([
      { $match: { userId: user?.id || "", creditType: "money" } },
      { $group: { _id: "$userId", totalMoney: { $sum: "$amount" } } },
    ])
    .toArray();

  return Math.max(0, roundSignedMoney(moneyLedgerTotals[0]?.totalMoney));
}

async function creditBalancesForUser(portal, user) {
  const [moneyCreditBalance, postCreditBalanceAmount] = await Promise.all([
    moneyCreditBalanceForUser(portal, user),
    postCreditBalance(portal, user?.id || ""),
  ]);

  return {
    moneyCreditBalance,
    postCreditBalance: postCreditBalanceAmount,
    postingCreditBalance: postCreditBalanceAmount,
  };
}

function canViewCreditBalance(viewer, target) {
  if (!viewer || !target || isSuperAdmin(target)) {
    return false;
  }
  if (isSuperAdmin(viewer) || viewer.id === target.id) {
    return true;
  }
  return isPortalWorker(viewer) && isClientRole(target.role) && viewer.assignedAdminId === target.id;
}

async function spendPostingCredit(portal, user, postId, stamp) {
  const balances = await creditBalancesForUser(portal, user);
  if (balances.postCreditBalance < POST_CREDIT_COST) {
    throw new Error("You need at least $1 post credit to publish a post.");
  }

  const postCreditUsed = POST_CREDIT_COST;
  await portal.creditLedger.insertOne({
    id: createId("credit"),
    userId: user.id,
    creditType: "post",
    amount: -postCreditUsed,
    source: "post_fee",
    relatedPostId: postId,
    relatedContractId: "",
    memo: "Post publishing fee",
    createdAt: stamp,
    updatedAt: stamp,
  });

  return { postCreditUsed, moneyCreditUsed: 0 };
}

function moneyLabel(amount) {
  return `$${roundMoney(amount).toFixed(2)}`;
}

async function createSuperAdminCreditNotification(portal, { client, deposit, source = "Cryptomus" }) {
  const stamp = now();
  const clientName = client?.name || "Client";
  const creditAmount = roundMoney(deposit.creditAmount);
  const amount = roundMoney(deposit.amount);

  await portal.notifications.updateOne(
    { type: "client_credit_paid", relatedDepositId: deposit.id },
    {
      $setOnInsert: {
        id: createId("notification"),
        recipientRole: "super_admin",
        type: "client_credit_paid",
        title: "Client credit added",
        body: `${clientName} added ${moneyLabel(creditAmount)} credits through ${source}.`,
        clientId: deposit.clientId,
        relatedDepositId: deposit.id,
        amount,
        creditAmount,
        readAt: "",
        createdAt: stamp,
      },
      $set: {
        updatedAt: stamp,
      },
    },
    { upsert: true }
  );
}

async function createUserNotification(portal, { recipientUserId, type, title, body, relatedWorkLogId = "", actorUserId = "" }) {
  const cleanRecipientUserId = cleanText(recipientUserId);
  if (!cleanRecipientUserId) {
    return;
  }

  const stamp = now();
  await portal.notifications.insertOne({
    id: createId("notification"),
    recipientUserId: cleanRecipientUserId,
    recipientRole: "",
    type: cleanText(type),
    title: cleanText(title).slice(0, 140),
    body: cleanText(body).slice(0, 800),
    relatedWorkLogId: cleanText(relatedWorkLogId),
    actorUserId: cleanText(actorUserId),
    clientId: "",
    relatedDepositId: "",
    amount: 0,
    creditAmount: 0,
    readAt: "",
    createdAt: stamp,
    updatedAt: stamp,
  });
}

async function notifyAssignedClientForWorkLog(portal, { bidder, workLogId, type, title, body }) {
  const assignedClientId = cleanText(bidder?.assignedAdminId);
  if (!assignedClientId) {
    return;
  }

  const client = stripMongoId(
    await portal.users.findOne(
      {
        id: assignedClientId,
        role: { $in: ["client", "admin"] },
        status: "approved",
      },
      { projection: { _id: 0, id: 1 } }
    )
  );
  if (!client) {
    return;
  }

  await createUserNotification(portal, {
    recipientUserId: client.id,
    type,
    title,
    body,
    relatedWorkLogId: workLogId,
    actorUserId: bidder.id,
  });
}

async function getPortalDataForUser(currentUser, sessionToken = "") {
  const portal = collections(await getDb());
  const safeCurrentUser = publicUser(currentUser);
  const users = await attachUserStats(portal, await visibleUsersForCurrentUser(portal, currentUser), safeCurrentUser);
  const recordUserIds = await recordUserIdsForCurrentUser(portal, safeCurrentUser, users);
  const userFilter = { userId: { $in: recordUserIds } };
  const escrowFilter = isSuperAdmin(safeCurrentUser)
    ? {}
    : isClientRole(safeCurrentUser.role)
      ? { clientId: safeCurrentUser.id }
      : { clientId: { $in: [] } };
  const depositFilter = escrowFilter;
  const notificationFilter = isSuperAdmin(safeCurrentUser)
    ? { $or: [{ recipientRole: "super_admin" }, { recipientUserId: safeCurrentUser.id }] }
    : { recipientUserId: safeCurrentUser.id };

  const [paymentMethods, workLogs, payments, escrows, deposits, contracts, posts, bidProfiles, disputes, notifications, chatContacts, chatMessages] = await Promise.all([
    portal.paymentMethods.find(userFilter, { projection: { _id: 0 } }).sort({ isPrimary: -1, updatedAt: -1 }).toArray(),
    portal.workLogs.find(userFilter, { projection: { _id: 0 } }).sort({ workDate: -1, createdAt: -1 }).toArray(),
    portal.payments.find(userFilter, { projection: { _id: 0 } }).sort({ scheduledDate: -1, createdAt: -1 }).toArray(),
    portal.escrows.find(escrowFilter, { projection: { _id: 0 } }).sort({ createdAt: -1 }).toArray(),
    portal.deposits.find(depositFilter, { projection: { _id: 0 } }).sort({ createdAt: -1 }).toArray(),
    portal.contracts.find(contractFilterForUser(safeCurrentUser), { projection: { _id: 0 } }).sort({ updatedAt: -1, createdAt: -1 }).toArray(),
    portal.posts.find(postFilterForUser(safeCurrentUser), { projection: { _id: 0 } }).sort({ createdAt: -1 }).limit(200).toArray(),
    portal.bidProfiles.find(bidProfileFilterForUser(safeCurrentUser, users), { projection: { _id: 0 } }).sort({ updatedAt: -1 }).limit(200).toArray(),
    portal.disputes.find(disputeFilterForUser(safeCurrentUser), { projection: { _id: 0 } }).sort({ updatedAt: -1 }).limit(200).toArray(),
    portal.notifications.find(notificationFilter, { projection: { _id: 0 } }).sort({ createdAt: -1 }).limit(50).toArray(),
    chatContactsForCurrentUser(portal, safeCurrentUser),
    portal.chatMessages
      .find(directMessageFilterForUser(safeCurrentUser), { projection: { _id: 0 } })
      .sort({ createdAt: 1 })
      .limit(200)
      .toArray(),
  ]);
  const enrichedCurrentUser = users.find((user) => user.id === safeCurrentUser.id) || safeCurrentUser;

  return {
    currentUser: enrichedCurrentUser,
    sessionToken,
    users,
    paymentMethods: stripMongoIds(paymentMethods),
    workLogs: stripMongoIds(workLogs),
    payments: stripMongoIds(payments),
    escrows: stripMongoIds(escrows),
    deposits: stripMongoIds(deposits),
    contracts: stripMongoIds(contracts),
    posts: stripMongoIds(posts),
    bidProfiles: stripMongoIds(bidProfiles),
    disputes: stripMongoIds(disputes),
    notifications: stripMongoIds(notifications),
    chatContacts,
    chatMessages: stripMongoIds(chatMessages),
  };
}

export async function getPortalData(email, sessionToken) {
  const currentUser = await getSessionUser(email, sessionToken, { allowIncompleteProfile: true });
  return getPortalDataForUser(currentUser, sessionToken);
}

export async function refreshPortal(email, sessionToken) {
  return getPortalData(email, sessionToken);
}

function canManageUser(actor, target) {
  return isSuperAdmin(actor) && Boolean(target);
}

function assertCanManageUser(actor, target, actionLabel = "manage") {
  if (!canManageUser(actor, target)) {
    throw new Error(`You can only ${actionLabel} assigned bidders.`);
  }
}

function canManagePaymentUser(actor, target) {
  if (!isPortalWorker(target)) {
    return false;
  }
  if (isSuperAdmin(actor)) {
    return true;
  }
  return isClientRole(actor?.role) && target.assignedAdminId === actor.id;
}

function assertCanManagePaymentUser(actor, target) {
  if (!canManagePaymentUser(actor, target)) {
    throw new Error("You can only manage payments for assigned bidders.");
  }
}

export async function signIn(emailInput, passwordInput, nameInput) {
  await ensurePortalSchema();
  const email = normalizeEmail(emailInput);
  validateEmail(email);
  assertDemoAccountAllowed(email);

  let user = await getUserByEmail(email, { includeSecrets: true });
  if (!user) {
    throw new Error("Account not found. Please sign up first.");
  }

  const verifiedUser = await verifyOrSetPassword(user, passwordInput);
  if (!verifiedUser.emailVerifiedAt) {
    throw new Error(EMAIL_VERIFICATION_SIGN_IN_ERROR);
  }

  const sessionToken = await createSession(verifiedUser);
  return getPortalDataForUser(verifiedUser, sessionToken);
}

export async function requestPasswordReset(emailInput) {
  await ensurePortalSchema();
  const portal = collections(await getDb());
  const email = normalizeEmail(emailInput);
  validateEmail(email);
  assertDemoAccountAllowed(email);

  const user = await getUserByEmail(email, { includeSecrets: true });
  if (!user) {
    return { ok: true, message: "If that account exists, a reset email has been sent." };
  }

  const token = await createAuthToken(portal, user, "password_reset", RESET_TOKEN_MS);
  const resetLink = `${appBaseUrl()}/?resetEmail=${encodeURIComponent(email)}&resetToken=${encodeURIComponent(token)}`;
  const stamp = now();

  await sendPortalEmail(portal, {
    to: email,
    subject: "Reset your Bidder Portal password",
    text: `Use this link to reset your password: ${resetLink}`,
    html: `<p>Use this link to reset your Bidder Portal password:</p><p><a href="${resetLink}">${resetLink}</a></p>`,
  });
  await portal.users.updateOne({ id: user.id }, { $set: { passwordResetSentAt: stamp, updatedAt: stamp } });

  return { ok: true, message: "If that account exists, a reset email has been sent." };
}

async function sendEmailVerificationToUser(portal, target) {
  const token = await createAuthToken(portal, target, "email_verification", VERIFY_TOKEN_MS);
  const verifyLink = `${appBaseUrl()}/?verifyEmail=${encodeURIComponent(target.email)}&verifyToken=${encodeURIComponent(token)}`;
  const stamp = now();

  await sendPortalEmail(portal, {
    to: target.email,
    subject: "Verify your Bidder Portal email",
    text: `Use this link to verify your email: ${verifyLink}`,
    html: `<p>Use this link to verify your Bidder Portal email:</p><p><a href="${verifyLink}">${verifyLink}</a></p>`,
  });
  await portal.users.updateOne({ id: target.id }, { $set: { emailVerificationSentAt: stamp, updatedAt: stamp } });
}

export async function resetPassword(emailInput, tokenInput, passwordInput) {
  await ensurePortalSchema();
  const portal = collections(await getDb());
  const email = normalizeEmail(emailInput);
  const password = cleanPassword(passwordInput);
  validateEmail(email);
  validatePassword(password);
  assertDemoAccountAllowed(email);

  const authToken = await consumeAuthToken(portal, email, tokenInput, "password_reset");
  const user = await getUserById(authToken.userId, { includeSecrets: true });
  if (!user || user.email !== email) {
    throw new Error("This reset link is invalid.");
  }

  const stamp = now();
  await portal.users.updateOne(
    { id: user.id },
    {
      $set: {
        passwordHash: await hashPassword(password),
        passwordUpdatedAt: stamp,
        passwordResetSentAt: "",
        updatedAt: stamp,
      },
    }
  );
  await portal.sessions.deleteMany({ userId: user.id });
  const updatedUser = await getUserById(user.id, { includeSecrets: true });
  if (!updatedUser.emailVerifiedAt) {
    await sendEmailVerificationToUser(portal, updatedUser);
    return {
      ok: true,
      needsEmailVerification: true,
      email: updatedUser.email,
      message: "Password reset. Check your email to verify your account before signing in.",
    };
  }

  const sessionToken = await createSession(updatedUser);

  return getPortalDataForUser(updatedUser, sessionToken);
}

export async function requestEmailVerification(email, payload = {}) {
  const currentUser = await getSessionUser(email, payload.sessionToken, { allowIncompleteProfile: true });
  const portal = collections(await getDb());
  const targetUserId = cleanText(payload.targetUserId, currentUser.id);
  const target = await getUserById(targetUserId, { includeSecrets: true });
  if (!target) {
    throw new Error("User not found.");
  }
  if (target.id !== currentUser.id) {
    if (!isSuperAdmin(currentUser)) {
      throw new Error("You cannot verify another user's email.");
    }
    assertCanManageUser(currentUser, target, "send verification for");
  }
  if (!targetVisibleInLive(target)) {
    throw new Error("Demo accounts cannot be verified in live mode.");
  }
  if (target.emailVerifiedAt) {
    return getPortalDataForUser(currentUser, payload.sessionToken);
  }

  await sendEmailVerificationToUser(portal, target);

  return getPortalDataForUser(currentUser, payload.sessionToken);
}

export async function updateOwnEmail(email, payload = {}) {
  const currentUser = await getSessionUser(email, payload.sessionToken, { allowIncompleteProfile: true });
  const portal = collections(await getDb());
  const nextEmail = normalizeEmail(payload.newEmail || payload.email);
  validateEmail(nextEmail);
  assertDemoAccountAllowed(nextEmail);

  if (currentUser.passwordHash) {
    const currentPassword = cleanPassword(payload.currentPassword);
    if (!currentPassword || !(await verifyPassword(currentPassword, currentUser.passwordHash))) {
      throw new Error("Current password is incorrect.");
    }
  }

  if (nextEmail === currentUser.email) {
    return getPortalDataForUser(currentUser, payload.sessionToken);
  }

  const existingUser = await getUserByEmail(nextEmail, { includeSecrets: true });
  if (existingUser && existingUser.id !== currentUser.id) {
    throw new Error("That email is already used by another account.");
  }

  const stamp = now();
  await portal.users.updateOne(
    { id: currentUser.id },
    {
      $set: {
        email: nextEmail,
        emailVerifiedAt: "",
        emailVerificationSentAt: "",
        updatedAt: stamp,
      },
    }
  );

  const updatedUser = await getUserById(currentUser.id, { includeSecrets: true });
  await sendEmailVerificationToUser(portal, updatedUser);
  await portal.sessions.deleteMany({ userId: currentUser.id });

  return {
    ok: true,
    needsEmailVerification: true,
    email: nextEmail,
    message: "Email changed. Check your email to verify the new address before signing in.",
  };
}

export async function updateOwnPassword(email, payload = {}) {
  const currentUser = await getSessionUser(email, payload.sessionToken, { allowIncompleteProfile: true });
  const currentPassword = cleanPassword(payload.currentPassword);
  const newPassword = cleanPassword(payload.newPassword || payload.password);
  validatePassword(newPassword);

  if (currentUser.passwordHash) {
    if (!currentPassword || !(await verifyPassword(currentPassword, currentUser.passwordHash))) {
      throw new Error("Current password is incorrect.");
    }
  }

  const portal = collections(await getDb());
  const stamp = now();
  await portal.users.updateOne(
    { id: currentUser.id },
    {
      $set: {
        passwordHash: await hashPassword(newPassword),
        passwordUpdatedAt: stamp,
        passwordResetSentAt: "",
        updatedAt: stamp,
      },
    }
  );

  const updatedUser = await getUserById(currentUser.id, { includeSecrets: true });
  return getPortalDataForUser(updatedUser, payload.sessionToken);
}

export async function verifyEmail(emailInput, tokenInput) {
  await ensurePortalSchema();
  const portal = collections(await getDb());
  const email = normalizeEmail(emailInput);
  validateEmail(email);
  assertDemoAccountAllowed(email);

  const authToken = await consumeAuthToken(portal, email, tokenInput, "email_verification");
  const stamp = now();
  await portal.users.updateOne(
    { id: authToken.userId, email },
    {
      $set: {
        emailVerifiedAt: stamp,
        emailVerificationSentAt: "",
        updatedAt: stamp,
      },
    }
  );

  return { ok: true, message: "Email verified. You can sign in now." };
}

export async function setUserPasswordAsAdmin(adminEmail, payload) {
  const admin = await getSessionUser(adminEmail, payload.sessionToken);
  if (!isSuperAdmin(admin)) {
    throw new Error("Only super admins can reset user passwords.");
  }

  const targetUserId = cleanText(payload.targetUserId);
  const password = cleanPassword(payload.password);
  validatePassword(password);

  const target = await getUserById(targetUserId);
  if (!target) {
    throw new Error("User not found.");
  }
  if (!targetVisibleInLive(target)) {
    throw new Error("Demo accounts cannot be managed in live mode.");
  }
  assertCanManageUser(admin, target, "reset passwords for");

  const portal = collections(await getDb());
  const stamp = now();
  await portal.users.updateOne(
    { id: target.id },
    {
      $set: {
        passwordHash: await hashPassword(password),
        passwordUpdatedAt: stamp,
        passwordResetSentAt: "",
        updatedAt: stamp,
      },
    }
  );
  await portal.sessions.deleteMany({ userId: target.id });

  return getPortalDataForUser(admin, payload.sessionToken);
}

export async function updateUserAsAdmin(adminEmail, payload) {
  const admin = await getSessionUser(adminEmail, payload.sessionToken);
  if (!isSuperAdmin(admin)) {
    throw new Error("Only super admins can manage users.");
  }

  const targetUserId = cleanText(payload.targetUserId);
  const target = await getUserById(targetUserId);
  if (!target) {
    throw new Error("User not found.");
  }
  if (!targetVisibleInLive(target)) {
    throw new Error("Demo accounts cannot be managed in live mode.");
  }
  assertCanManageUser(admin, target);

  const role = cleanRole(payload.role, target.role);
  const status = cleanText(payload.status, target.status);
  const safeRole = canonicalRole(role);
  const safeStatus = ["pending", "approved", "paused"].includes(status) ? status : target.status;
  const isNonWorkerRoleTarget = safeRole === "super_admin" || isClientRole(safeRole);
  const portal = collections(await getDb());
  let assignedAdminId = target.assignedAdminId || "";
  assignedAdminId = safeRole === "bidder" ? cleanText(payload.assignedAdminId, assignedAdminId) : "";
  if (assignedAdminId) {
    const assignedAdmin = await getUserById(assignedAdminId);
    if (!assignedAdmin || !isClientRole(assignedAdmin.role) || assignedAdmin.status !== "approved" || !targetVisibleInLive(assignedAdmin)) {
      throw new Error("Select a valid client for this bidder.");
    }
  }

  if (target.role === "super_admin" && (safeRole !== "super_admin" || safeStatus !== "approved")) {
    const liveFilter = isLiveMode() ? { email: { $nin: Array.from(DEMO_EMAILS) } } : {};
    const otherSuperAdminCount = await portal.users.countDocuments({
      ...liveFilter,
      role: "super_admin",
      status: "approved",
      id: { $ne: target.id },
    });
    if (otherSuperAdminCount < 1) {
      throw new Error("At least one approved super admin account must remain.");
    }
  }

  const targetSchedule = paymentScheduleFromUser(target);
  const frequency = normalizePaymentFrequency(payload.paymentFrequency) || targetSchedule.frequency;
  const weekday = normalizePaymentWeekday(payload.paymentWeekday) || targetSchedule.weekday;
  const nextPaymentDate = isNonWorkerRoleTarget
    ? ""
    : await nextOpenPaymentDate(portal, target.id, frequency, weekday, cleanText(payload.nextPaymentDate, target.nextPaymentDate));
  const paymentSchedule = isNonWorkerRoleTarget
    ? ""
    : paymentScheduleLabel(frequency, weekday) || cleanText(payload.paymentSchedule, target.paymentSchedule);

  const stamp = now();
  await portal.users.updateOne(
    { id: target.id },
    {
      $set: {
        name: cleanText(payload.name, target.name) || target.name,
        role: safeRole,
        status: safeStatus,
        assignedAdminId,
        ratePerApplication: isNonWorkerRoleTarget ? 0 : cleanNumber(payload.ratePerApplication, target.ratePerApplication),
        bonusPerInterview: isNonWorkerRoleTarget ? 0 : cleanNumber(payload.bonusPerInterview, target.bonusPerInterview),
        nextPaymentDate,
        paymentSchedule,
        paymentFrequency: isNonWorkerRoleTarget ? "" : frequency,
        paymentWeekday: isNonWorkerRoleTarget ? "" : weekday,
        updatedAt: stamp,
      },
    }
  );
  if (isClientRole(target.role) && !isClientRole(safeRole)) {
    await portal.users.updateMany({ assignedAdminId: target.id }, { $set: { assignedAdminId: "", updatedAt: stamp } });
  }

  return getPortalDataForUser(admin, payload.sessionToken);
}

export async function deleteUserAsAdmin(adminEmail, payload) {
  const admin = await getSessionUser(adminEmail, payload.sessionToken);
  if (!isSuperAdmin(admin)) {
    throw new Error("Only super admins can remove users.");
  }

  const portal = collections(await getDb());
  const targetUserId = cleanText(payload.targetUserId);
  const target = await getUserById(targetUserId);
  if (!target) {
    throw new Error("User not found.");
  }
  if (!targetVisibleInLive(target)) {
    throw new Error("Demo accounts cannot be managed in live mode.");
  }
  if (target.id === admin.id) {
    throw new Error("You cannot remove your own account.");
  }
  assertCanManageUser(admin, target, "remove");
  if (target.role === "super_admin") {
    const liveFilter = isLiveMode() ? { email: { $nin: Array.from(DEMO_EMAILS) } } : {};
    const otherSuperAdminCount = await portal.users.countDocuments({
      ...liveFilter,
      role: "super_admin",
      status: "approved",
      id: { $ne: target.id },
    });
    if (otherSuperAdminCount < 1) {
      throw new Error("At least one approved super admin account must remain.");
    }
  }

  const stamp = now();
  await Promise.all([
    portal.users.deleteOne({ id: target.id }),
    portal.users.updateMany({ assignedAdminId: target.id }, { $set: { assignedAdminId: "", updatedAt: stamp } }),
    portal.paymentMethods.deleteMany({ userId: target.id }),
    portal.workLogs.deleteMany({ userId: target.id }),
    portal.payments.deleteMany({ userId: target.id }),
    portal.contracts.updateMany(
      { $or: [{ clientId: target.id }, { workerId: target.id }], status: { $in: OPEN_CONTRACT_STATUSES } },
      { $set: { status: "ended", endedAt: stamp, updatedAt: stamp } }
    ),
    portal.posts.updateMany({ authorId: target.id, status: "active" }, { $set: { status: "closed", closedAt: stamp, updatedAt: stamp } }),
    portal.bidProfiles.deleteMany({ clientId: target.id }),
    portal.disputes.deleteMany({ $or: [{ clientId: target.id }, { targetUserId: target.id }] }),
    portal.creditLedger.deleteMany({ userId: target.id }),
    portal.chatMessages.deleteMany({ $or: [{ userId: target.id }, { recipientId: target.id }] }),
    portal.sessions.deleteMany({ userId: target.id }),
    portal.authTokens.deleteMany({ userId: target.id }),
  ]);

  return getPortalDataForUser(admin, payload.sessionToken);
}

export async function saveProfile(email, payload) {
  const currentUser = await getSessionUser(email, payload.sessionToken, { allowIncompleteProfile: true });
  const portal = collections(await getDb());
  const stamp = now();
  const name = cleanText(payload.name, currentUser.name).slice(0, 90) || currentUser.name;
  const profileTitle = cleanText(payload.profileTitle).slice(0, 90);
  const profileBio = cleanText(payload.profileBio).slice(0, 900);
  const profileSkills = cleanProfileSkills(payload.profileSkills);
  const country = cleanText(payload.country || payload.profileLocation).slice(0, 120);
  const profileLocation = cleanText(payload.profileLocation, country).slice(0, 120) || country;
  const profileTimeZone = cleanText(payload.profileTimeZone).slice(0, 80);
  const companyName = cleanText(payload.companyName).slice(0, 120);
  const clientPreferences = cleanProfileSkills(payload.clientPreferences);
  const profileLanguages = cleanProfileSkills(payload.profileLanguages);
  const allowDirectMessages = payload.allowDirectMessages !== false;
  const profileDraft = {
    ...currentUser,
    name,
    profileTitle,
    profileBio,
    profileSkills,
    profileLocation,
    profileTimeZone,
    companyName,
    country,
    clientPreferences,
    profileLanguages,
    allowDirectMessages,
  };
  const profileCompletedAt = profileCompleteForUser(profileDraft)
    ? currentUser.profileCompletedAt || stamp
    : "";

  await portal.users.updateOne(
    { id: currentUser.id },
    {
      $set: {
        name,
        profileTitle,
        profileBio,
        profileSkills,
        profileLocation,
        profileTimeZone,
        companyName,
        country,
        clientPreferences,
        profileLanguages,
        allowDirectMessages,
        profileCompletedAt,
        updatedAt: stamp,
      },
    }
  );

  const updatedUser = await getUserById(currentUser.id, { includeSecrets: true });
  return getPortalDataForUser(updatedUser, payload.sessionToken);
}

export async function saveBidProfile(email, payload) {
  const currentUser = await getSessionUser(email, payload.sessionToken);
  if (!isSuperAdmin(currentUser) && !isClientRole(currentUser.role)) {
    throw new Error("Only clients can manage bid profiles.");
  }

  const portal = collections(await getDb());
  const targetClientId = isSuperAdmin(currentUser) ? cleanText(payload.clientId, currentUser.id) : currentUser.id;
  const targetClient = await getUserById(targetClientId);
  if (!targetClient || !isClientRole(targetClient.role) || !targetVisibleInLive(targetClient)) {
    throw new Error("Select a valid client for this bid profile.");
  }

  const bidProfileId = cleanText(payload.bidProfileId);
  if (bidProfileId) {
    const existingProfile = stripMongoId(await portal.bidProfiles.findOne({ id: bidProfileId }, { projection: { _id: 0 } }));
    if (!existingProfile) {
      throw new Error("Bid profile not found.");
    }
    if (!isSuperAdmin(currentUser) && existingProfile.clientId !== currentUser.id) {
      throw new Error("You can only manage your own bid profiles.");
    }
  }

  const profileName = cleanText(payload.profileName).slice(0, 120);
  const fullLegalName = cleanText(payload.fullLegalName).slice(0, 120);
  const contactEmail = normalizeEmail(payload.contactEmail || targetClient.email);
  const phone = cleanText(payload.phone).slice(0, 80);
  const targetSalary = cleanText(payload.targetSalary).slice(0, 80);
  const visaStatus = cleanText(payload.visaStatus).slice(0, 80);
  const jobTitles = cleanProfileSkills(payload.jobTitles);
  const extraFields = cleanExtraFields(payload.extraFields);
  const notes = cleanText(payload.notes).slice(0, 900);

  if (!profileName || !fullLegalName || !contactEmail || !jobTitles.length) {
    throw new Error("Bid profile name, legal name, email, and job titles are required.");
  }
  validateEmail(contactEmail);

  const stamp = now();
  const id = bidProfileId || createId("bid_profile");
  await portal.bidProfiles.updateOne(
    { id },
    {
      $set: {
        clientId: targetClient.id,
        profileName,
        fullLegalName,
        contactEmail,
        phone,
        targetSalary,
        visaStatus,
        jobTitles,
        extraFields,
        notes,
        updatedAt: stamp,
      },
      $setOnInsert: {
        id,
        createdAt: stamp,
      },
    },
    { upsert: true }
  );

  return getPortalDataForUser(currentUser, payload.sessionToken);
}

export async function deleteBidProfile(email, payload) {
  const currentUser = await getSessionUser(email, payload.sessionToken);
  if (!isSuperAdmin(currentUser) && !isClientRole(currentUser.role)) {
    throw new Error("Only clients can delete bid profiles.");
  }

  const portal = collections(await getDb());
  const bidProfileId = cleanText(payload.bidProfileId);
  const existingProfile = stripMongoId(await portal.bidProfiles.findOne({ id: bidProfileId }, { projection: { _id: 0 } }));
  if (!existingProfile) {
    throw new Error("Bid profile not found.");
  }
  if (!isSuperAdmin(currentUser) && existingProfile.clientId !== currentUser.id) {
    throw new Error("You can only delete your own bid profiles.");
  }

  await portal.bidProfiles.deleteOne({ id: existingProfile.id });
  return getPortalDataForUser(currentUser, payload.sessionToken);
}

export async function createDispute(email, payload) {
  const currentUser = await getSessionUser(email, payload.sessionToken);
  if (!isClientRole(currentUser.role)) {
    throw new Error("Only clients can open disputes.");
  }

  const subject = cleanText(payload.subject).slice(0, 140);
  const body = cleanText(payload.body).slice(0, 1200);
  if (!subject || !body) {
    throw new Error("Dispute subject and details are required.");
  }

  const targetUserId = cleanText(payload.targetUserId);
  if (targetUserId) {
    const target = await getUserById(targetUserId);
    if (!target || !isPortalWorker(target) || target.assignedAdminId !== currentUser.id || !targetVisibleInLive(target)) {
      throw new Error("Select an assigned bidder for this dispute.");
    }
  }

  const contractId = cleanText(payload.contractId);
  const paymentId = cleanText(payload.paymentId);
  const portal = collections(await getDb());
  if (contractId) {
    const contract = await portal.contracts.findOne({ id: contractId, clientId: currentUser.id }, { projection: { _id: 1 } });
    if (!contract) {
      throw new Error("Select a valid contract for this dispute.");
    }
  }
  if (paymentId) {
    const payment = await portal.payments.findOne({ id: paymentId, clientId: currentUser.id }, { projection: { _id: 1 } });
    if (!payment) {
      throw new Error("Select a valid payment for this dispute.");
    }
  }

  const stamp = now();
  await portal.disputes.insertOne({
    id: createId("dispute"),
    clientId: currentUser.id,
    targetUserId,
    contractId,
    paymentId,
    subject,
    body,
    status: "open",
    resolution: "",
    createdAt: stamp,
    updatedAt: stamp,
    resolvedAt: "",
    closedAt: "",
  });

  return getPortalDataForUser(currentUser, payload.sessionToken);
}

export async function updateDispute(email, payload) {
  const currentUser = await getSessionUser(email, payload.sessionToken);
  if (!isSuperAdmin(currentUser)) {
    throw new Error("Only super admins can resolve disputes.");
  }

  const disputeId = cleanText(payload.disputeId);
  const status = cleanText(payload.status).toLowerCase();
  if (!DISPUTE_STATUSES.has(status)) {
    throw new Error("Select a valid dispute status.");
  }

  const portal = collections(await getDb());
  const dispute = stripMongoId(await portal.disputes.findOne({ id: disputeId }, { projection: { _id: 0 } }));
  if (!dispute) {
    throw new Error("Dispute not found.");
  }

  const stamp = now();
  await portal.disputes.updateOne(
    { id: dispute.id },
    {
      $set: {
        status,
        resolution: cleanText(payload.resolution, dispute.resolution || "").slice(0, 1200),
        resolvedAt: status === "resolved" ? dispute.resolvedAt || stamp : dispute.resolvedAt || "",
        closedAt: status === "closed" ? dispute.closedAt || stamp : dispute.closedAt || "",
        updatedAt: stamp,
      },
    }
  );

  return getPortalDataForUser(currentUser, payload.sessionToken);
}

export async function addEscrowAsClient(email, payload) {
  const currentUser = await getSessionUser(email, payload.sessionToken);
  if (!isSuperAdmin(currentUser) && !isClientRole(currentUser.role)) {
    throw new Error("Only clients and super admins can add escrow records.");
  }

  const portal = collections(await getDb());
  const targetClientId = isSuperAdmin(currentUser) ? cleanText(payload.clientId) : currentUser.id;
  const targetClient = await getUserById(targetClientId);
  if (!targetClient || !isClientRole(targetClient.role) || !targetVisibleInLive(targetClient)) {
    throw new Error("Select a valid client for escrow.");
  }

  const amount = cleanNumber(payload.amount);
  if (amount <= 0) {
    throw new Error("Escrow amount is required.");
  }

  const feeAmount = escrowFeeFor(amount);
  const netAmount = Math.round((amount - feeAmount) * 100) / 100;
  const stamp = now();
  await portal.escrows.insertOne({
    id: createId("escrow"),
    clientId: targetClient.id,
    amount,
    feeAmount,
    netAmount,
    status: "funded",
    receiptLink: cleanText(payload.receiptLink),
    memo: cleanText(payload.memo),
    createdAt: stamp,
    updatedAt: stamp,
  });

  return getPortalDataForUser(currentUser, payload.sessionToken);
}

async function createCryptomusInvoice(payload) {
  assertCryptomusConfigured();

  const response = await fetch(`${cryptomusApiBaseUrl()}/v1/payment`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      merchant: cryptomusMerchantUuid(),
      sign: cryptomusSign(payload),
    },
    body: JSON.stringify(payload),
  });
  const result = await response.json().catch(() => ({}));
  if (!response.ok || result.state === 1) {
    throw new Error(result.message || "Cryptomus invoice creation failed.");
  }

  return result.result || result;
}

async function createCryptomusPayout(payload) {
  assertCryptomusPayoutConfigured();

  if (cryptomusPayoutTestMode()) {
    return {
      uuid: `test_${payload.order_id}`,
      status: "process",
      txid: "",
      test_mode: true,
    };
  }

  const response = await fetch(`${cryptomusApiBaseUrl()}/v1/payout`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      merchant: cryptomusMerchantUuid(),
      sign: cryptomusSign(payload, cryptomusPayoutKey()),
    },
    body: JSON.stringify(payload),
  });
  const result = await response.json().catch(() => ({}));
  if (!response.ok || result.state === 1) {
    throw new Error(result.message || "Cryptomus payout creation failed.");
  }

  return result.result || result;
}

function paymentStatusFromPayoutStatus(status) {
  const normalizedStatus = cleanText(status).toLowerCase();
  if (normalizedStatus === "paid" || normalizedStatus === "success") {
    return "paid";
  }
  if (["fail", "failed", "cancel", "canceled", "system_fail"].includes(normalizedStatus)) {
    return "failed";
  }
  return "processing";
}

export async function createCreditDeposit(email, payload) {
  const currentUser = await getSessionUser(email, payload.sessionToken);
  if (!isSuperAdmin(currentUser) && !isClientRole(currentUser.role)) {
    throw new Error("Only clients can deposit credits.");
  }

  const portal = collections(await getDb());
  const targetClientId = isSuperAdmin(currentUser) ? cleanText(payload.clientId) : currentUser.id;
  const targetClient = await getUserById(targetClientId);
  if (!targetClient || !isClientRole(targetClient.role) || !targetVisibleInLive(targetClient)) {
    throw new Error("Select a valid client for credit deposit.");
  }

  const amount = roundMoney(payload.amount);
  if (amount <= 0) {
    throw new Error("Deposit amount is required.");
  }

  const feeAmount = escrowFeeFor(amount);
  const creditAmount = roundMoney(amount - feeAmount);
  const stamp = now();
  const orderId = `deposit_${randomUUID().replace(/-/g, "")}`;
  const currency = cleanText(payload.currency, CREDIT_CURRENCY).toUpperCase() || CREDIT_CURRENCY;
  const toCurrency = cleanText(payload.toCurrency, "USDT").toUpperCase() || "USDT";
  const network = cleanText(payload.network).toLowerCase();
  const callbackUrl = cryptomusCallbackUrl();
  const appBaseUrl = cleanText(process.env.APP_BASE_URL).replace(/\/$/, "");
  const invoicePayload = {
    amount: amount.toFixed(2),
    currency,
    order_id: orderId,
    to_currency: toCurrency,
    is_payment_multiple: false,
    lifetime: 43200,
    additional_data: targetClient.id,
    ...(network ? { network } : {}),
    ...(callbackUrl ? { url_callback: callbackUrl } : {}),
    ...(appBaseUrl ? { url_return: `${appBaseUrl}/billing`, url_success: `${appBaseUrl}/billing` } : {}),
  };

  await portal.deposits.insertOne({
    id: createId("deposit"),
    clientId: targetClient.id,
    provider: "cryptomus",
    orderId,
    invoiceUuid: "",
    amount,
    feeAmount,
    creditAmount,
    currency,
    toCurrency,
    network,
    status: "pending",
    providerStatus: "check",
    paymentUrl: "",
    paymentAmountUsd: 0,
    merchantAmount: 0,
    txid: "",
    rawProvider: {},
    createdAt: stamp,
    updatedAt: stamp,
    paidAt: "",
  });

  const invoice = await createCryptomusInvoice(invoicePayload);
  await portal.deposits.updateOne(
    { orderId },
    {
      $set: {
        invoiceUuid: cleanText(invoice.uuid),
        providerStatus: cleanText(invoice.payment_status || invoice.status || "check"),
        paymentUrl: cleanText(invoice.url),
        rawProvider: invoice,
        updatedAt: now(),
      },
    }
  );

  return getPortalDataForUser(currentUser, payload.sessionToken);
}

export async function adjustCreditAsSuperAdmin(adminEmail, payload) {
  const admin = await getSessionUser(adminEmail, payload.sessionToken);
  if (!isSuperAdmin(admin)) {
    throw new Error("Only super admins can adjust credits.");
  }

  const portal = collections(await getDb());
  const targetUserId = cleanText(payload.targetUserId || payload.clientId);
  const target = await getUserById(targetUserId);
  if (!target || isSuperAdmin(target) || !targetVisibleInLive(target)) {
    throw new Error("Select a valid user for credit adjustment.");
  }

  const creditType = cleanText(payload.creditType, "money").toLowerCase();
  if (!["money", "post"].includes(creditType)) {
    throw new Error("Select money credit or post credit.");
  }
  const direction = cleanText(payload.direction, "add").toLowerCase() === "deduct" ? "deduct" : "add";
  const creditAmount = roundMoney(payload.amount);
  if (creditAmount <= 0) {
    throw new Error("Credit amount is required.");
  }

  const stamp = now();
  await portal.creditLedger.insertOne({
    id: createId("credit"),
    userId: target.id,
    creditType,
    amount: direction === "deduct" ? -creditAmount : creditAmount,
    source: "manual_adjustment",
    relatedPostId: "",
    relatedContractId: "",
    memo: cleanText(payload.memo),
    referenceLink: cleanText(payload.referenceLink),
    adjustedByUserId: admin.id,
    adjustedByName: admin.name,
    createdAt: stamp,
    updatedAt: stamp,
  });

  return getPortalDataForUser(admin, payload.sessionToken);
}

export async function addManualCreditAsSuperAdmin(adminEmail, payload) {
  return adjustCreditAsSuperAdmin(adminEmail, {
    ...payload,
    targetUserId: payload.targetUserId || payload.clientId,
    creditType: payload.creditType || "money",
    direction: payload.direction || "add",
  });
}

function postTypeForUser(user) {
  if (user?.role === "bidder") {
    return "bidder";
  }
  return "";
}

export async function createPost(email, payload) {
  const currentUser = await getSessionUser(email, payload.sessionToken);
  if (currentUser.status !== "approved") {
    throw new Error("Only approved users can publish posts.");
  }

  const type = postTypeForUser(currentUser);
  if (!type) {
    throw new Error("Only bidders can publish posts.");
  }

  const title = cleanText(payload.title).slice(0, 120);
  const criteria = cleanText(payload.criteria).slice(0, 1200);
  if (!title || !criteria) {
    throw new Error("Post title and criteria are required.");
  }

  const frequency = normalizePaymentFrequency(payload.paymentFrequency);
  const weekday = normalizePaymentWeekday(payload.paymentWeekday);
  const stamp = now();
  const postId = createId("post");
  const portal = collections(await getDb());
  const { postCreditUsed, moneyCreditUsed } = await spendPostingCredit(portal, currentUser, postId, stamp);

  await portal.posts.insertOne({
    id: postId,
    authorId: currentUser.id,
    type,
    title,
    criteria,
    budgetAmount: roundMoney(payload.budgetAmount),
    preferredRate: roundMoney(payload.preferredRate),
    bonusPerInterview: roundMoney(payload.bonusPerInterview),
    paymentFrequency: frequency,
    paymentWeekday: weekday,
    status: "active",
    postCreditUsed,
    moneyCreditUsed,
    createdAt: stamp,
    updatedAt: stamp,
    closedAt: "",
  });

  return getPortalDataForUser(currentUser, payload.sessionToken);
}

export async function updatePostStatus(email, payload) {
  const currentUser = await getSessionUser(email, payload.sessionToken);
  const postId = cleanText(payload.postId);
  const status = cleanText(payload.status).toLowerCase();
  if (!POST_STATUSES.has(status)) {
    throw new Error("Select a valid post status.");
  }

  const portal = collections(await getDb());
  const post = stripMongoId(await portal.posts.findOne({ id: postId }, { projection: { _id: 0 } }));
  if (!post) {
    throw new Error("Post not found.");
  }
  const canCloseBidderPost = isClientRole(currentUser.role) && post.type === "bidder" && status === "closed";
  if (!isSuperAdmin(currentUser) && post.authorId !== currentUser.id && !canCloseBidderPost) {
    throw new Error("You can only manage your own posts or close bidder posts.");
  }

  const stamp = now();
  await portal.posts.updateOne(
    { id: post.id },
    {
      $set: {
        status,
        closedAt: status === "closed" ? post.closedAt || stamp : "",
        updatedAt: stamp,
      },
    }
  );

  return getPortalDataForUser(currentUser, payload.sessionToken);
}

function contractUsersFromPayload(actor, targetUser) {
  if (isClientRole(actor?.role) && isPortalWorker(targetUser)) {
    return { client: actor, worker: targetUser };
  }
  if (isPortalWorker(actor) && isClientRole(targetUser?.role)) {
    return { client: targetUser, worker: actor };
  }
  return { client: null, worker: null };
}

function canManageContract(user, contract) {
  return isSuperAdmin(user) || contract.clientId === user.id || contract.workerId === user.id;
}

async function applyAcceptedContract(portal, contract, worker, stamp) {
  const frequency = normalizePaymentFrequency(contract.paymentFrequency) || "weekly";
  const weekday = normalizePaymentWeekday(contract.paymentWeekday) || "friday";
  const nextPaymentDate = await nextOpenPaymentDate(portal, worker.id, frequency, weekday, contract.startDate || dateToIso(new Date()));

  await portal.users.updateOne(
    { id: worker.id },
    {
      $set: {
        assignedAdminId: contract.clientId,
        ratePerApplication: roundMoney(contract.ratePerApplication),
        bonusPerInterview: roundMoney(contract.bonusPerInterview),
        paymentFrequency: frequency,
        paymentWeekday: weekday,
        paymentSchedule: paymentScheduleLabel(frequency, weekday),
        nextPaymentDate,
        updatedAt: stamp,
      },
    }
  );
}

export async function createContract(email, payload) {
  const currentUser = await getSessionUser(email, payload.sessionToken);
  if (currentUser.status !== "approved") {
    throw new Error("Only approved users can start contracts.");
  }
  if (!isClientRole(currentUser.role) && !isPortalWorker(currentUser)) {
    throw new Error("Only clients and bidders can start contracts.");
  }

  const target = await getUserById(cleanText(payload.targetUserId));
  const { client, worker } = contractUsersFromPayload(currentUser, target);
  if (!client || !worker || !targetVisibleInLive(client) || !targetVisibleInLive(worker)) {
    throw new Error("Select a valid client-bidder pair.");
  }
  if (worker.assignedAdminId && worker.assignedAdminId !== client.id) {
    throw new Error("This bidder is contracted with another client.");
  }

  const title = cleanText(payload.title).slice(0, 120);
  const criteria = cleanText(payload.criteria).slice(0, 1200);
  if (!title || !criteria) {
    throw new Error("Contract title and criteria are required.");
  }

  const frequency = normalizePaymentFrequency(payload.paymentFrequency) || normalizePaymentFrequency(worker.paymentFrequency) || "weekly";
  const weekday = normalizePaymentWeekday(payload.paymentWeekday) || normalizePaymentWeekday(worker.paymentWeekday) || "friday";
  const startDate = parseIsoDate(cleanText(payload.startDate)) ? cleanText(payload.startDate) : dateToIso(new Date());
  const portal = collections(await getDb());
  const existingOpenContract = await portal.contracts.findOne(
    {
      clientId: client.id,
      workerId: worker.id,
      status: { $in: OPEN_CONTRACT_STATUSES },
    },
    { projection: { _id: 1 } }
  );
  if (existingOpenContract) {
    throw new Error("This client and bidder already have an open contract.");
  }

  const stamp = now();
  await portal.contracts.insertOne({
    id: createId("contract"),
    clientId: client.id,
    workerId: worker.id,
    requestedByUserId: currentUser.id,
    title,
    criteria,
    ratePerApplication: roundMoney(payload.ratePerApplication),
    bonusPerInterview: roundMoney(payload.bonusPerInterview),
    paymentFrequency: frequency,
    paymentWeekday: weekday,
    startDate,
    status: "requested",
    sourcePostId: cleanText(payload.sourcePostId),
    acceptedAt: "",
    acceptedByUserId: "",
    rejectedAt: "",
    endedAt: "",
    createdAt: stamp,
    updatedAt: stamp,
  });

  return getPortalDataForUser(currentUser, payload.sessionToken);
}

export async function updateContractStatus(email, payload) {
  const currentUser = await getSessionUser(email, payload.sessionToken);
  const contractId = cleanText(payload.contractId);
  const status = cleanText(payload.status).toLowerCase();
  if (!CONTRACT_STATUSES.has(status) || status === "requested") {
    throw new Error("Select a valid contract action.");
  }

  const portal = collections(await getDb());
  const contract = stripMongoId(await portal.contracts.findOne({ id: contractId }, { projection: { _id: 0 } }));
  if (!contract) {
    throw new Error("Contract not found.");
  }
  if (!canManageContract(currentUser, contract)) {
    throw new Error("You can only manage your own contracts.");
  }

  const worker = await getUserById(contract.workerId);
  const client = await getUserById(contract.clientId);
  if (!worker || !client) {
    throw new Error("Contract members were not found.");
  }

  const stamp = now();
  if (status === "active") {
    if (contract.status !== "requested") {
      throw new Error("Only requested contracts can be accepted.");
    }
    if (!isSuperAdmin(currentUser) && contract.requestedByUserId === currentUser.id) {
      throw new Error("The other member must accept this contract.");
    }
    if (worker.assignedAdminId && worker.assignedAdminId !== client.id) {
      throw new Error("This bidder is contracted with another client.");
    }

    await portal.contracts.updateOne(
      { id: contract.id },
      {
        $set: {
          status: "active",
          acceptedAt: stamp,
          acceptedByUserId: currentUser.id,
          updatedAt: stamp,
        },
      }
    );
    await applyAcceptedContract(portal, contract, worker, stamp);
    const refreshedUser = await getUserById(currentUser.id, { includeSecrets: true });
    return getPortalDataForUser(refreshedUser || currentUser, payload.sessionToken);
  }

  if (status === "rejected") {
    if (contract.status !== "requested") {
      throw new Error("Only requested contracts can be rejected.");
    }
    if (!isSuperAdmin(currentUser) && contract.requestedByUserId === currentUser.id) {
      throw new Error("The other member must reject this contract.");
    }

    await portal.contracts.updateOne(
      { id: contract.id },
      { $set: { status: "rejected", rejectedAt: stamp, updatedAt: stamp } }
    );
    return getPortalDataForUser(currentUser, payload.sessionToken);
  }

  if (status === "ended") {
    if (contract.status !== "active") {
      throw new Error("Only active contracts can be ended.");
    }

    await Promise.all([
      portal.contracts.updateOne(
        { id: contract.id },
        { $set: { status: "ended", endedAt: stamp, updatedAt: stamp } }
      ),
      worker.assignedAdminId === client.id
        ? portal.users.updateOne({ id: worker.id }, { $set: { assignedAdminId: "", updatedAt: stamp } })
        : Promise.resolve(),
    ]);
    const refreshedUser = await getUserById(currentUser.id, { includeSecrets: true });
    return getPortalDataForUser(refreshedUser || currentUser, payload.sessionToken);
  }

  throw new Error("Select a valid contract action.");
}

async function handleCryptomusPayoutWebhook(payload) {
  assertCryptomusPayoutConfigured();

  const providedSign = cleanText(payload.sign);
  const unsignedPayload = { ...payload };
  delete unsignedPayload.sign;
  const expectedSign = cryptomusSign(unsignedPayload, cryptomusPayoutKey());
  if (!providedSign || providedSign !== expectedSign) {
    throw new Error("Invalid Cryptomus webhook signature.");
  }

  const orderId = cleanText(payload.order_id);
  if (!orderId) {
    throw new Error("Cryptomus payout order ID is required.");
  }

  const portal = collections(await getDb());
  const payment = await portal.payments.findOne({ payoutOrderId: orderId }, { projection: { _id: 0 } });
  if (!payment) {
    return { ok: true };
  }

  const payoutStatus = cleanText(payload.status || "process");
  await portal.payments.updateOne(
    { id: payment.id },
    {
      $set: {
        status: paymentStatusFromPayoutStatus(payoutStatus),
        payoutStatus,
        payoutUuid: cleanText(payload.uuid, payment.payoutUuid || ""),
        payoutTxid: cleanText(payload.txid),
        paymentLink: cleanText(payload.txid || payload.uuid || payment.paymentLink || ""),
        payoutCurrency: cleanText(payload.payer_currency || payload.currency || payment.payoutCurrency || ""),
        payoutNetwork: cleanText(payload.network || payment.payoutNetwork || ""),
        payoutError: cleanText(payload.fail_reason),
        rawPayout: payload,
        updatedAt: now(),
      },
    }
  );

  return { ok: true };
}

export async function handleCryptomusWebhook(payload) {
  if (cleanText(payload.type).toLowerCase() === "payout") {
    return handleCryptomusPayoutWebhook(payload);
  }

  assertCryptomusConfigured();

  const providedSign = cleanText(payload.sign);
  const unsignedPayload = { ...payload };
  delete unsignedPayload.sign;
  const expectedSign = cryptomusSign(unsignedPayload);
  if (!providedSign || providedSign !== expectedSign) {
    throw new Error("Invalid Cryptomus webhook signature.");
  }

  const orderId = cleanText(payload.order_id);
  if (!orderId) {
    throw new Error("Cryptomus order ID is required.");
  }

  const portal = collections(await getDb());
  const deposit = await portal.deposits.findOne({ orderId }, { projection: { _id: 0 } });
  if (!deposit) {
    return { ok: true };
  }

  const providerStatus = cleanText(payload.status || payload.payment_status || "check");
  const grossPaid = roundMoney(payload.payment_amount_usd || payload.amount || deposit.amount);
  const feeAmount = escrowFeeFor(grossPaid);
  const creditAmount = roundMoney(grossPaid - feeAmount);
  const isPaid = providerStatus === "paid" || providerStatus === "paid_over";
  const isFailed = ["fail", "cancel", "system_fail", "wrong_amount", "refund_paid"].includes(providerStatus);
  const nextStatus = isPaid ? "paid" : isFailed ? "failed" : "pending";
  const stamp = now();
  const paidDeposit = {
    ...deposit,
    amount: isPaid ? grossPaid : deposit.amount,
    feeAmount: isPaid ? feeAmount : deposit.feeAmount,
    creditAmount: isPaid ? creditAmount : deposit.creditAmount,
  };

  await portal.deposits.updateOne(
    { orderId },
    {
      $set: {
        status: nextStatus,
        providerStatus,
        amount: isPaid ? grossPaid : deposit.amount,
        feeAmount: isPaid ? feeAmount : deposit.feeAmount,
        creditAmount: isPaid ? creditAmount : deposit.creditAmount,
        paymentAmountUsd: grossPaid,
        merchantAmount: roundMoney(payload.merchant_amount),
        txid: cleanText(payload.txid),
        rawProvider: payload,
        paidAt: isPaid && !deposit.paidAt ? stamp : deposit.paidAt || "",
        updatedAt: stamp,
      },
    }
  );

  if (isPaid && deposit.status !== "paid") {
    const client = stripMongoId(
      await portal.users.findOne({ id: deposit.clientId }, { projection: PUBLIC_USER_PROJECTION })
    );
    await createSuperAdminCreditNotification(portal, {
      client,
      deposit: paidDeposit,
      source: "Cryptomus",
    });
  }

  return { ok: true };
}

export async function markNotificationsRead(email, payload) {
  const currentUser = await getSessionUser(email, payload.sessionToken);

  const portal = collections(await getDb());
  const notificationIds = Array.isArray(payload.notificationIds)
    ? payload.notificationIds.map((id) => cleanText(id)).filter(Boolean)
    : [];
  const ownerFilter = isSuperAdmin(currentUser)
    ? { $or: [{ recipientRole: "super_admin" }, { recipientUserId: currentUser.id }] }
    : { recipientUserId: currentUser.id };
  const filter = {
    ...ownerFilter,
    readAt: "",
    ...(notificationIds.length ? { id: { $in: notificationIds } } : {}),
  };

  await portal.notifications.updateMany(filter, { $set: { readAt: now(), updatedAt: now() } });

  return getPortalDataForUser(currentUser, payload.sessionToken);
}

export async function savePaymentMethod(email, payload) {
  const currentUser = await getSessionUser(email, payload.sessionToken);
  if (isSuperAdmin(currentUser) || isClientRole(currentUser.role)) {
    throw new Error("Clients do not need payment methods.");
  }

  const method = cleanText(payload.method);
  const currency = cleanText(payload.currency).toUpperCase();
  const network = cleanText(payload.network).toUpperCase();
  const address = cleanText(payload.address);
  const methodId = cleanText(payload.methodId);
  if (!method || !currency || !network || !address) {
    throw new Error("Payout coin, network, and wallet address are required.");
  }

  const portal = collections(await getDb());
  const stamp = now();

  if (methodId) {
    const existingMethod = stripMongoId(
      await portal.paymentMethods.findOne({ id: methodId, userId: currentUser.id }, { projection: { _id: 0 } })
    );
    if (!existingMethod) {
      throw new Error("Payment method not found.");
    }

    const duplicateMethod = stripMongoId(
      await portal.paymentMethods.findOne(
        { userId: currentUser.id, method, id: { $ne: methodId } },
        { projection: { _id: 0, id: 1 } }
      )
    );
    if (duplicateMethod) {
      throw new Error("You already have this payment method.");
    }

    await portal.paymentMethods.updateMany(
      { userId: currentUser.id },
      { $set: { isPrimary: false, updatedAt: stamp } }
    );
    await portal.paymentMethods.updateOne(
      { id: methodId, userId: currentUser.id },
      {
        $set: {
          method,
          currency,
          network,
          address,
          isPrimary: true,
          updatedAt: stamp,
        },
      }
    );

    return getPortalDataForUser(currentUser, payload.sessionToken);
  }

  await portal.paymentMethods.updateMany(
    { userId: currentUser.id },
    { $set: { isPrimary: false, updatedAt: stamp } }
  );
  await portal.paymentMethods.updateOne(
    { userId: currentUser.id, method },
    {
      $set: {
        address,
        currency,
        network,
        isPrimary: true,
        updatedAt: stamp,
      },
      $setOnInsert: {
        id: createId("method"),
        userId: currentUser.id,
        method,
        createdAt: stamp,
      },
    },
    { upsert: true }
  );

  return getPortalDataForUser(currentUser, payload.sessionToken);
}

export async function saveWorkLog(email, payload) {
  const currentUser = await getSessionUser(email, payload.sessionToken);
  if (currentUser.role !== "bidder" || currentUser.status !== "approved") {
    throw new Error("Only approved bidders can log bidder work.");
  }

  const workDate = cleanText(payload.workDate);
  const sheetLink = cleanText(payload.sheetLink);
  const workLogId = cleanText(payload.workLogId);
  if (!workDate || !sheetLink) {
    throw new Error("Work date and Google Sheet link are required.");
  }

  const portal = collections(await getDb());
  const stamp = now();
  if (workLogId) {
    const existingLog = stripMongoId(
      await portal.workLogs.findOne(
        { id: workLogId, userId: currentUser.id },
        { projection: { _id: 0 } }
      )
    );

    if (!existingLog) {
      throw new Error("Work log not found.");
    }
    if (await paidPaymentCoversDate(portal, currentUser.id, existingLog.workDate)) {
      throw new Error("Paid work logs cannot be edited.");
    }
    if (await paidPaymentCoversDate(portal, currentUser.id, workDate)) {
      throw new Error("This work date has already been paid.");
    }

    const duplicateLog = stripMongoId(
      await portal.workLogs.findOne(
        { userId: currentUser.id, workDate, id: { $ne: workLogId } },
        { projection: { _id: 0 } }
      )
    );
    if (duplicateLog) {
      throw new Error("A work log already exists for this date.");
    }

    await portal.workLogs.updateOne(
      { id: workLogId, userId: currentUser.id },
      {
        $set: {
          workDate,
          sheetLink,
          appliedJobs: Math.round(cleanNumber(payload.appliedJobs)),
          interviewsScheduled: Math.round(cleanNumber(payload.interviewsScheduled)),
          notes: cleanText(payload.notes),
          reviewStatus: "pending",
          reviewNote: "",
          reviewedByUserId: "",
          reviewRequestedByUserId: "",
          reviewedAt: "",
          updatedAt: stamp,
        },
      }
    );
    await notifyAssignedClientForWorkLog(portal, {
      bidder: currentUser,
      workLogId: existingLog.id,
      type: "work_log_updated",
      title: "Work log updated",
      body: `${currentUser.name} updated the work log for ${workDate}. Please review it again.`,
    });

    return getPortalDataForUser(currentUser, payload.sessionToken);
  }

  if (await paidPaymentCoversDate(portal, currentUser.id, workDate)) {
    throw new Error("This work date has already been paid.");
  }

  const existingSameDateLog = stripMongoId(
    await portal.workLogs.findOne(
      { userId: currentUser.id, workDate },
      { projection: { _id: 0, id: 1 } }
    )
  );
  const nextWorkLogId = existingSameDateLog?.id || createId("log");
  await portal.workLogs.updateOne(
    { userId: currentUser.id, workDate },
    {
      $set: {
        sheetLink,
        appliedJobs: Math.round(cleanNumber(payload.appliedJobs)),
        interviewsScheduled: Math.round(cleanNumber(payload.interviewsScheduled)),
        notes: cleanText(payload.notes),
        reviewStatus: "pending",
        reviewNote: "",
        reviewedByUserId: "",
        reviewRequestedByUserId: "",
        reviewedAt: "",
        updatedAt: stamp,
      },
      $setOnInsert: {
        id: nextWorkLogId,
        userId: currentUser.id,
        workDate,
        createdAt: stamp,
      },
    },
    { upsert: true }
  );
  await notifyAssignedClientForWorkLog(portal, {
    bidder: currentUser,
    workLogId: nextWorkLogId,
    type: existingSameDateLog ? "work_log_updated" : "work_log_submitted",
    title: existingSameDateLog ? "Work log updated" : "Work log submitted",
    body: `${currentUser.name} ${existingSameDateLog ? "updated" : "submitted"} the work log for ${workDate}.`,
  });

  return getPortalDataForUser(currentUser, payload.sessionToken);
}

export async function deleteWorkLog(email, payload) {
  const currentUser = await getSessionUser(email, payload.sessionToken);
  if (currentUser.role !== "bidder" || currentUser.status !== "approved") {
    throw new Error("Only approved bidders can delete bidder work.");
  }

  const workLogId = cleanText(payload.workLogId);
  if (!workLogId) {
    throw new Error("Work log is required.");
  }

  const portal = collections(await getDb());
  const existingLog = stripMongoId(
    await portal.workLogs.findOne(
      { id: workLogId, userId: currentUser.id },
      { projection: { _id: 0 } }
    )
  );

  if (!existingLog) {
    throw new Error("Work log not found.");
  }
  if (await paidPaymentCoversDate(portal, currentUser.id, existingLog.workDate)) {
    throw new Error("Paid work logs cannot be deleted.");
  }

  await portal.workLogs.deleteOne({ id: existingLog.id, userId: currentUser.id });

  return getPortalDataForUser(currentUser, payload.sessionToken);
}

export async function reviewWorkLog(email, payload) {
  const currentUser = await getSessionUser(email, payload.sessionToken);
  if (!isClientRole(currentUser.role) || currentUser.status !== "approved") {
    throw new Error("Only approved clients can review work logs.");
  }

  const workLogId = cleanText(payload.workLogId);
  const reviewStatus = cleanWorkLogReviewStatus(payload.reviewStatus);
  const reviewNote = cleanText(payload.reviewNote).slice(0, 800);
  if (!workLogId) {
    throw new Error("Work log is required.");
  }
  if (reviewStatus !== "approved" && reviewStatus !== "changes_requested") {
    throw new Error("Select a valid work log review action.");
  }
  if (reviewStatus === "changes_requested" && !reviewNote) {
    throw new Error("Add a suggestion before requesting edits.");
  }

  const portal = collections(await getDb());
  const workLog = stripMongoId(
    await portal.workLogs.findOne({ id: workLogId }, { projection: { _id: 0 } })
  );
  if (!workLog) {
    throw new Error("Work log not found.");
  }

  const bidder = await getUserById(workLog.userId);
  if (!bidder || !isPortalWorker(bidder) || !targetVisibleInLive(bidder)) {
    throw new Error("Work log bidder was not found.");
  }
  assertCanManagePaymentUser(currentUser, bidder);
  if (await paidPaymentCoversDate(portal, bidder.id, workLog.workDate)) {
    throw new Error("Paid work logs cannot be reviewed.");
  }

  const stamp = now();
  await portal.workLogs.updateOne(
    { id: workLog.id },
    {
      $set: {
        reviewStatus,
        reviewNote: reviewStatus === "changes_requested" ? reviewNote : "",
        reviewedByUserId: currentUser.id,
        reviewRequestedByUserId: reviewStatus === "changes_requested" ? currentUser.id : "",
        reviewedAt: stamp,
        updatedAt: stamp,
      },
    }
  );

  await createUserNotification(portal, {
    recipientUserId: bidder.id,
    type: reviewStatus === "approved" ? "work_log_approved" : "work_log_changes_requested",
    title: reviewStatus === "approved" ? "Work log approved" : "Work log edit requested",
    body:
      reviewStatus === "approved"
        ? `${currentUser.name} approved your work log for ${workLog.workDate}.`
        : `${currentUser.name} requested edits for ${workLog.workDate}: ${reviewNote}`,
    relatedWorkLogId: workLog.id,
    actorUserId: currentUser.id,
  });

  return getPortalDataForUser(currentUser, payload.sessionToken);
}

export async function releasePaymentAsClient(clientEmail, payload) {
  const client = await getSessionUser(clientEmail, payload.sessionToken);
  if (!isClientRole(client.role)) {
    throw new Error("Only clients can release bidder payments.");
  }

  const targetUserId = cleanText(payload.userId);
  const target = await getUserById(targetUserId);
  if (!target || !isPortalWorker(target)) {
    throw new Error("Select a bidder or developer for payment.");
  }
  if (!targetVisibleInLive(target)) {
    throw new Error("Demo accounts cannot be paid in live mode.");
  }
  assertCanManagePaymentUser(client, target);

  const periodStart = cleanText(payload.periodStart);
  const periodEnd = cleanText(payload.periodEnd);
  if (!parseIsoDate(periodStart) || !parseIsoDate(periodEnd) || periodStart > periodEnd) {
    throw new Error("Select a valid payment date range.");
  }

  const portal = collections(await getDb());
  const sourcePaymentId = cleanText(payload.sourcePaymentId);
  const sourcePayment = sourcePaymentId
    ? stripMongoId(await portal.payments.findOne({ id: sourcePaymentId, userId: target.id, status: "scheduled" }, { projection: { _id: 0 } }))
    : null;
  if (sourcePaymentId && !sourcePayment) {
    throw new Error("Select a valid scheduled payment to release.");
  }
  if (sourcePayment && sourcePayment.clientId && sourcePayment.clientId !== client.id) {
    throw new Error("You can only release your own scheduled payments.");
  }
  if (await releasedPaymentOverlapsPeriod(portal, target.id, periodStart, periodEnd, sourcePayment?.id || "")) {
    throw new Error("This date range overlaps an existing released payment.");
  }

  const paymentMethodId = cleanText(payload.paymentMethodId);
  const payoutMethod = stripMongoId(
    await portal.paymentMethods.findOne({ id: paymentMethodId, userId: target.id }, { projection: { _id: 0 } })
  );
  if (!payoutMethod || !payoutMethod.address) {
    throw new Error("Bidder must save a crypto payout wallet first.");
  }

  const payoutCurrency = cleanText(payoutMethod.currency || payoutMethod.method.split(/\s+/)[0]).toUpperCase();
  const payoutNetwork = cleanText(payoutMethod.network || payoutMethod.method.split(/\s+/)[1]).toUpperCase();
  if (!payoutCurrency || !payoutNetwork) {
    throw new Error("Bidder payout coin and network are required.");
  }

  const logs = await portal.workLogs
    .find({ userId: target.id, workDate: { $gte: periodStart, $lte: periodEnd }, reviewStatus: "approved" }, { projection: { _id: 0 } })
    .toArray();
  const calculatedBaseAmount = roundMoney(
    logs.reduce(
      (total, log) =>
        total +
        cleanNumber(log.appliedJobs) * cleanNumber(target.ratePerApplication) +
        cleanNumber(log.interviewsScheduled) * cleanNumber(target.bonusPerInterview),
      0
    )
  );
  const requestedBaseAmount = payload.baseAmount === undefined || payload.baseAmount === ""
    ? null
    : roundMoney(payload.baseAmount);
  if (requestedBaseAmount != null && requestedBaseAmount < 0) {
    throw new Error("Payment release amount is required.");
  }
  if (requestedBaseAmount != null && requestedBaseAmount > calculatedBaseAmount) {
    throw new Error("Only approved work logs can be released.");
  }
  const baseAmount = requestedBaseAmount ?? calculatedBaseAmount;
  const tipAmount = roundMoney(payload.tipAmount);
  const amount = roundMoney(baseAmount + tipAmount);
  if (amount <= 0) {
    throw new Error("Payment release amount is required.");
  }

  const creditBalance = await clientCreditBalance(portal, client.id);
  if (creditBalance < amount) {
    throw new Error("Client does not have enough credits for this payment.");
  }

  const stamp = now();
  const paymentId = sourcePayment?.id || createId("payment");
  const payoutOrderId = `payout_${randomUUID().replace(/-/g, "")}`;
  const callbackUrl = cryptomusCallbackUrl();
  const payoutPayload = {
    amount: amount.toFixed(2),
    currency: CREDIT_CURRENCY,
    to_currency: payoutCurrency,
    network: payoutNetwork,
    order_id: payoutOrderId,
    address: payoutMethod.address,
    is_subtract: true,
    from_currency: "USDT",
    ...(callbackUrl ? { url_callback: callbackUrl } : {}),
  };

  const paymentRecord = {
    userId: target.id,
    clientId: client.id,
    periodStart,
    periodEnd,
    scheduledDate: dateToIso(new Date()),
    amount,
    baseAmount,
    tipAmount,
    creditAmountUsed: amount,
    status: "processing",
    paymentLink: "",
    memo: cleanText(payload.memo),
    payoutOrderId,
    payoutUuid: "",
    payoutStatus: "process",
    payoutCurrency,
    payoutNetwork,
    payoutAddress: payoutMethod.address,
    payoutTxid: "",
    payoutError: "",
    rawPayout: {},
    updatedAt: stamp,
  };
  if (sourcePayment) {
    await portal.payments.updateOne({ id: sourcePayment.id }, { $set: paymentRecord });
  } else {
    await portal.payments.insertOne({
      id: paymentId,
      ...paymentRecord,
      createdAt: stamp,
    });
  }

  try {
    const payout = await createCryptomusPayout(payoutPayload);
    const payoutStatus = cleanText(payout.status || "process");
    await portal.payments.updateOne(
      { id: paymentId },
      {
        $set: {
          status: paymentStatusFromPayoutStatus(payoutStatus),
          paymentLink: cleanText(payout.txid || payout.uuid || ""),
          payoutUuid: cleanText(payout.uuid),
          payoutStatus,
          payoutTxid: cleanText(payout.txid),
          rawPayout: payout,
          updatedAt: now(),
        },
      }
    );
  } catch (error) {
    await portal.payments.updateOne(
      { id: paymentId },
      {
        $set: {
          status: "failed",
          payoutError: error instanceof Error ? error.message : "Cryptomus payout failed.",
          updatedAt: now(),
        },
      }
    );
    throw error;
  }

  const schedule = paymentScheduleFromUser(target);
  const paidCycleDate = sourcePayment?.scheduledDate || target.nextPaymentDate || periodEnd;
  const nextCycleDate = schedule.frequency && schedule.weekday
    ? nextPaymentDateFromSchedule(schedule.frequency, schedule.weekday, paidCycleDate, true)
    : "";
  const nextPaymentDate = schedule.frequency && schedule.weekday
    ? await nextOpenPaymentDate(portal, target.id, schedule.frequency, schedule.weekday, nextCycleDate)
    : periodEnd;

  await portal.users.updateOne({ id: target.id }, { $set: { nextPaymentDate, updatedAt: now() } });

  return getPortalDataForUser(client, payload.sessionToken);
}

export async function addPaymentAsAdmin(adminEmail, payload) {
  const admin = await getSessionUser(adminEmail, payload.sessionToken);
  if (!isSuperAdmin(admin)) {
    throw new Error("Only super admins can add payments.");
  }

  const targetUserId = cleanText(payload.userId);
  const target = await getUserById(targetUserId);
  if (!target || !isPortalWorker(target)) {
    throw new Error("Select a bidder or developer for payment.");
  }
  if (!targetVisibleInLive(target)) {
    throw new Error("Demo accounts cannot be paid in live mode.");
  }
  assertCanManagePaymentUser(admin, target);
  const targetClientId = isClientRole(admin.role) ? admin.id : cleanText(payload.clientId, target.assignedAdminId || "");
  const targetClient = await getUserById(targetClientId);
  if (!targetClient || !isClientRole(targetClient.role) || !targetVisibleInLive(targetClient)) {
    throw new Error("Select a valid client for this payment.");
  }
  if (target.assignedAdminId && target.assignedAdminId !== targetClient.id) {
    throw new Error("This bidder is contracted with another client.");
  }

  const periodStart = cleanText(payload.periodStart);
  const periodEnd = cleanText(payload.periodEnd);
  const scheduledDate = cleanText(payload.scheduledDate);
  const amount = cleanNumber(payload.amount);
  const paymentLink = cleanText(payload.paymentLink) || "Internal credit payment";

  if (!periodStart || !periodEnd || !scheduledDate || amount <= 0) {
    throw new Error("Payment period, scheduled date, and amount are required.");
  }

  const portal = collections(await getDb());
  const creditBalance = await clientCreditBalance(portal, targetClient.id);
  if (creditBalance < amount) {
    throw new Error("Client does not have enough credits for this payment.");
  }
  const stamp = now();

  await portal.payments.insertOne({
    id: createId("payment"),
    userId: target.id,
    clientId: targetClient.id,
    periodStart,
    periodEnd,
    scheduledDate,
    amount,
    creditAmountUsed: amount,
    status: "paid",
    paymentLink,
    memo: cleanText(payload.memo),
    createdAt: stamp,
    updatedAt: stamp,
  });

  const schedule = paymentScheduleFromUser(target);
  const nextPaymentDate = schedule.frequency && schedule.weekday
    ? await nextOpenPaymentDate(portal, target.id, schedule.frequency, schedule.weekday, target.nextPaymentDate || scheduledDate)
    : scheduledDate;

  await portal.users.updateOne({ id: target.id }, { $set: { nextPaymentDate, updatedAt: stamp } });

  return getPortalDataForUser(admin, payload.sessionToken);
}

export async function editPaymentAsAdmin(adminEmail, payload) {
  const admin = await getSessionUser(adminEmail, payload.sessionToken);
  if (!isSuperAdmin(admin)) {
    throw new Error("Only super admins can edit payments.");
  }

  const portal = collections(await getDb());
  const paymentId = cleanText(payload.paymentId);
  const existingPayment = await portal.payments.findOne({ id: paymentId }, { projection: { _id: 0 } });
  if (!existingPayment) {
    throw new Error("Payment record not found.");
  }
  const existingTarget = await getUserById(existingPayment.userId);
  if (existingTarget) {
    assertCanManagePaymentUser(admin, existingTarget);
  }

  const targetUserId = cleanText(payload.userId, existingPayment.userId);
  const target = await getUserById(targetUserId);
  if (!target || !isPortalWorker(target)) {
    throw new Error("Select a bidder or developer for payment.");
  }
  if (!targetVisibleInLive(target)) {
    throw new Error("Demo accounts cannot be paid in live mode.");
  }
  assertCanManagePaymentUser(admin, target);
  const targetClientId = cleanText(payload.clientId, existingPayment.clientId || target.assignedAdminId || "");
  const targetClient = await getUserById(targetClientId);
  if (!targetClient || !isClientRole(targetClient.role) || !targetVisibleInLive(targetClient)) {
    throw new Error("Select a valid client for this payment.");
  }
  if (target.assignedAdminId && target.assignedAdminId !== targetClient.id) {
    throw new Error("This bidder is contracted with another client.");
  }

  const periodStart = cleanText(payload.periodStart);
  const periodEnd = cleanText(payload.periodEnd);
  const scheduledDate = cleanText(payload.scheduledDate);
  const amount = cleanNumber(payload.amount);
  const paymentLink = cleanText(payload.paymentLink) || "Internal credit payment";

  if (!periodStart || !periodEnd || !scheduledDate || amount <= 0) {
    throw new Error("Payment period, scheduled date, and amount are required.");
  }
  const creditBalance = await clientCreditBalance(portal, targetClient.id, { excludePaymentId: existingPayment.id });
  if (creditBalance < amount) {
    throw new Error("Client does not have enough credits for this payment.");
  }

  const stamp = now();
  await portal.payments.updateOne(
    { id: existingPayment.id },
    {
      $set: {
        userId: target.id,
        clientId: targetClient.id,
        periodStart,
        periodEnd,
        scheduledDate,
        amount,
        creditAmountUsed: amount,
        status: "paid",
        paymentLink,
        memo: cleanText(payload.memo),
        updatedAt: stamp,
      },
    }
  );

  const usersToRefresh = new Set([existingPayment.userId, target.id]);
  await Promise.all(
    Array.from(usersToRefresh).map(async (userId) => {
      const user = await getUserById(userId);
      if (!user || isSuperAdmin(user) || isClientRole(user.role)) {
        return;
      }

      const schedule = paymentScheduleFromUser(user);
      const nextPaymentDate = schedule.frequency && schedule.weekday
        ? await nextOpenPaymentDate(portal, user.id, schedule.frequency, schedule.weekday, user.nextPaymentDate || scheduledDate)
        : scheduledDate;
      await portal.users.updateOne({ id: user.id }, { $set: { nextPaymentDate, updatedAt: stamp } });
    })
  );

  return getPortalDataForUser(admin, payload.sessionToken);
}

export async function deletePaymentAsAdmin(adminEmail, payload) {
  const admin = await getSessionUser(adminEmail, payload.sessionToken);
  if (!isSuperAdmin(admin)) {
    throw new Error("Only super admins can delete payments.");
  }

  const portal = collections(await getDb());
  const paymentId = cleanText(payload.paymentId);
  const existingPayment = await portal.payments.findOne({ id: paymentId }, { projection: { _id: 0 } });
  if (!existingPayment) {
    throw new Error("Payment record not found.");
  }

  const target = await getUserById(existingPayment.userId);
  if (target && !targetVisibleInLive(target)) {
    throw new Error("Demo account payments cannot be managed in live mode.");
  }
  if (target) {
    assertCanManagePaymentUser(admin, target);
  }

  await portal.payments.deleteOne({ id: existingPayment.id });

  if (target && !isSuperAdmin(target) && !isClientRole(target.role)) {
    const schedule = paymentScheduleFromUser(target);
    const nextPaymentDate = schedule.frequency && schedule.weekday
      ? await nextOpenPaymentDate(portal, target.id, schedule.frequency, schedule.weekday, existingPayment.scheduledDate)
      : target.nextPaymentDate;
    await portal.users.updateOne({ id: target.id }, { $set: { nextPaymentDate, updatedAt: now() } });
  }

  return getPortalDataForUser(admin, payload.sessionToken);
}

export async function addChatMessage(email, payload) {
  const currentUser = await getSessionUser(email, payload.sessionToken);
  if (currentUser.status !== "approved") {
    throw new Error("Only approved users can send chat messages.");
  }
  if (isSuperAdmin(currentUser)) {
    throw new Error("Super admins can monitor inbox conversations but cannot send direct messages.");
  }

  const body = cleanText(payload.body);
  const attachments = cleanChatAttachments(payload.attachments);
  if (!body && !attachments.length) {
    throw new Error("Message or attachment is required.");
  }

  const portal = collections(await getDb());
  const recipientId = cleanText(payload.recipientId);
  const recipient = await getUserById(recipientId);
  if (!recipient || recipient.id === currentUser.id || recipient.status !== "approved" || !targetVisibleInLive(recipient)) {
    throw new Error("Select a valid inbox recipient.");
  }
  if (isSuperAdmin(recipient)) {
    throw new Error("Inbox messages are only for client-bidder communication.");
  }
  const clientToWorker = isClientRole(currentUser.role) && isPortalWorker(recipient);
  const workerToClient = isPortalWorker(currentUser) && isClientRole(recipient.role);
  if (!clientToWorker && !workerToClient) {
    throw new Error("Inbox messages are only for client-bidder communication.");
  }
  if (recipient.allowDirectMessages === false) {
    throw new Error("This member is not accepting direct messages.");
  }

  const relatedPostId = cleanText(payload.relatedPostId);
  const relatedPost = relatedPostId
    ? stripMongoId(await portal.posts.findOne({ id: relatedPostId }, { projection: { _id: 0 } }))
    : null;
  if (relatedPostId && !relatedPost) {
    throw new Error("Select a valid related post.");
  }
  if (relatedPost && relatedPost.authorId !== currentUser.id && relatedPost.authorId !== recipient.id) {
    throw new Error("Related post must belong to one of the inbox members.");
  }

  const stamp = now();
  await portal.chatMessages.insertOne({
    id: createId("chat"),
    userId: currentUser.id,
    recipientId: recipient.id,
    conversationId: chatConversationId(currentUser.id, recipient.id),
    authorName: currentUser.name,
    authorRole: currentUser.role,
    body: body.slice(0, 1000),
    attachments,
    relatedPostId: relatedPost?.id || "",
    authorTimeZone: cleanText(payload.authorTimeZone).slice(0, 80),
    createdAt: stamp,
    updatedAt: stamp,
    editedAt: "",
    deletedAt: "",
  });

  return getPortalDataForUser(currentUser, payload.sessionToken);
}

export async function editChatMessage(email, payload) {
  const currentUser = await getSessionUser(email, payload.sessionToken);
  if (currentUser.status !== "approved") {
    throw new Error("Only approved users can edit chat messages.");
  }

  const messageId = cleanText(payload.messageId);
  const body = cleanText(payload.body);
  if (!messageId) {
    throw new Error("Message is required.");
  }

  const portal = collections(await getDb());
  const message = stripMongoId(await portal.chatMessages.findOne({ id: messageId }, { projection: { _id: 0 } }));
  if (!message) {
    throw new Error("Message not found.");
  }
  if (message.deletedAt) {
    throw new Error("Deleted messages cannot be edited.");
  }
  if (!canManageChatMessage(currentUser, message)) {
    throw new Error("You cannot edit this message.");
  }
  if (!body && !(message.attachments || []).length) {
    throw new Error("Message cannot be empty.");
  }

  const stamp = now();
  await portal.chatMessages.updateOne(
    { id: message.id },
    {
      $set: {
        body: body.slice(0, 1000),
        editedAt: stamp,
        editedByUserId: currentUser.id,
        updatedAt: stamp,
      },
    }
  );

  return getPortalDataForUser(currentUser, payload.sessionToken);
}

export async function deleteChatMessage(email, payload) {
  const currentUser = await getSessionUser(email, payload.sessionToken);
  if (currentUser.status !== "approved") {
    throw new Error("Only approved users can delete chat messages.");
  }

  const messageId = cleanText(payload.messageId);
  if (!messageId) {
    throw new Error("Message is required.");
  }

  const portal = collections(await getDb());
  const message = stripMongoId(await portal.chatMessages.findOne({ id: messageId }, { projection: { _id: 0 } }));
  if (!message) {
    throw new Error("Message not found.");
  }
  if (!isSuperAdmin(currentUser)) {
    throw new Error("Only super admins can delete inbox messages.");
  }

  const stamp = now();
  await portal.chatMessages.updateOne(
    { id: message.id },
    {
      $set: {
        body: "",
        attachments: [],
        deletedAt: stamp,
        deletedByUserId: currentUser.id,
        updatedAt: stamp,
      },
    }
  );

  return getPortalDataForUser(currentUser, payload.sessionToken);
}

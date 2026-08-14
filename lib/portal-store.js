import { createHash, randomBytes, randomUUID, scrypt as scryptCallback, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";
import { MongoClient } from "mongodb";

const ADMIN_EMAIL = "admin@portal.local";
const DEFAULT_DB_NAME = "bidder_portal";
const DEMO_PASSWORD = "demo1234";
const DEMO_EMAILS = new Set([ADMIN_EMAIL, "maya.bidder@example.com", "pending.bidder@example.com"]);
const CHAT_ATTACHMENT_LIMIT = 3;
const MAX_CHAT_ATTACHMENT_BYTES = 2 * 1024 * 1024;
const MAX_CHAT_ATTACHMENT_DATA_URL_LENGTH = Math.ceil(MAX_CHAT_ATTACHMENT_BYTES * 1.4) + 250;
const BLOCKED_CHAT_ATTACHMENT_TYPES = new Set(["image/svg+xml", "text/html", "application/xhtml+xml"]);
const SESSION_DAYS = 14;
const SESSION_MS = SESSION_DAYS * 24 * 60 * 60 * 1000;
const RESET_TOKEN_MS = 60 * 60 * 1000;
const VERIFY_TOKEN_MS = 24 * 60 * 60 * 1000;
const PUBLIC_USER_PROJECTION = { _id: 0, passwordHash: 0 };
const PAYMENT_FREQUENCIES = new Set(["weekly", "biweekly", "monthly"]);
const PAYMENT_WEEKDAYS = ["monday", "tuesday", "wednesday", "thursday", "friday"];
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

function createId(prefix) {
  return `${prefix}_${randomUUID()}`;
}

function cleanMimeType(value) {
  return cleanText(value, "application/octet-stream").toLowerCase().slice(0, 120) || "application/octet-stream";
}

function cleanPassword(value) {
  return typeof value === "string" ? value : "";
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

function canManageChatMessage(user, message) {
  return user.role === "admin" || message.userId === user.id;
}

async function paidPaymentCoversDate(portal, userId, workDate) {
  return Boolean(
    await portal.payments.findOne(
      {
        userId,
        status: "paid",
        periodStart: { $lte: workDate },
        periodEnd: { $gte: workDate },
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
        status: "paid",
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
  record.passwordSet = Boolean(record.passwordHash);
  record.passwordUpdatedAt = record.passwordUpdatedAt || "";
  record.emailVerifiedAt = record.emailVerifiedAt || "";
  record.emailVerificationSentAt = record.emailVerificationSentAt || "";
  record.passwordResetSentAt = record.passwordResetSentAt || "";
  const schedule = paymentScheduleFromUser(record);
  record.paymentFrequency = schedule.frequency;
  record.paymentWeekday = schedule.weekday;
  record.paymentSchedule = paymentScheduleLabel(schedule.frequency, schedule.weekday) || record.paymentSchedule || "";
  delete record.passwordHash;
  return record;
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
    portal.paymentMethods.createIndex({ userId: 1 }),
    portal.paymentMethods.createIndex({ userId: 1, method: 1 }, { unique: true }),
    portal.workLogs.createIndex({ userId: 1 }),
    portal.workLogs.createIndex({ userId: 1, workDate: 1 }, { unique: true }),
    portal.payments.createIndex({ userId: 1 }),
    portal.payments.createIndex({ scheduledDate: 1 }),
    portal.chatMessages.createIndex({ createdAt: 1 }),
    portal.sessions.createIndex({ tokenHash: 1 }, { unique: true }),
    portal.sessions.createIndex({ userId: 1 }),
    portal.sessions.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 }),
    portal.authTokens.createIndex({ tokenHash: 1 }, { unique: true }),
    portal.authTokens.createIndex({ userId: 1, type: 1 }),
    portal.authTokens.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 }),
    portal.emailEvents.createIndex({ createdAt: -1 }),
  ]);

  if (!isLiveMode()) {
    await seedDemoData(portal);
  }
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
  await portal.users.updateOne({ email: user.email }, { $setOnInsert: user }, { upsert: true });
}

async function seedDemoData(portal) {
  const stamp = now();
  const demoPasswordHash = await hashPassword(DEMO_PASSWORD);

  await Promise.all([
    seedUser(portal, {
      id: "user_admin",
      email: ADMIN_EMAIL,
      name: "Admin Owner",
      role: "admin",
      status: "approved",
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
      id: "user_maya",
      email: "maya.bidder@example.com",
      name: "Maya Bidder",
      role: "bidder",
      status: "approved",
      ratePerApplication: 1.25,
      bonusPerInterview: 12,
      nextPaymentDate: "2026-08-21",
      paymentSchedule: "Weekly on Friday",
      paymentFrequency: "weekly",
      paymentWeekday: "friday",
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
      ratePerApplication: 0,
      bonusPerInterview: 0,
      nextPaymentDate: "",
      paymentSchedule: "",
      paymentFrequency: "",
      paymentWeekday: "",
      passwordHash: demoPasswordHash,
      passwordUpdatedAt: stamp,
      emailVerifiedAt: "",
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
    portal.paymentMethods.updateOne(
      { userId: "user_maya", method: "Wise" },
      {
        $setOnInsert: {
          id: "method_maya_wise",
          userId: "user_maya",
          method: "Wise",
          address: "maya@example.com",
          isPrimary: true,
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
          userId: "user_admin",
          authorName: "Admin Owner",
          authorRole: "admin",
          body: "Welcome. Please log daily sheet links, applied jobs, and scheduled interviews before the payment review.",
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

async function createUser(email, nameInput, role, status, password) {
  const portal = collections(await getDb());
  const stamp = now();
  const passwordHash = await hashPassword(password);
  const user = {
    id: createId("user"),
    email,
    name: cleanText(nameInput) || displayNameFromEmail(email),
    role,
    status,
    ratePerApplication: 0,
    bonusPerInterview: 0,
    nextPaymentDate: "",
    paymentSchedule: "",
    paymentFrequency: "",
    paymentWeekday: "",
    passwordHash,
    passwordUpdatedAt: stamp,
    emailVerifiedAt: "",
    emailVerificationSentAt: "",
    passwordResetSentAt: "",
    createdAt: stamp,
    updatedAt: stamp,
  };

  await portal.users.updateOne({ email }, { $setOnInsert: user }, { upsert: true });
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

async function getSessionUser(emailInput, sessionTokenInput) {
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

async function hasLiveUser(portal) {
  const existingUser = await portal.users.findOne(
    { email: { $nin: Array.from(DEMO_EMAILS) } },
    { projection: { _id: 1 } }
  );
  return Boolean(existingUser);
}

export async function signUp(emailInput, nameInput, passwordInput) {
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

  const firstLiveUser = isLiveMode() && !(await hasLiveUser(portal));
  const user = await createUser(
    email,
    nameInput,
    firstLiveUser ? "admin" : "bidder",
    firstLiveUser ? "approved" : "pending",
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

async function getPortalDataForUser(currentUser, sessionToken = "") {
  const portal = collections(await getDb());
  const safeCurrentUser = publicUser(currentUser);
  const isAdmin = safeCurrentUser.role === "admin";
  const userVisibilityFilter = isLiveMode() ? { email: { $nin: Array.from(DEMO_EMAILS) } } : {};
  const users = isAdmin
    ? stripMongoIds(
        await portal.users
          .find(userVisibilityFilter, { projection: { _id: 0 } })
          .sort({ role: 1, status: 1, name: 1 })
          .toArray()
      ).map(publicUser)
    : [safeCurrentUser];
  const visibleUserIds = users.map((user) => user.id);
  const userFilter = isAdmin ? (isLiveMode() ? { userId: { $in: visibleUserIds } } : {}) : { userId: safeCurrentUser.id };
  const chatUserIds = isLiveMode()
    ? (
        await portal.users
          .find(userVisibilityFilter, { projection: { _id: 0, id: 1 } })
          .toArray()
      ).map((user) => user.id)
    : [];

  const [paymentMethods, workLogs, payments, chatMessages] = await Promise.all([
    portal.paymentMethods.find(userFilter, { projection: { _id: 0 } }).sort({ isPrimary: -1, updatedAt: -1 }).toArray(),
    portal.workLogs.find(userFilter, { projection: { _id: 0 } }).sort({ workDate: -1, createdAt: -1 }).toArray(),
    portal.payments.find(userFilter, { projection: { _id: 0 } }).sort({ scheduledDate: -1, createdAt: -1 }).toArray(),
    portal.chatMessages
      .find(isLiveMode() ? { userId: { $in: chatUserIds } } : {}, { projection: { _id: 0 } })
      .sort({ createdAt: 1 })
      .limit(80)
      .toArray(),
  ]);

  return {
    currentUser: safeCurrentUser,
    sessionToken,
    users,
    paymentMethods: stripMongoIds(paymentMethods),
    workLogs: stripMongoIds(workLogs),
    payments: stripMongoIds(payments),
    chatMessages: stripMongoIds(chatMessages),
  };
}

export async function getPortalData(email, sessionToken) {
  const currentUser = await getSessionUser(email, sessionToken);
  return getPortalDataForUser(currentUser, sessionToken);
}

export async function refreshPortal(email, sessionToken) {
  return getPortalData(email, sessionToken);
}

export async function signIn(emailInput, passwordInput, nameInput) {
  await ensurePortalSchema();
  const email = normalizeEmail(emailInput);
  validateEmail(email);
  assertDemoAccountAllowed(email);

  let user = await getUserByEmail(email, { includeSecrets: true });
  if (!user) {
    if (isLiveMode()) {
      throw new Error("Account not found. Please sign up first.");
    }

    const isAdmin = email === ADMIN_EMAIL;
    user = await createUser(
      email,
      nameInput,
      isAdmin ? "admin" : "bidder",
      isAdmin ? "approved" : "pending",
      cleanPassword(passwordInput)
    );
    user = await getUserByEmail(email, { includeSecrets: true });
  }

  const verifiedUser = await verifyOrSetPassword(user, passwordInput);
  if (isLiveMode() && !verifiedUser.emailVerifiedAt) {
    throw new Error("Verify your email before signing in.");
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
  const sessionToken = await createSession(updatedUser);

  return getPortalDataForUser(updatedUser, sessionToken);
}

export async function requestEmailVerification(email, payload = {}) {
  const currentUser = await getSessionUser(email, payload.sessionToken);
  const portal = collections(await getDb());
  const targetUserId = cleanText(payload.targetUserId, currentUser.id);
  const target = await getUserById(targetUserId, { includeSecrets: true });
  if (!target) {
    throw new Error("User not found.");
  }
  if (currentUser.role !== "admin" && target.id !== currentUser.id) {
    throw new Error("You cannot verify another user's email.");
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
  if (admin.role !== "admin") {
    throw new Error("Only admins can reset user passwords.");
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
  if (admin.role !== "admin") {
    throw new Error("Only admins can manage users.");
  }

  const targetUserId = cleanText(payload.targetUserId);
  const target = await getUserById(targetUserId);
  if (!target) {
    throw new Error("User not found.");
  }
  if (!targetVisibleInLive(target)) {
    throw new Error("Demo accounts cannot be managed in live mode.");
  }

  const role = cleanText(payload.role, target.role);
  const status = cleanText(payload.status, target.status);
  const safeRole = ["admin", "bidder", "developer"].includes(role) ? role : target.role;
  const safeStatus = ["pending", "approved", "paused"].includes(status) ? status : target.status;
  const isAdminRole = safeRole === "admin";
  const portal = collections(await getDb());
  const targetSchedule = paymentScheduleFromUser(target);
  const frequency = normalizePaymentFrequency(payload.paymentFrequency) || targetSchedule.frequency;
  const weekday = normalizePaymentWeekday(payload.paymentWeekday) || targetSchedule.weekday;
  const nextPaymentDate = isAdminRole
    ? ""
    : await nextOpenPaymentDate(portal, target.id, frequency, weekday, cleanText(payload.nextPaymentDate, target.nextPaymentDate));
  const paymentSchedule = isAdminRole
    ? ""
    : paymentScheduleLabel(frequency, weekday) || cleanText(payload.paymentSchedule, target.paymentSchedule);

  await portal.users.updateOne(
    { id: target.id },
    {
      $set: {
        name: cleanText(payload.name, target.name) || target.name,
        role: safeRole,
        status: safeStatus,
        ratePerApplication: isAdminRole ? 0 : cleanNumber(payload.ratePerApplication, target.ratePerApplication),
        bonusPerInterview: isAdminRole ? 0 : cleanNumber(payload.bonusPerInterview, target.bonusPerInterview),
        nextPaymentDate,
        paymentSchedule,
        paymentFrequency: isAdminRole ? "" : frequency,
        paymentWeekday: isAdminRole ? "" : weekday,
        updatedAt: now(),
      },
    }
  );

  return getPortalDataForUser(admin, payload.sessionToken);
}

export async function deleteUserAsAdmin(adminEmail, payload) {
  const admin = await getSessionUser(adminEmail, payload.sessionToken);
  if (admin.role !== "admin") {
    throw new Error("Only admins can remove users.");
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
  if (target.role === "admin") {
    const liveFilter = isLiveMode() ? { email: { $nin: Array.from(DEMO_EMAILS) } } : {};
    const otherAdminCount = await portal.users.countDocuments({ ...liveFilter, role: "admin", id: { $ne: target.id } });
    if (otherAdminCount < 1) {
      throw new Error("At least one admin account must remain.");
    }
  }

  await Promise.all([
    portal.users.deleteOne({ id: target.id }),
    portal.paymentMethods.deleteMany({ userId: target.id }),
    portal.workLogs.deleteMany({ userId: target.id }),
    portal.payments.deleteMany({ userId: target.id }),
    portal.chatMessages.deleteMany({ userId: target.id }),
    portal.sessions.deleteMany({ userId: target.id }),
    portal.authTokens.deleteMany({ userId: target.id }),
  ]);

  return getPortalDataForUser(admin, payload.sessionToken);
}

export async function savePaymentMethod(email, payload) {
  const currentUser = await getSessionUser(email, payload.sessionToken);
  if (currentUser.role === "admin") {
    throw new Error("Admins do not need payment methods.");
  }

  const method = cleanText(payload.method);
  const address = cleanText(payload.address);
  if (!method || !address) {
    throw new Error("Payment method and address are required.");
  }

  const portal = collections(await getDb());
  const stamp = now();

  await portal.paymentMethods.updateMany(
    { userId: currentUser.id },
    { $set: { isPrimary: false, updatedAt: stamp } }
  );
  await portal.paymentMethods.updateOne(
    { userId: currentUser.id, method },
    {
      $set: {
        address,
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
          updatedAt: stamp,
        },
      }
    );

    return getPortalDataForUser(currentUser, payload.sessionToken);
  }

  if (await paidPaymentCoversDate(portal, currentUser.id, workDate)) {
    throw new Error("This work date has already been paid.");
  }

  await portal.workLogs.updateOne(
    { userId: currentUser.id, workDate },
    {
      $set: {
        sheetLink,
        appliedJobs: Math.round(cleanNumber(payload.appliedJobs)),
        interviewsScheduled: Math.round(cleanNumber(payload.interviewsScheduled)),
        notes: cleanText(payload.notes),
        updatedAt: stamp,
      },
      $setOnInsert: {
        id: createId("log"),
        userId: currentUser.id,
        workDate,
        createdAt: stamp,
      },
    },
    { upsert: true }
  );

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

export async function addPaymentAsAdmin(adminEmail, payload) {
  const admin = await getSessionUser(adminEmail, payload.sessionToken);
  if (admin.role !== "admin") {
    throw new Error("Only admins can add payments.");
  }

  const targetUserId = cleanText(payload.userId);
  const target = await getUserById(targetUserId);
  if (!target || target.role === "admin") {
    throw new Error("Select a non-admin user for payment.");
  }
  if (!targetVisibleInLive(target)) {
    throw new Error("Demo accounts cannot be paid in live mode.");
  }

  const periodStart = cleanText(payload.periodStart);
  const periodEnd = cleanText(payload.periodEnd);
  const scheduledDate = cleanText(payload.scheduledDate);
  const amount = cleanNumber(payload.amount);
  const paymentLink = cleanText(payload.paymentLink);

  if (!periodStart || !periodEnd || !scheduledDate || amount <= 0) {
    throw new Error("Payment period, scheduled date, and amount are required.");
  }
  if (!paymentLink) {
    throw new Error("Payment link is required for paid records.");
  }

  const portal = collections(await getDb());
  const stamp = now();

  await portal.payments.insertOne({
    id: createId("payment"),
    userId: target.id,
    periodStart,
    periodEnd,
    scheduledDate,
    amount,
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
  if (admin.role !== "admin") {
    throw new Error("Only admins can edit payments.");
  }

  const portal = collections(await getDb());
  const paymentId = cleanText(payload.paymentId);
  const existingPayment = await portal.payments.findOne({ id: paymentId }, { projection: { _id: 0 } });
  if (!existingPayment) {
    throw new Error("Payment record not found.");
  }

  const targetUserId = cleanText(payload.userId, existingPayment.userId);
  const target = await getUserById(targetUserId);
  if (!target || target.role === "admin") {
    throw new Error("Select a non-admin user for payment.");
  }
  if (!targetVisibleInLive(target)) {
    throw new Error("Demo accounts cannot be paid in live mode.");
  }

  const periodStart = cleanText(payload.periodStart);
  const periodEnd = cleanText(payload.periodEnd);
  const scheduledDate = cleanText(payload.scheduledDate);
  const amount = cleanNumber(payload.amount);
  const paymentLink = cleanText(payload.paymentLink);

  if (!periodStart || !periodEnd || !scheduledDate || amount <= 0) {
    throw new Error("Payment period, scheduled date, and amount are required.");
  }
  if (!paymentLink) {
    throw new Error("Payment link is required for paid records.");
  }

  const stamp = now();
  await portal.payments.updateOne(
    { id: existingPayment.id },
    {
      $set: {
        userId: target.id,
        periodStart,
        periodEnd,
        scheduledDate,
        amount,
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
      if (!user || user.role === "admin") {
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
  if (admin.role !== "admin") {
    throw new Error("Only admins can delete payments.");
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

  await portal.payments.deleteOne({ id: existingPayment.id });

  if (target && target.role !== "admin") {
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

  const body = cleanText(payload.body);
  const attachments = cleanChatAttachments(payload.attachments);
  if (!body && !attachments.length) {
    throw new Error("Message or attachment is required.");
  }

  const portal = collections(await getDb());
  const stamp = now();
  await portal.chatMessages.insertOne({
    id: createId("chat"),
    userId: currentUser.id,
    authorName: currentUser.name,
    authorRole: currentUser.role,
    body: body.slice(0, 1000),
    attachments,
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
  if (!canManageChatMessage(currentUser, message)) {
    throw new Error("You cannot delete this message.");
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

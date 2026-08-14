import { MongoClient } from "mongodb";

const ADMIN_EMAIL = "admin@portal.local";
const DEFAULT_DB_NAME = "bidder_portal";

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
  return `${prefix}_${crypto.randomUUID()}`;
}

function displayNameFromEmail(email) {
  const local = email.split("@")[0] || "User";
  return local
    .split(/[._-]+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
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
  const databaseKey = `${uri}#${dbName}`;

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
  ]);

  await seedDemoData(portal);
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
      createdAt: stamp,
      updatedAt: stamp,
    }),
  ]);

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
          createdAt: stamp,
        },
      },
      { upsert: true }
    ),
  ]);
}

async function getUserByEmail(email) {
  const portal = collections(await getDb());
  return stripMongoId(await portal.users.findOne({ email: normalizeEmail(email) }, { projection: { _id: 0 } }));
}

async function getUserById(userId) {
  const portal = collections(await getDb());
  return stripMongoId(await portal.users.findOne({ id: userId }, { projection: { _id: 0 } }));
}

export async function findOrCreateUser(emailInput, nameInput) {
  await ensurePortalSchema();
  const portal = collections(await getDb());
  const email = normalizeEmail(emailInput);

  if (!email || !email.includes("@")) {
    throw new Error("Enter a valid email address.");
  }

  const existing = await getUserByEmail(email);
  if (existing) {
    return existing;
  }

  const isAdmin = email === ADMIN_EMAIL;
  const stamp = now();
  const user = {
    id: createId("user"),
    email,
    name: cleanText(nameInput) || displayNameFromEmail(email),
    role: isAdmin ? "admin" : "bidder",
    status: isAdmin ? "approved" : "pending",
    ratePerApplication: 0,
    bonusPerInterview: 0,
    nextPaymentDate: "",
    paymentSchedule: "",
    createdAt: stamp,
    updatedAt: stamp,
  };

  await portal.users.updateOne({ email }, { $setOnInsert: user }, { upsert: true });
  return getUserByEmail(email);
}

export async function getPortalData(email) {
  const currentUser = await findOrCreateUser(email);
  const portal = collections(await getDb());
  const isAdmin = currentUser.role === "admin";
  const userFilter = isAdmin ? {} : { userId: currentUser.id };

  const [users, paymentMethods, workLogs, payments, chatMessages] = await Promise.all([
    isAdmin
      ? portal.users.find({}, { projection: { _id: 0 } }).sort({ role: 1, status: 1, name: 1 }).toArray()
      : Promise.resolve([currentUser]),
    portal.paymentMethods.find(userFilter, { projection: { _id: 0 } }).sort({ isPrimary: -1, updatedAt: -1 }).toArray(),
    portal.workLogs.find(userFilter, { projection: { _id: 0 } }).sort({ workDate: -1, createdAt: -1 }).toArray(),
    portal.payments.find(userFilter, { projection: { _id: 0 } }).sort({ scheduledDate: -1, createdAt: -1 }).toArray(),
    portal.chatMessages.find({}, { projection: { _id: 0 } }).sort({ createdAt: 1 }).limit(80).toArray(),
  ]);

  return {
    currentUser,
    users: stripMongoIds(users),
    paymentMethods: stripMongoIds(paymentMethods),
    workLogs: stripMongoIds(workLogs),
    payments: stripMongoIds(payments),
    chatMessages: stripMongoIds(chatMessages),
  };
}

export async function signIn(email, name) {
  const user = await findOrCreateUser(email, name);
  return getPortalData(user.email);
}

export async function updateUserAsAdmin(adminEmail, payload) {
  const admin = await findOrCreateUser(adminEmail);
  if (admin.role !== "admin") {
    throw new Error("Only admins can manage users.");
  }

  const targetUserId = cleanText(payload.targetUserId);
  const target = await getUserById(targetUserId);
  if (!target) {
    throw new Error("User not found.");
  }

  const role = cleanText(payload.role, target.role);
  const status = cleanText(payload.status, target.status);
  const safeRole = ["admin", "bidder", "developer"].includes(role) ? role : target.role;
  const safeStatus = ["pending", "approved", "paused"].includes(status) ? status : target.status;
  const isAdminRole = safeRole === "admin";
  const portal = collections(await getDb());

  await portal.users.updateOne(
    { id: target.id },
    {
      $set: {
        name: cleanText(payload.name, target.name) || target.name,
        role: safeRole,
        status: safeStatus,
        ratePerApplication: isAdminRole ? 0 : cleanNumber(payload.ratePerApplication, target.ratePerApplication),
        bonusPerInterview: isAdminRole ? 0 : cleanNumber(payload.bonusPerInterview, target.bonusPerInterview),
        nextPaymentDate: isAdminRole ? "" : cleanText(payload.nextPaymentDate, target.nextPaymentDate),
        paymentSchedule: isAdminRole ? "" : cleanText(payload.paymentSchedule, target.paymentSchedule),
        updatedAt: now(),
      },
    }
  );

  return getPortalData(admin.email);
}

export async function savePaymentMethod(email, payload) {
  const currentUser = await findOrCreateUser(email);
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

  return getPortalData(currentUser.email);
}

export async function saveWorkLog(email, payload) {
  const currentUser = await findOrCreateUser(email);
  if (currentUser.role !== "bidder" || currentUser.status !== "approved") {
    throw new Error("Only approved bidders can log bidder work.");
  }

  const workDate = cleanText(payload.workDate);
  const sheetLink = cleanText(payload.sheetLink);
  if (!workDate || !sheetLink) {
    throw new Error("Work date and Google Sheet link are required.");
  }

  const portal = collections(await getDb());
  const stamp = now();

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

  return getPortalData(currentUser.email);
}

export async function addPaymentAsAdmin(adminEmail, payload) {
  const admin = await findOrCreateUser(adminEmail);
  if (admin.role !== "admin") {
    throw new Error("Only admins can add payments.");
  }

  const targetUserId = cleanText(payload.userId);
  const target = await getUserById(targetUserId);
  if (!target || target.role === "admin") {
    throw new Error("Select a non-admin user for payment.");
  }

  const periodStart = cleanText(payload.periodStart);
  const periodEnd = cleanText(payload.periodEnd);
  const scheduledDate = cleanText(payload.scheduledDate);
  const amount = cleanNumber(payload.amount);
  const statusInput = cleanText(payload.status, "scheduled");
  const status = statusInput === "paid" ? "paid" : "scheduled";

  if (!periodStart || !periodEnd || !scheduledDate || amount <= 0) {
    throw new Error("Payment period, scheduled date, and amount are required.");
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
    status,
    paymentLink: cleanText(payload.paymentLink),
    memo: cleanText(payload.memo),
    createdAt: stamp,
    updatedAt: stamp,
  });

  await portal.users.updateOne({ id: target.id }, { $set: { nextPaymentDate: scheduledDate, updatedAt: stamp } });

  return getPortalData(admin.email);
}

export async function addChatMessage(email, payload) {
  const currentUser = await findOrCreateUser(email);
  if (currentUser.status !== "approved") {
    throw new Error("Only approved users can send chat messages.");
  }

  const body = cleanText(payload.body);
  if (!body) {
    throw new Error("Message cannot be empty.");
  }

  const portal = collections(await getDb());
  await portal.chatMessages.insertOne({
    id: createId("chat"),
    userId: currentUser.id,
    authorName: currentUser.name,
    authorRole: currentUser.role,
    body: body.slice(0, 1000),
    createdAt: now(),
  });

  return getPortalData(currentUser.email);
}

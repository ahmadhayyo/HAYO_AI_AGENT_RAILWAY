import { db } from "@workspace/db";
import {
  users, conversations, messages, uploadedFiles,
  subscriptionPlans, subscriptions, usageRecords, apiKeys, integrations, subscriptionCodes,
  type User, type InsertUser, type Conversation, type InsertConversation,
  type MessageRow, type InsertMessage, type UploadedFile, type InsertUploadedFile,
  type SubscriptionPlan, type InsertSubscriptionPlan, type Subscription, type InsertSubscription,
  type ApiKey, type InsertApiKey, type UsageRecord, type Integration,
} from "@workspace/db/schema";
import { eq, desc, and, sql, gte, lte, count, isNotNull, gt } from "drizzle-orm";
import { createHash, randomBytes } from "crypto";
import { hashPassword, verifyPassword, isLegacyHash, OWNER_EMAIL, isOwnerEmail } from "./auth";

export type { User, Conversation, MessageRow, UploadedFile, SubscriptionPlan, Subscription, ApiKey, UsageRecord, Integration };

// Guard function to ensure database is available
function ensureDb() {
  if (!db) {
    throw new Error("[Database] Database is not available. Make sure DATABASE_URL is set.");
  }
  return db;
}

// ==================== Users ====================
export async function upsertUser(user: InsertUser): Promise<void> {
  const database = ensureDb();
  const now = new Date();
  await database.insert(users).values({ ...user, updatedAt: now, lastSignedIn: now })
    .onConflictDoUpdate({
      target: users.openId,
      set: {
        name: user.name,
        email: user.email,
        lastSignedIn: now,
        updatedAt: now,
        ...(user.role ? { role: user.role } : {}),
      },
    });
}

// OWNER_EMAIL is defined in ./auth (env-overridable, single source of truth).

export async function createUser(data: { name: string; email: string; password: string }): Promise<User> {
  const normalizedEmail = data.email.toLowerCase().trim();
  const existing = await db.select().from(users).where(sql`lower(${users.email}) = ${normalizedEmail}`).limit(1);
  if (existing[0]) throw new Error("البريد الإلكتروني مسجل مسبقاً");

  const openId = `local_${randomBytes(16).toString("hex")}`;
  const passwordHash = hashPassword(data.password);
  const isOwner = normalizedEmail === OWNER_EMAIL.toLowerCase();
  const isFirstUser = (await db.select({ c: count() }).from(users))[0]?.c === 0;

  const result = await db.insert(users).values({
    openId,
    name: data.name,
    email: normalizedEmail,
    passwordHash,
    loginMethod: "password",
    role: (isOwner || isFirstUser) ? "admin" : "user",
    lastSignedIn: new Date(),
  }).returning();

  // Ensure owner always has admin role (in case DB was reset)
  if (isOwner && result[0]?.role !== "admin") {
    await db.update(users).set({ role: "admin" }).where(eq(users.id, result[0].id));
    result[0].role = "admin";
  }

  return result[0];
}

export async function loginUser(email: string, password: string): Promise<User> {
  const normalizedEmail = email.toLowerCase().trim();
  // Fetch ALL rows for this email. There can legitimately be duplicates (e.g. an
  // account created via password + one seeded/created by another path); without
  // an explicit choice, `LIMIT 1` returns an arbitrary row, which is why the
  // owner sometimes logged into the admin account and sometimes a "free" one.
  const rows = await db.select().from(users).where(sql`lower(${users.email}) = ${normalizedEmail}`);
  if (rows.length === 0) throw new Error("البريد الإلكتروني أو كلمة المرور غير صحيحة");

  // Authenticate against whichever duplicate actually holds the correct password.
  const matched = rows.find((u: User) => u.passwordHash && verifyPassword(password, u.passwordHash));
  if (!matched) throw new Error("البريد الإلكتروني أو كلمة المرور غير صحيحة");

  // Resolve the account to log into. For the OWNER email we always collapse onto
  // ONE canonical owner account (an existing admin row, else the oldest) and
  // guarantee it is admin — so the owner can never land on a duplicate free
  // account regardless of which row their password matched.
  let account = matched;
  if (isOwnerEmail(normalizedEmail)) {
    account = rows.find((u: User) => u.role === "admin") ?? [...rows].sort((a: User, b: User) => a.id - b.id)[0];
    if (account.role !== "admin") {
      await db.update(users).set({ role: "admin", updatedAt: new Date() }).where(eq(users.id, account.id));
      account.role = "admin";
    }
  }

  // Transparently upgrade the legacy sha256 hash on the row that verified.
  if (isLegacyHash(matched.passwordHash)) {
    await db.update(users).set({ passwordHash: hashPassword(password), updatedAt: new Date() }).where(eq(users.id, matched.id));
  }
  await db.update(users).set({ lastSignedIn: new Date(), updatedAt: new Date() }).where(eq(users.id, account.id));
  return account;
}

export async function getUserById(id: number): Promise<User | undefined> {
  const result = await db.select().from(users).where(eq(users.id, id)).limit(1);
  return result[0];
}

export async function getAllUsers(): Promise<User[]> {
  return db.select().from(users).orderBy(desc(users.createdAt));
}

// ==================== Conversations ====================
export async function createConversation(data: InsertConversation): Promise<number> {
  const result = await db.insert(conversations).values(data).returning({ id: conversations.id });
  return result[0].id;
}

export async function getUserConversations(userId: number): Promise<Conversation[]> {
  return db.select().from(conversations).where(eq(conversations.userId, userId)).orderBy(desc(conversations.updatedAt));
}

export async function getConversation(id: number, userId: number): Promise<Conversation | undefined> {
  const result = await db.select().from(conversations)
    .where(and(eq(conversations.id, id), eq(conversations.userId, userId))).limit(1);
  return result[0];
}

export async function updateConversationTitle(id: number, userId: number, title: string): Promise<void> {
  // Scope by userId so a user can only rename their OWN conversations (prevents IDOR).
  await db.update(conversations).set({ title, updatedAt: new Date() })
    .where(and(eq(conversations.id, id), eq(conversations.userId, userId)));
}

export async function deleteConversation(id: number, userId: number): Promise<void> {
  // Verify ownership before deleting anything (prevents IDOR deletion of others' data).
  const owned = await db.select({ id: conversations.id }).from(conversations)
    .where(and(eq(conversations.id, id), eq(conversations.userId, userId))).limit(1);
  if (!owned[0]) return;
  await db.delete(messages).where(eq(messages.conversationId, id));
  await db.delete(conversations).where(and(eq(conversations.id, id), eq(conversations.userId, userId)));
}

// ==================== Messages ====================
export async function addMessage(data: InsertMessage): Promise<number> {
  const result = await db.insert(messages).values(data).returning({ id: messages.id });
  await db.update(conversations).set({ updatedAt: new Date() }).where(eq(conversations.id, data.conversationId));
  return result[0].id;
}

export async function getConversationMessages(conversationId: number): Promise<MessageRow[]> {
  return db.select().from(messages)
    .where(eq(messages.conversationId, conversationId))
    .orderBy(messages.createdAt);
}

// ==================== Files ====================
export async function saveUploadedFile(data: InsertUploadedFile): Promise<number> {
  const result = await db.insert(uploadedFiles).values(data).returning({ id: uploadedFiles.id });
  return result[0].id;
}

export async function getUserFiles(userId: number): Promise<UploadedFile[]> {
  return db.select().from(uploadedFiles)
    .where(eq(uploadedFiles.userId, userId))
    .orderBy(desc(uploadedFiles.createdAt));
}

export async function getFileById(id: number): Promise<UploadedFile | undefined> {
  const result = await db.select().from(uploadedFiles).where(eq(uploadedFiles.id, id)).limit(1);
  return result[0];
}

export async function deleteFile(id: number, userId: number): Promise<void> {
  await db.delete(uploadedFiles)
    .where(and(eq(uploadedFiles.id, id), eq(uploadedFiles.userId, userId)));
}

// ==================== Plans ====================
export async function getActivePlans(): Promise<SubscriptionPlan[]> {
  return db.select().from(subscriptionPlans)
    .where(eq(subscriptionPlans.isActive, true))
    .orderBy(subscriptionPlans.sortOrder);
}

export async function getPlanById(id: number): Promise<SubscriptionPlan | undefined> {
  const result = await db.select().from(subscriptionPlans).where(eq(subscriptionPlans.id, id)).limit(1);
  return result[0];
}

export async function seedDefaultPlans(): Promise<void> {
  if (!db) {
    console.warn("[Seed] Database not available — skipping default plans seed");
    return;
  }

  try {
    const existing = await db.select({ c: count() }).from(subscriptionPlans);
  if ((existing[0]?.c ?? 0) > 0) {
    // Update existing plans with accurate pricing and limits (investment tiers).
    // Prices are in cents. Credit allotments / daily caps are tuned so the
    // effective $/1000-credits declines with tier (volume discount) while
    // staying above the blended provider cost basis.
    await db.update(subscriptionPlans).set({
      displayName: "تجريبي",
      description: "تجربة مجانية — 3 أيام",
      priceMonthly: 0, priceYearly: 0,
      monthlyCredits: 60, dailyCreditLimit: 20,
      dailyMessageLimit: 20, monthlyMessageLimit: 60,
      allowedModels: "haiku",
      maxAgentPipelines: 1, maxWarRoomBattles: 1,
      maxFileUploadMB: 5,
      canUseSandbox: false, canUseWebSearch: false, canUseImageGen: false, canUseFileCreation: false,
      canUseReverse: false, canUseAppBuilder: false, canUseCodeAgent: false, canUseTrading: false, canUseOsint: false,
      prioritySupport: false,
    }).where(eq(subscriptionPlans.name, "free"));

    await db.update(subscriptionPlans).set({
      displayName: "المبتدئ",
      description: "للاستخدام الشخصي والطلاب",
      priceMonthly: 1200, priceYearly: 12000,
      monthlyCredits: 700, dailyCreditLimit: 50,
      dailyMessageLimit: 50, monthlyMessageLimit: 700,
      allowedModels: "haiku,sonnet",
      maxAgentPipelines: 5, maxWarRoomBattles: 5,
      maxFileUploadMB: 20,
      canUseSandbox: false, canUseWebSearch: true, canUseImageGen: false, canUseFileCreation: true,
      canUseReverse: false, canUseAppBuilder: false, canUseCodeAgent: false, canUseTrading: false, canUseOsint: false,
      prioritySupport: false,
    }).where(eq(subscriptionPlans.name, "starter"));

    await db.update(subscriptionPlans).set({
      displayName: "الاحترافي",
      description: "للمحترفين والمستقلين",
      priceMonthly: 3900, priceYearly: 39000,
      monthlyCredits: 2500, dailyCreditLimit: 150,
      dailyMessageLimit: 150, monthlyMessageLimit: 2500,
      allowedModels: "haiku,sonnet,opus",
      maxAgentPipelines: 40, maxWarRoomBattles: 40,
      maxFileUploadMB: 75,
      canUseSandbox: true, canUseWebSearch: true, canUseImageGen: true, canUseFileCreation: true,
      canUseReverse: true, canUseAppBuilder: true, canUseCodeAgent: true, canUseTrading: false, canUseOsint: false,
      prioritySupport: false,
    }).where(eq(subscriptionPlans.name, "pro"));

    await db.update(subscriptionPlans).set({
      displayName: "الأعمال",
      description: "للشركات والفرق الكبيرة",
      priceMonthly: 9900, priceYearly: 99000,
      monthlyCredits: 7000, dailyCreditLimit: 400,
      dailyMessageLimit: 500, monthlyMessageLimit: 10000,
      allowedModels: "haiku,sonnet,opus",
      maxAgentPipelines: 200, maxWarRoomBattles: -1,
      maxFileUploadMB: 200,
      canUseSandbox: true, canUseWebSearch: true, canUseImageGen: true, canUseFileCreation: true,
      canUseReverse: true, canUseAppBuilder: true, canUseCodeAgent: true, canUseTrading: true, canUseOsint: true,
      prioritySupport: true,
    }).where(eq(subscriptionPlans.name, "business"));

    return;
  }

  await db.insert(subscriptionPlans).values([
    {
      name: "free",
      displayName: "تجريبي",
      description: "تجربة مجانية — 3 أيام",
      priceMonthly: 0, priceYearly: 0,
      monthlyCredits: 60, dailyCreditLimit: 20,
      dailyMessageLimit: 20, monthlyMessageLimit: 60,
      allowedModels: "haiku",
      maxAgentPipelines: 1, maxWarRoomBattles: 1,
      maxFileUploadMB: 5, canUseSandbox: false, canUseWebSearch: false, canUseImageGen: false, canUseFileCreation: false,
      canUseReverse: false, canUseAppBuilder: false, canUseCodeAgent: false, canUseTrading: false, canUseOsint: false,
      sortOrder: 0,
    },
    {
      name: "starter",
      displayName: "المبتدئ",
      description: "للاستخدام الشخصي والطلاب",
      priceMonthly: 1200, priceYearly: 12000,
      monthlyCredits: 700, dailyCreditLimit: 50,
      dailyMessageLimit: 50, monthlyMessageLimit: 700,
      allowedModels: "haiku,sonnet",
      maxAgentPipelines: 5, maxWarRoomBattles: 5,
      maxFileUploadMB: 20, canUseSandbox: false, canUseWebSearch: true, canUseImageGen: false, canUseFileCreation: true,
      canUseReverse: false, canUseAppBuilder: false, canUseCodeAgent: false, canUseTrading: false, canUseOsint: false,
      sortOrder: 1,
    },
    {
      name: "pro",
      displayName: "الاحترافي",
      description: "للمحترفين والمستقلين",
      priceMonthly: 3900, priceYearly: 39000,
      monthlyCredits: 2500, dailyCreditLimit: 150,
      dailyMessageLimit: 150, monthlyMessageLimit: 2500,
      allowedModels: "haiku,sonnet,opus",
      maxAgentPipelines: 40, maxWarRoomBattles: 40,
      maxFileUploadMB: 75, canUseSandbox: true, canUseWebSearch: true, canUseImageGen: true, canUseFileCreation: true,
      canUseReverse: true, canUseAppBuilder: true, canUseCodeAgent: true, canUseTrading: false, canUseOsint: false,
      sortOrder: 2,
    },
    {
      name: "business",
      displayName: "الأعمال",
      description: "للشركات والفرق الكبيرة",
      priceMonthly: 9900, priceYearly: 99000,
      monthlyCredits: 7000, dailyCreditLimit: 400,
      dailyMessageLimit: 500, monthlyMessageLimit: 10000,
      allowedModels: "haiku,sonnet,opus",
      maxAgentPipelines: 200, maxWarRoomBattles: -1,
      maxFileUploadMB: 200, canUseSandbox: true, canUseWebSearch: true, canUseImageGen: true, canUseFileCreation: true,
      canUseReverse: true, canUseAppBuilder: true, canUseCodeAgent: true, canUseTrading: true, canUseOsint: true,
      prioritySupport: true,
      sortOrder: 3,
    },
  ]);
  console.log("[DB] Default plans seeded");
  } catch (err: any) {
    console.warn("[Seed] Failed to seed plans (tables may not exist yet):", err.message);
  }
}

// ==================== Owner Account Seed ====================
const OWNER_PASSWORD_ENV = process.env.OWNER_PASSWORD;

export async function seedOwnerAccount(): Promise<void> {
  if (!db) {
    console.warn("[Seed] Database not available — skipping owner account seed");
    return;
  }

  try {
    const ownerEmailLower = OWNER_EMAIL.toLowerCase();
    const existing = await db.select().from(users).where(sql`lower(${users.email}) = ${ownerEmailLower}`).limit(1);
    if (existing.length > 0) {
      // Ensure owner always has admin role
      if (existing[0].role !== "admin") {
        await db.update(users).set({ role: "admin", updatedAt: new Date() }).where(eq(users.id, existing[0].id));
        console.log("[DB] Owner role restored to admin");
      }
      return;
    }
    // Create owner account on first startup.
    // The owner password must come from the OWNER_PASSWORD env var — it is NEVER
    // hard-coded (a hard-coded password committed to the repo is a full account
    // takeover). If it is not set we skip seeding; the owner can simply register
    // through the normal sign-up flow (OWNER_EMAIL is auto-granted admin role).
    if (!OWNER_PASSWORD_ENV || OWNER_PASSWORD_ENV.trim().length === 0) {
      console.warn(
        "[DB] OWNER_PASSWORD not set — skipping owner seed. " +
          "Register with the owner email to get the admin account, or set OWNER_PASSWORD.",
      );
      return;
    }
    const ownerPassword = OWNER_PASSWORD_ENV;
    const openId = `local_${randomBytes(16).toString("hex")}`;
    await db.insert(users).values({
      openId,
      name: "مالك المنصة",
      email: OWNER_EMAIL,
      passwordHash: hashPassword(ownerPassword),
      loginMethod: "password",
      role: "admin",
      lastSignedIn: new Date(),
    });
    console.log("[DB] Owner account seeded successfully");
  } catch (err: any) {
    console.warn("[DB] Owner seed warning:", err.message);
  }
}

// ==================== Subscriptions ====================
export async function getUserActiveSubscription(userId: number): Promise<Subscription | undefined> {
  const now = new Date();
  const result = await db.select().from(subscriptions)
    .where(and(
      eq(subscriptions.userId, userId),
      eq(subscriptions.status, "active"),
      gte(subscriptions.endDate, now),
    ))
    .orderBy(desc(subscriptions.startDate))
    .limit(1);
  return result[0];
}

export async function createSubscription(data: InsertSubscription): Promise<number> {
  const result = await db.insert(subscriptions).values(data).returning({ id: subscriptions.id });
  return result[0].id;
}

/**
 * SINGLE SOURCE OF TRUTH for a user's active plan.
 *
 * Historically the platform had two disconnected mechanisms:
 *   1. `subscriptions` table  — written by admin (manual activation after payment)
 *   2. `subscriptionCodes`    — written by code redemption + Stripe checkout
 * …but enforcement only ever read mechanism #2, so an admin-activated paying
 * subscriber silently fell back to the free plan. This helper reads BOTH (no
 * feature removed) and returns the effective plan, with the `subscriptions`
 * table taking precedence, then an active code, then the free plan.
 */
export async function getEffectivePlan(
  userId: number,
): Promise<{ plan: SubscriptionPlan; source: "subscription" | "code" | "free" }> {
  const now = new Date();

  // (0) Owner / admin ALWAYS get the top (unlimited) plan — never fall back to
  // "free". This keeps the owner's plan consistent everywhere (account page,
  // credit checks, middleware) regardless of whether a subscription row exists.
  const ownerRows = await db.select().from(users).where(eq(users.id, userId)).limit(1);
  const u = ownerRows[0];
  if (u && (u.role === "admin" || isOwnerEmail(u.email))) {
    const topRows = await db.select().from(subscriptionPlans).orderBy(desc(subscriptionPlans.sortOrder)).limit(1);
    if (topRows[0]) return { plan: topRows[0], source: "subscription" };
  }

  // (1) Admin / payment-activated subscription (authoritative).
  const subRows = await db
    .select({ plan: subscriptionPlans })
    .from(subscriptions)
    .innerJoin(subscriptionPlans, eq(subscriptions.planId, subscriptionPlans.id))
    .where(and(
      eq(subscriptions.userId, userId),
      eq(subscriptions.status, "active"),
      gte(subscriptions.endDate, now),
    ))
    .orderBy(desc(subscriptions.endDate))
    .limit(1);
  if (subRows[0]?.plan) return { plan: subRows[0].plan, source: "subscription" };

  // (2) Active redeemed code / Stripe-issued code.
  const codeRows = await db
    .select({ plan: subscriptionPlans })
    .from(subscriptionCodes)
    .innerJoin(subscriptionPlans, eq(subscriptionCodes.planId, subscriptionPlans.id))
    .where(and(
      eq(subscriptionCodes.usedBy, userId),
      isNotNull(subscriptionCodes.usedAt),
      gt(subscriptionCodes.expiresAt, now),
    ))
    .orderBy(desc(subscriptionCodes.expiresAt))
    .limit(1);
  if (codeRows[0]?.plan) return { plan: codeRows[0].plan, source: "code" };

  // (3) Fall back to the free plan.
  const freeRows = await db
    .select().from(subscriptionPlans)
    .where(eq(subscriptionPlans.name, "free"))
    .limit(1);
  return { plan: freeRows[0], source: "free" };
}

// ==================== Usage ====================
export async function getOrCreateDailyUsage(userId: number): Promise<UsageRecord> {
  const today = new Date().toISOString().split("T")[0];
  const existing = await db.select().from(usageRecords)
    .where(and(eq(usageRecords.userId, userId), eq(usageRecords.date, today))).limit(1);
  if (existing[0]) return existing[0];

  const result = await db.insert(usageRecords)
    .values({ userId, date: today, messageCount: 0, tokenCount: 0 })
    .returning();
  return result[0];
}

export async function incrementUsage(userId: number, tokens: number = 0): Promise<void> {
  const today = new Date().toISOString().split("T")[0];
  await db.update(usageRecords).set({
    messageCount: sql`${usageRecords.messageCount} + 1`,
    tokenCount: sql`${usageRecords.tokenCount} + ${tokens}`,
    updatedAt: new Date(),
  }).where(and(eq(usageRecords.userId, userId), eq(usageRecords.date, today)));
}

// ── تكلفة كل عملية بالنقاط ──
export const CREDIT_COSTS: Record<string, number> = {
  // دردشة
  "chat":               2,
  // وكيل الكود
  "agent_pipeline":     30,
  "agent_chat":         2,
  "agent_fix":          3,
  "agent_fixAll":       10,
  // غرفة المعارك
  "war_room":           10,
  // بيئة التطوير BYOC
  "byoc_analyze":       3,
  // الأعمال المكتبية
  "pptx_generate":      8,
  "report_generate":    8,
  "office_tool":        2,
  "excel_process":      3,
  "file_convert":       0,
  "doc_chat":           3,
  "smart_template":     3,
  // الاتصالات
  "telegram_msg":       1,
  // الهندسة العكسية
  "reverse_decompile":  5,
  "reverse_analyze":    3,
  "reverse_edit_session": 10,
  "reverse_ai_modify":  3,
  "reverse_ai_search":  2,
  "reverse_rebuild":    5,
  "reverse_clone":      15,
  // منشئ التطبيقات
  "app_generate":       10,
  "app_build":          15,
  "app_review":         5,
  "app_desktop":        8,
  // EA Factory
  "ea_analyze":         10,
  "ea_generate":        15,
  "ea_fix":             5,
  // الدراسات
  "study_generate":     15,
  "study_followup":     3,
  // مصنع البرومبت
  "prompt_generate":    5,
  "prompt_refine":      3,
  "prompt_test":        3,
  // التداول
  "trading_analyze":    5,
  "trading_autosignal": 8,
  "trading_execute":    2,
};

// ── فحص الرصيد قبل العملية ──
export async function checkCredits(
  userId: number,
  operation: string,
  userPlan?: { dailyCreditLimit: number },
  userRole?: string
): Promise<{ allowed: boolean; remaining: number; cost: number; message?: string }> {
  const cost = CREDIT_COSTS[operation] ?? 1;
  if (cost === 0) return { allowed: true, remaining: 999, cost: 0 };

  // المسؤول (admin) لديه نقاط غير محدودة
  if (userRole === "admin") {
    return { allowed: true, remaining: 9999, cost };
  }

  // تحقق من دور المستخدم من قاعدة البيانات إن لم يُعطَ
  const userRecord = await db.select({ role: users.role }).from(users).where(eq(users.id, userId)).limit(1);
  if (userRecord[0]?.role === "admin") {
    return { allowed: true, remaining: 9999, cost };
  }

  const usage = await getOrCreateDailyUsage(userId);
  const todayCredits = usage.creditsUsed ?? 0;

  // احصل على الحد من الـ plan إذا لم يُعطَ — عبر المصدر الموحّد (اشتراك + كود).
  let dailyLimit = userPlan?.dailyCreditLimit ?? 50;
  if (!userPlan) {
    const effective = await getEffectivePlan(userId);
    dailyLimit = effective.plan?.dailyCreditLimit ?? 50;
  }

  const realLimit = dailyLimit === -1 ? Infinity : dailyLimit;
  if (todayCredits + cost > realLimit) {
    return {
      allowed: false,
      remaining: Math.max(0, realLimit === Infinity ? 9999 : realLimit - todayCredits),
      cost,
      message: `وصلت إلى حد النقاط اليومي (${realLimit} نقطة). يُجدد رصيدك غداً أو قم بالترقية.`,
    };
  }
  return { allowed: true, remaining: realLimit === Infinity ? 9999 : realLimit - todayCredits - cost, cost };
}

// ── خصم النقاط بعد العملية ──
export async function deductCredits(userId: number, operation: string): Promise<void> {
  const cost = CREDIT_COSTS[operation] ?? 1;
  if (cost === 0) return;
  const today = new Date().toISOString().split("T")[0];
  await db.update(usageRecords).set({
    creditsUsed: sql`${usageRecords.creditsUsed} + ${cost}`,
    messageCount: sql`${usageRecords.messageCount} + 1`,
    updatedAt: new Date(),
  }).where(and(eq(usageRecords.userId, userId), eq(usageRecords.date, today)));
}

// ==================== Admin Stats ====================
export async function getAdminStats() {
  const [totalUsers, totalConversations, totalMessages, recentUsers] = await Promise.all([
    db.select({ c: count() }).from(users),
    db.select({ c: count() }).from(conversations),
    db.select({ c: count() }).from(messages),
    db.select().from(users).orderBy(desc(users.createdAt)).limit(5),
  ]);

  return {
    totalUsers: totalUsers[0]?.c ?? 0,
    totalConversations: totalConversations[0]?.c ?? 0,
    totalMessages: totalMessages[0]?.c ?? 0,
    recentUsers,
  };
}

// ==================== Integrations ====================
export async function getUserIntegrations(userId: number): Promise<Integration[]> {
  return db.select().from(integrations).where(eq(integrations.userId, userId));
}

export async function connectIntegration(data: { userId: number; provider: string; accessToken: string; metadata?: Record<string, unknown> }): Promise<void> {
  await db.insert(integrations).values({
    userId: data.userId,
    provider: data.provider,
    accessToken: data.accessToken,
    metadata: data.metadata,
    isActive: true,
  }).onConflictDoUpdate({
    target: [integrations.userId, integrations.provider],
    set: {
      accessToken: data.accessToken,
      metadata: data.metadata,
      isActive: true,
      updatedAt: new Date(),
    },
  });
}

export async function disconnectIntegration(userId: number, provider: string): Promise<void> {
  await db.update(integrations)
    .set({ isActive: false, updatedAt: new Date() })
    .where(and(eq(integrations.userId, userId), eq(integrations.provider, provider)));
}

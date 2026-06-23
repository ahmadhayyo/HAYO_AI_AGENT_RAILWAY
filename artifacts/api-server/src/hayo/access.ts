/**
 * Access control helpers for tRPC procedures.
 *
 * Two concerns, both with an automatic admin/owner bypass:
 *   - assertFeature: is this plan tier allowed to use the feature at all?
 *   - assertCredits: does the user have enough daily credits? (also deducts)
 *
 * Keeping these in one place means every paid feature enforces limits the same
 * way, instead of the previous state where only war_room checked credits.
 */
import { TRPCError } from "@trpc/server";
import { checkCredits, deductCredits, getEffectivePlan } from "./db";

export type PlanFeatureGate =
  | "canUseReverse"
  | "canUseAppBuilder"
  | "canUseCodeAgent"
  | "canUseTrading"
  | "canUseOsint"
  | "canUseSandbox"
  | "canUseWebSearch"
  | "canUseImageGen"
  | "canUseFileCreation";

export const GATE_LABEL_AR: Record<PlanFeatureGate, string> = {
  canUseReverse: "الهندسة العكسية",
  canUseAppBuilder: "منشئ التطبيقات",
  canUseCodeAgent: "وكيل الكود",
  canUseTrading: "التداول الحقيقي",
  canUseOsint: "أدوات OSINT",
  canUseSandbox: "البيئة التطويرية",
  canUseWebSearch: "بحث الويب",
  canUseImageGen: "توليد الصور",
  canUseFileCreation: "إنشاء الملفات",
};

type Principal = { id: number; role: string };

/** Throw FORBIDDEN unless the user's effective plan unlocks `gate` (admins bypass). */
export async function assertFeature(user: Principal, gate: PlanFeatureGate): Promise<void> {
  if (user.role === "admin") return;
  const { plan } = await getEffectivePlan(user.id);
  if (!plan || !(plan as Record<string, unknown>)[gate]) {
    throw new TRPCError({
      code: "FORBIDDEN",
      message: `ميزة "${GATE_LABEL_AR[gate]}" متاحة في خطة أعلى. يرجى الترقية للوصول إليها.`,
    });
  }
}

/**
 * Throw FORBIDDEN if the user is out of daily credits for `operation`, otherwise
 * deduct its cost. Admins bypass entirely. Call this at the START of an expensive
 * mutation so the work is only done when the user can pay for it.
 */
export async function assertCredits(user: Principal, operation: string): Promise<void> {
  if (user.role === "admin") return;
  const check = await checkCredits(user.id, operation, undefined, user.role);
  if (!check.allowed) {
    throw new TRPCError({ code: "FORBIDDEN", message: check.message || "وصلت إلى حد النقاط اليومي. يرجى الترقية." });
  }
  await deductCredits(user.id, operation);
}

import { initTRPC, TRPCError } from "@trpc/server";
import superjson from "superjson";
import type { Request, Response } from "express";
import type { User } from "@workspace/db/schema";
import { assertFeature, type PlanFeatureGate } from "./access";

export type HayoContext = {
  req: Request;
  res: Response;
  user: User | null;
};

const t = initTRPC.context<HayoContext>().create({
  transformer: superjson,
});

export const router = t.router;
export const publicProcedure = t.procedure;

const UNAUTHED_ERR_MSG = "Please login (10001)";

export const protectedProcedure = t.procedure.use(({ ctx, next }) => {
  if (!ctx.user) {
    throw new TRPCError({ code: "UNAUTHORIZED", message: UNAUTHED_ERR_MSG });
  }
  return next({ ctx: { ...ctx, user: ctx.user } });
});

export const adminProcedure = protectedProcedure.use(({ ctx, next }) => {
  if (ctx.user.role !== "admin") {
    throw new TRPCError({ code: "FORBIDDEN", message: "صلاحيات المدير مطلوبة" });
  }
  return next({ ctx });
});

/**
 * A protected procedure that also requires the user's plan to unlock `gate`
 * (admins bypass inside assertFeature). Use for entire tier-locked sub-routers.
 */
export const featureProcedure = (gate: PlanFeatureGate) =>
  protectedProcedure.use(async ({ ctx, next }) => {
    await assertFeature(ctx.user, gate);
    return next({ ctx });
  });

export const tradingProcedure = featureProcedure("canUseTrading");
export const osintProcedure = featureProcedure("canUseOsint");
export const appBuilderProcedure = featureProcedure("canUseAppBuilder");

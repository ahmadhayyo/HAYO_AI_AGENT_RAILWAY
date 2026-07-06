import { Router, type IRouter } from "express";
import healthRouter from "./health";
import chatStreamRouter from "./chat-stream";
import officeRouter from "./office";
import studiesRouter from "./studies";
import promptFactoryRouter from "./prompt-factory";
import reverseRouter from "./reverse";
import telegramRouter from "./telegram";
import extractArchiveRouter from "./extract-archive";
import agentRouter from "./agent";
import pentestRouter from "./pentest";
import { requireAuth, requireFeature, requireAdmin } from "../middlewares/requireAuth";

const router: IRouter = Router();

// ── Public routes ────────────────────────────────────────────────
// health: liveness probe. chat-stream: performs its own auth internally.
// telegram: inbound webhooks (verified by Telegram secret token, not a session).
router.use(healthRouter);
router.use(chatStreamRouter);
router.use(telegramRouter);
// Dynamic-agent ingestion: authenticated by a pairing token in the path, not a cookie.
router.use(pentestRouter);

// ── Authenticated feature routes ─────────────────────────────────
// These power expensive tools (LLM calls, decompilation, builds) and must not
// be reachable anonymously.
// office / studies / prompt-factory: available to all signed-in tiers (credit-metered).
router.use(requireAuth, officeRouter);
router.use(requireAuth, studiesRouter);
router.use(requireAuth, promptFactoryRouter);
router.use(requireAuth, extractArchiveRouter);
// reverse engineering: higher-tier feature → gated by plan flag.
router.use("/reverse", requireAuth, requireFeature("canUseReverse"), reverseRouter);
// Executive self-modifying agent (/api/agent/*): writes the platform's own
// source and runs shell commands — OWNER ONLY, never a subscriber feature.
// (The user-facing code agent uses the trpc `agent.*` router, not these routes.)
router.use(requireAuth, requireAdmin, agentRouter);
export default router;

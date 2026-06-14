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
import { requireAuth } from "../middlewares/requireAuth";

const router: IRouter = Router();

// ── Public routes ────────────────────────────────────────────────
// health: liveness probe. chat-stream: performs its own auth internally.
// telegram: inbound webhooks (verified by Telegram secret token, not a session).
router.use(healthRouter);
router.use(chatStreamRouter);
router.use(telegramRouter);

// ── Authenticated feature routes ─────────────────────────────────
// These power expensive tools (LLM calls, decompilation, builds) and must not
// be reachable anonymously.
router.use(requireAuth, officeRouter);
router.use(requireAuth, studiesRouter);
router.use(requireAuth, promptFactoryRouter);
router.use("/reverse", requireAuth, reverseRouter);
router.use(requireAuth, extractArchiveRouter);
router.use(requireAuth, agentRouter);
export default router;

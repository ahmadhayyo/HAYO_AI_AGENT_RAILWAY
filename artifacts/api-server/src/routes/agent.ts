/**
 * Agent Route — SSE streaming for the autonomous AI coding agent
 *
 * POST /api/agent/stream
 *   Body: { command: string, history?: {role,content}[], sessionId?: string }
 *   Returns: text/event-stream with AgentStreamEvent JSON lines
 *
 * POST /api/agent/execute
 *   Body: { command: string, history?: {role,content}[], autoExecute?: boolean }
 *   Returns: JSON AgentResponse (single-shot, non-streaming)
 */
import { Router } from "express";
import {
  executeAgentCommand,
  executeAgentCommandStreaming,
  type AgentStreamEvent,
} from "../hayo/services/ai-agent.js";

const router = Router();

// ─── Helper: write one SSE event ─────────────────────────────────────────────
function sseWrite(res: any, event: string, data: unknown): void {
  res.write(`event: ${event}\n`);
  res.write(`data: ${JSON.stringify(data)}\n\n`);
}

// ─── POST /api/agent/stream — SSE streaming agentic execution ───────────────
router.post("/agent/stream", async (req, res) => {
  const { command, history = [], sessionId } = req.body || {};

  if (!command || typeof command !== "string") {
    return res.status(400).json({ error: "command is required" });
  }

  // SSE headers
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");
  res.flushHeaders();

  // Keep-alive ping every 15 s so Railway / nginx don't close the connection
  const pingInterval = setInterval(() => {
    try { res.write(": ping\n\n"); } catch { /* ignore */ }
  }, 15_000);

  try {
    const stream = executeAgentCommandStreaming(command, history);

    for await (const event of stream) {
      sseWrite(res, "agent_event", event);
    }

    sseWrite(res, "agent_done", { success: true });
  } catch (err: any) {
    sseWrite(res, "agent_error", {
      type: "error",
      node: "system",
      content: `Server error: ${err?.message || String(err)}`,
    });
  } finally {
    clearInterval(pingInterval);
    res.end();
  }
});

// ─── POST /api/agent/execute — single-shot (non-streaming) ──────────────────
router.post("/agent/execute", async (req, res) => {
  const { command, history = [], autoExecute = false } = req.body || {};

  if (!command || typeof command !== "string") {
    return res.status(400).json({ error: "command is required" });
  }

  try {
    const result = await executeAgentCommand(command, history, autoExecute);
    res.json({ success: true, ...result });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err?.message || String(err) });
  }
});

export default router;

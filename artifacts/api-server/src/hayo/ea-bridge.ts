/**
 * MT4 EXECUTION BRIDGE
 *
 * Forex signals the Telegram bot sends (entry / SL / TP1-3) are queued here;
 * the "HAYO_Bridge_EA" Expert Advisor running in the owner's MT4 polls this
 * endpoint every few seconds, executes new signals and reports the result,
 * which is forwarded to Telegram.
 *
 *   GET /api/ea/signals?token=..&after=<id>&acct=..&bal=..&demo=0|1&broker=..
 *       → text, one record per line (easy to parse in MQL4):
 *         OK|<enabled 0/1>|<server unix time>
 *         S|<id>|<pair>|<BUY/SELL>|<entry>|<sl>|<tp1>|<tp2>|<tp3>|<created unix>|<expires unix>|<source>
 *   GET /api/ea/report?token=..&id=..&status=filled|rejected|closed&ticket=..&price=..&lots=..&msg=..
 *
 * Auth: a random token kept in botSettings ("eaBridge"), shown to the owner
 * by the Telegram /ea command. The queue lives in memory (signals are only
 * valid for minutes); ids are millisecond timestamps so they keep increasing
 * across restarts and the EA's "after" cursor stays valid.
 */
import crypto from "node:crypto";
import { Router, type Request, type Response } from "express";
import { loadBotSetting, saveBotSetting } from "./db";

export interface EaSignal {
  id: number; pair: string; dir: "BUY" | "SELL";
  entry: number; sl: number; tp1: number; tp2: number; tp3: number;
  createdAt: number; expiresAt: number; source: string;
}
export interface EaSettings {
  token: string; enabled: boolean;
  lastSeen?: { at: number; acct: string; bal: string; demo: boolean; broker: string };
}

const QUEUE_MAX = 200;
const SIGNAL_TTL_MS = 10 * 60_000;
const queue: EaSignal[] = [];
let lastId = 0;
let settings: EaSettings | null = null;
let notifier: ((text: string) => void) | null = null;

/** Telegram hook for execution reports (registered by the trading bot). */
export function setEaNotifier(fn: (text: string) => void): void { notifier = fn; }

export async function getEaSettings(): Promise<EaSettings> {
  if (settings) return settings;
  const saved = await loadBotSetting<EaSettings>("eaBridge");
  settings = saved && typeof saved.token === "string" && saved.token.length >= 32
    ? saved
    : { token: crypto.randomBytes(20).toString("hex"), enabled: false };
  if (!saved) await saveBotSetting("eaBridge", settings);
  return settings;
}
export async function updateEaSettings(patch: Partial<EaSettings>): Promise<EaSettings> {
  const s = { ...(await getEaSettings()), ...patch };
  settings = s;
  await saveBotSetting("eaBridge", s);
  return s;
}
export async function regenerateEaToken(): Promise<EaSettings> {
  return updateEaSettings({ token: crypto.randomBytes(20).toString("hex") });
}

/**
 * Take-profit levels in multiples of the stop distance (R), shared with the
 * Telegram message. 0.75/1.25/2 instead of 1/2/3: on the bot's forex signals
 * (OANDA 2019, 6 instruments, spread included) the expectancy is the same
 * (-0.06R vs -0.07R per trade) but targets are reached more often
 * (win rate 55% vs 48%); TP3 at 3R was reached only 23% of the time.
 */
export const TP_R = [0.75, 1.25, 2] as const;

/**
 * Queue a forex signal for MT4 with TP1/2/3 at TP_R (as in the Telegram
 * message). Ignored while the bridge is off or the levels are bad.
 */
export async function enqueueEaSignal(sig: { pair: string; dir: "BUY" | "SELL"; entry: number; sl: number; source: string }): Promise<EaSignal | null> {
  const s = await getEaSettings();
  if (!s.enabled) return null;
  const { pair, dir, entry, sl } = sig;
  const r = Math.abs(entry - sl);
  if (!(entry > 0) || !(r > 0) || !isFinite(r) || (dir === "BUY" ? sl >= entry : sl <= entry)) return null;
  const k = dir === "BUY" ? 1 : -1;
  const now = Date.now();
  const id = Math.max(now, lastId + 1);
  lastId = id;
  const e: EaSignal = {
    id, pair, dir, entry, sl, tp1: entry + k * TP_R[0] * r, tp2: entry + k * TP_R[1] * r, tp3: entry + k * TP_R[2] * r,
    createdAt: now, expiresAt: now + SIGNAL_TTL_MS, source: sig.source.replace(/[|\r\n]/g, " ").slice(0, 40),
  };
  queue.push(e);
  while (queue.length > QUEUE_MAX) queue.shift();
  console.log(`[EA] queued #${id} ${pair} ${dir} entry ${entry} sl ${sl}`);
  return e;
}

/** Pending (not expired) signals newer than `after`. */
export function pendingEaSignals(after: number, now = Date.now()): EaSignal[] {
  return queue.filter(q => q.id > after && q.expiresAt > now);
}

function tokenOk(given: unknown, expected: string): boolean {
  if (typeof given !== "string" || given.length !== expected.length) return false;
  return crypto.timingSafeEqual(Buffer.from(given), Buffer.from(expected));
}
const num = (x: number) => (Number.isFinite(x) ? String(Number(x.toPrecision(10))) : "0");
const clean = (v: unknown, max = 60) => String(v ?? "").replace(/[<>&|\r\n]/g, " ").trim().slice(0, max);

export function formatSignals(enabled: boolean, list: EaSignal[], now = Date.now()): string {
  const lines = [`OK|${enabled ? 1 : 0}|${Math.floor(now / 1000)}`];
  for (const q of list) {
    lines.push(["S", q.id, q.pair, q.dir, num(q.entry), num(q.sl), num(q.tp1), num(q.tp2), num(q.tp3),
      Math.floor(q.createdAt / 1000), Math.floor(q.expiresAt / 1000), q.source].join("|"));
  }
  return lines.join("\n") + "\n";
}

export function eaRouter(): Router {
  const r = Router();
  r.get("/signals", async (req: Request, res: Response) => {
    const s = await getEaSettings();
    if (!tokenOk(req.query.token, s.token)) { res.status(401).type("text/plain").send("ERR|bad token\n"); return; }
    const prevSeen = s.lastSeen?.at ?? 0;
    s.lastSeen = { at: Date.now(), acct: clean(req.query.acct, 20), bal: clean(req.query.bal, 20), demo: req.query.demo === "1", broker: clean(req.query.broker, 40) };
    // first contact after a pause → tell the owner the EA is online
    if (Date.now() - prevSeen > 5 * 60_000) {
      await saveBotSetting("eaBridge", s);
      notifier?.(`🔌 <b>MT4 متصل</b>\nالحساب <code>${s.lastSeen.acct}</code> ${s.lastSeen.demo ? "(تجريبي)" : "(<b>حقيقي</b>)"} — ${s.lastSeen.broker}\nالرصيد: <code>${s.lastSeen.bal}</code>\nالتنفيذ التلقائي: ${s.enabled ? "✅ مفعّل" : "⏸️ متوقف (/ea للتفعيل)"}`);
    }
    const after = Number(req.query.after) || 0;
    res.type("text/plain").send(formatSignals(s.enabled, s.enabled ? pendingEaSignals(after) : []));
  });
  r.get("/report", async (req: Request, res: Response) => {
    const s = await getEaSettings();
    if (!tokenOk(req.query.token, s.token)) { res.status(401).type("text/plain").send("ERR|bad token\n"); return; }
    const id = Number(req.query.id) || 0;
    const sig = queue.find(q => q.id === id);
    const status = clean(req.query.status, 12);
    const label = sig ? `${sig.pair} ${sig.dir === "BUY" ? "🟢 شراء" : "🔴 بيع"}` : `#${id}`;
    const ticket = clean(req.query.ticket, 20), price = clean(req.query.price, 20), lots = clean(req.query.lots, 12), msg = clean(req.query.msg, 120);
    console.log(`[EA] report #${id} ${status} ticket=${ticket} price=${price} lots=${lots} ${msg}`);
    if (status === "filled") notifier?.(`🤖 <b>MT4 — نُفذت الصفقة</b>\n${label}\n📦 ${lots} لوت @ <code>${price}</code>\n🎫 تذكرة ${ticket}${msg ? `\n<i>${msg}</i>` : ""}`);
    else if (status === "rejected") notifier?.(`⚠️ <b>MT4 — لم تُنفذ</b>\n${label}\nالسبب: ${msg || "غير معروف"}`);
    else if (status === "closed") notifier?.(`🏁 <b>MT4 — أُغلقت</b>\n${label} 🎫 ${ticket}\n${msg}`);
    res.type("text/plain").send("OK\n");
  });
  return r;
}

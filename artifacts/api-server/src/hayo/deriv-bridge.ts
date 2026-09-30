/**
 * DERIV EXECUTION BRIDGE — binary (Rise/Fall) signals executed automatically
 * on Deriv the moment the bot sends them (entry timing is where the edge is:
 * one candle late costs 1-3 points of hit rate, see research notes).
 *
 * Official API: WebSocket wss://ws.derivws.com/websockets/v3?app_id=<id>
 *   authorize → contracts_for (allowed Rise/Fall durations) → buy
 *   → at expiry proposal_open_contract (won / lost, profit) → Telegram.
 * The API token (scope "Trade", created by the owner in Deriv) is stored
 * encrypted in botSettings ("derivBridge"). Real accounts are refused unless
 * the owner allows them explicitly. Off by default.
 */
import { loadBotSetting, saveBotSetting } from "./db";
import { encryptCred, decryptCred } from "./services/trading-bridge";

const APP_ID = process.env.DERIV_APP_ID || "1089";
const WS_URL = process.env.DERIV_WS_URL || `wss://ws.derivws.com/websockets/v3?app_id=${APP_ID}`;

export interface DerivStats { n: number; win: number; loss: number; pnl: number }
export interface DerivSettings {
  tokenEnc: string | null;
  enabled: boolean;
  stake: number;
  allowReal: boolean;
  source: "convergence" | "all";      // which binary signals are executed
  stats: DerivStats;
}
export interface DerivAccount { loginid: string; isVirtual: boolean; balance: number; currency: string }

let settings: DerivSettings | null = null;
let notifier: ((text: string) => void) | null = null;
export function setDerivNotifier(fn: (text: string) => void): void { notifier = fn; }

export async function getDerivSettings(): Promise<DerivSettings> {
  if (settings) return settings;
  const saved = await loadBotSetting<DerivSettings>("derivBridge");
  settings = {
    tokenEnc: saved?.tokenEnc ?? null, enabled: saved?.enabled ?? false, stake: saved?.stake ?? 10,
    allowReal: saved?.allowReal ?? false, source: saved?.source ?? "convergence",
    stats: saved?.stats ?? { n: 0, win: 0, loss: 0, pnl: 0 },
  };
  return settings;
}
export async function updateDerivSettings(patch: Partial<DerivSettings>): Promise<DerivSettings> {
  const s = { ...(await getDerivSettings()), ...patch };
  settings = s;
  await saveBotSetting("derivBridge", s);
  return s;
}
export async function setDerivToken(token: string | null): Promise<void> {
  await updateDerivSettings({ tokenEnc: token ? encryptCred(token) : null });
}

// ── minimal request/response client over one WebSocket ─────────────────
type Call = (req: Record<string, unknown>, timeoutMs?: number) => Promise<any>;
async function wsCtor(): Promise<any> {
  const g: any = (globalThis as any).WebSocket;
  if (typeof g === "function") return g;
  // Node < 22 has no global WebSocket; "ws" is bundled (no type declarations installed)
  // @ts-ignore
  const mod: any = await import("ws");
  return mod.default ?? mod.WebSocket ?? mod;
}
async function withDeriv<T>(token: string, fn: (call: Call, acct: DerivAccount) => Promise<T>): Promise<T> {
  const WS = await wsCtor();
  const ws = new WS(WS_URL);
  const pending = new Map<number, { resolve: (v: any) => void; reject: (e: Error) => void; timer: any }>();
  let seq = 0;
  await new Promise<void>((resolve, reject) => {
    const t = setTimeout(() => reject(new Error("Deriv: connection timeout")), 8000);
    ws.onopen = () => { clearTimeout(t); resolve(); };
    ws.onerror = (e: any) => { clearTimeout(t); reject(new Error(`Deriv: connection failed ${e?.message ?? ""}`.trim())); };
  });
  ws.onmessage = (ev: any) => {
    let d: any;
    try { d = JSON.parse(typeof ev.data === "string" ? ev.data : ev.data.toString()); } catch { return; }
    const p = pending.get(d.req_id);
    if (!p) return;
    pending.delete(d.req_id); clearTimeout(p.timer);
    if (d.error) p.reject(new Error(d.error.message || d.error.code || "Deriv error"));
    else p.resolve(d);
  };
  const call: Call = (req, timeoutMs = 10000) => new Promise((resolve, reject) => {
    const req_id = ++seq;
    const timer = setTimeout(() => { pending.delete(req_id); reject(new Error("Deriv: request timeout")); }, timeoutMs);
    pending.set(req_id, { resolve, reject, timer });
    ws.send(JSON.stringify({ ...req, req_id }));
  });
  try {
    const a = (await call({ authorize: token })).authorize;
    const acct: DerivAccount = { loginid: a.loginid, isVirtual: !!a.is_virtual, balance: Number(a.balance), currency: a.currency || "USD" };
    return await fn(call, acct);
  } finally {
    for (const p of pending.values()) clearTimeout(p.timer);
    try { ws.close(); } catch { /* ignore */ }
  }
}

async function token(): Promise<string | null> {
  const s = await getDerivSettings();
  return decryptCred(s.tokenEnc);
}
export async function derivAccount(): Promise<DerivAccount> {
  const t = await token();
  if (!t) throw new Error("لا يوجد توكن Deriv — أرسل /deriv <التوكن>");
  return withDeriv(t, async (_c, acct) => acct);
}

/** Deriv symbol for a bot pair (forex + metals only). */
export function derivSymbol(pair: string): string | null {
  return /^[A-Z]{6}$/.test(pair) && !/^(BTC|ETH)/.test(pair) ? `frx${pair}` : null;
}
/** "15m" → 15, "1h" → 60, "1d" → 1440, ticks/seconds → null. */
export function durationMinutes(d: string): number | null {
  const m = /^(\d+)([smhd])$/.exec(String(d || ""));
  if (!m) return null;
  const n = Number(m[1]);
  return m[2] === "m" ? n : m[2] === "h" ? n * 60 : m[2] === "d" ? n * 1440 : m[2] === "s" ? n / 60 : null;
}
/** Allowed intraday Rise/Fall minutes for a symbol, from contracts_for. */
export function riseFallRange(available: any[]): { min: number; max: number } | null {
  const rows = (available || []).filter((a: any) => a.contract_type === "CALL" && a.barrier_category === "euro_atm" && a.expiry_type === "intraday");
  let min = Infinity, max = 0;
  for (const r of rows) {
    const lo = durationMinutes(r.min_contract_duration), hi = durationMinutes(r.max_contract_duration);
    if (lo !== null) min = Math.min(min, Math.max(1, Math.ceil(lo)));
    if (hi !== null) max = Math.max(max, Math.floor(hi));
  }
  return isFinite(min) && max >= min ? { min, max } : null;
}

const fmtMoney = (x: number, cur: string) => `${x >= 0 ? "+" : ""}${x.toFixed(2)} ${cur}`;

/**
 * Execute one binary signal on Deriv (fire-and-forget from the bot).
 * `minutes` = the signal's expiry (candles × timeframe).
 */
export async function executeDerivSignal(sig: { pair: string; dir: "BUY" | "SELL"; minutes: number; origin: "convergence" | "auto"; label: string }): Promise<void> {
  const s = await getDerivSettings();
  if (!s.enabled) return;
  if (s.source === "convergence" && sig.origin !== "convergence") return;
  const t = decryptCred(s.tokenEnc);
  if (!t) { notifier?.("⚠️ <b>Deriv</b>: التنفيذ مفعّل لكن لا يوجد توكن — أرسل <code>/deriv التوكن</code>"); return; }
  const symbol = derivSymbol(sig.pair);
  const side = sig.dir === "BUY" ? "🟢 CALL" : "🔴 PUT";
  if (!symbol) { notifier?.(`⚠️ <b>Deriv — لم تُنفذ</b>\n${sig.label}: الزوج غير متاح في Deriv`); return; }
  const t0 = Date.now();
  try {
    const res = await withDeriv(t, async (call, acct) => {
      if (!acct.isVirtual && !s.allowReal) throw new Error("حساب حقيقي — التنفيذ عليه معطّل (فعّله بـ /deriv real on على مسؤوليتك)");
      const cf = await call({ contracts_for: symbol, currency: acct.currency, product_type: "basic" });
      const range = riseFallRange(cf.contracts_for?.available);
      if (!range) throw new Error("عقود Rise/Fall غير متاحة لهذا الزوج الآن (السوق مغلق؟)");
      const minutes = Math.min(range.max, Math.max(range.min, Math.round(sig.minutes)));
      const stake = Math.max(0.35, Math.round(s.stake * 100) / 100);
      const buy = (await call({
        buy: 1, price: stake,
        parameters: { amount: stake, basis: "stake", contract_type: sig.dir === "BUY" ? "CALL" : "PUT", currency: acct.currency, duration: minutes, duration_unit: "m", symbol },
      })).buy;
      return { acct, minutes, stake, buy };
    });
    const adj = res.minutes !== Math.round(sig.minutes) ? ` <i>(أقل مدة مسموحة في Deriv: ${res.minutes} د بدل ${Math.round(sig.minutes)})</i>` : "";
    notifier?.(`🎰 <b>Deriv — نُفذت الصفقة</b> ${res.acct.isVirtual ? "(تجريبي)" : "(<b>حقيقي</b>)"}\n${sig.label} ${side}\n💵 ${res.stake} ${res.acct.currency} → عائد محتمل ${Number(res.buy.payout).toFixed(2)}\n⌛ ${res.minutes} دقيقة${adj}\n⚡ التنفيذ خلال ${((Date.now() - t0) / 1000).toFixed(1)} ث — عقد ${res.buy.contract_id}`);
    setTimeout(() => settle(res.buy.contract_id, sig.label, side, 0), (res.minutes * 60 + 20) * 1000);
  } catch (err: any) {
    console.warn("[Deriv] execute failed:", err?.message);
    notifier?.(`⚠️ <b>Deriv — لم تُنفذ</b>\n${sig.label} ${side}\nالسبب: ${String(err?.message || err).replace(/[<>&]/g, " ")}`);
  }
}

export async function settle(contractId: number, label: string, side: string, attempt: number): Promise<void> {
  const t = await token();
  if (!t) return;
  try {
    const poc = await withDeriv(t, async (call) => (await call({ proposal_open_contract: 1, contract_id: contractId })).proposal_open_contract);
    if (!poc?.is_sold && attempt < 6) { setTimeout(() => settle(contractId, label, side, attempt + 1), 30_000); return; }
    const profit = Number(poc?.profit ?? 0), cur = poc?.currency || "USD";
    const won = poc?.status === "won" || profit > 0;
    const s = await getDerivSettings();
    const stats = { ...s.stats, n: s.stats.n + 1, win: s.stats.win + (won ? 1 : 0), loss: s.stats.loss + (won ? 0 : 1), pnl: Math.round((s.stats.pnl + profit) * 100) / 100 };
    await updateDerivSettings({ stats });
    notifier?.(`${won ? "✅ <b>Deriv — ربح</b>" : "❌ <b>Deriv — خسارة</b>"}\n${label} ${side}  ${fmtMoney(profit, cur)}\n📊 السجل: ${stats.win} ربح / ${stats.loss} خسارة (${stats.n ? Math.round(stats.win / stats.n * 100) : 0}%) — الصافي ${fmtMoney(stats.pnl, cur)}`);
  } catch (err: any) {
    if (attempt < 6) setTimeout(() => settle(contractId, label, side, attempt + 1), 30_000);
    else console.warn("[Deriv] settle failed:", err?.message);
  }
}

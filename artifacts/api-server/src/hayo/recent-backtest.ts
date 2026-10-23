/**
 * RECENT-DATA BACKTEST of the live binary signals (weights model ± liquidity
 * trap), run on the server against the same Dukascopy feed the bot trades on.
 *
 * Replays every closed low-TF bar of the last N days through the PRODUCTION
 * code (tfFeatureSeries → weights model, detectLiquidityTraps, decideSignal),
 * exactly like the live scanner:
 *   - one open trade per pair: a new signal only after the previous expired;
 *   - entry = next bar open (≈ live price when the signal is sent);
 *   - win if the close `horizon` bars later is beyond entry (binary rules),
 *     a tie is refunded; payout defaults to +0.83 / −1 (configurable).
 * Replays the fresh-extreme, 15m trend and meta-confidence gates. Does not
 * replay high-impact news, optional AI veto (both remove signals), or scan
 * cadence (live sends at most as many signals as this counts).
 */
import { fetchFromDukascopy } from "./market-data";
import { tfFeatureSeries, WEIGHT_MODELS, ALL_FEATURES, FEATURE_NAMES, type FeatureName, type OhlcBar } from "./weights-model";
import { detectLiquidityTraps, lastBarTrap } from "./liquidity-trap";
import { decideSignal, type MinGrade } from "./signal-policy";
import { freshExtremeNoLine, trendMisaligned, type TrendGateMode } from "./extreme-filter";
import { metaFeatures, metaConfidence, META_MIN_CONF, META_ENABLED } from "./meta-model";

type Bar = OhlcBar & { t: number };
const TF_MS: Record<string, number> = { "1m": 60_000, "5m": 300_000, "15m": 900_000, "1h": 3_600_000 };
const TF_IV: Record<string, string> = { "1m": "1min", "5m": "5min", "15m": "15min", "1h": "1h" };
const WARM_BARS = 300;           // indicator warm-up fetched before the test window
export const BINARY_PAYOUT_BT = Number(process.env.HAYO_BINARY_PAYOUT ?? 0.83);
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));

/** Closed bars in [fromMs, toMs), oldest first, paging Dukascopy backwards 1000 bars at a time. */
type Fetcher = typeof fetchFromDukascopy;
export async function fetchHistory(symbol: string, tf: string, fromMs: number, toMs: number, fetcher: Fetcher = fetchFromDukascopy, pauseMs = 250): Promise<Bar[]> {
  const ms = TF_MS[tf], out = new Map<number, Bar>();
  let cursor = toMs;
  for (let page = 0; page < 120 && cursor > fromMs; page++) {
    const r = await fetcher(symbol, TF_IV[tf], 1000, cursor);
    if (!r || r.values.length === 0) break;
    let oldest = Infinity;
    for (const v of r.values) {
      const t = Date.parse(v.datetime);
      if (!Number.isFinite(t)) continue;
      oldest = Math.min(oldest, t);
      if (t < fromMs || t + ms > toMs) continue;                // outside window / still forming
      const bar = { t, open: +v.open, high: +v.high, low: +v.low, close: +v.close, volume: +v.volume || 0 };
      if (bar.high - bar.low <= 0 && !bar.volume) continue;      // flat no-trade filler (weekend / break)
      out.set(t, bar);
    }
    if (!(oldest < cursor)) break;                               // feed did not go further back
    cursor = oldest;
    if (pauseMs) await sleep(pauseMs);
  }
  return [...out.values()].sort((a, b) => a.t - b.t);
}

export interface Tally { n: number; win: number; loss: number; tie: number }
const tally = (): Tally => ({ n: 0, win: 0, loss: 0, tie: 0 });
export interface BacktestResult {
  modelId: string; horizon: number; lowTf: string; days: number; minGrade: MinGrade;
  from: number; to: number;
  total: Tally;
  byMode: Record<"weights" | "trap", Tally>;
  byPair: Record<string, Tally>;
  byDay: Record<string, Tally>;           // UTC date
  coveredFrom: Record<string, number>;    // oldest low-TF bar actually received, per pair
  skipped: string[];                      // pairs without usable data
}
const add = (t: Tally, r: "win" | "loss" | "tie") => { t.n++; t[r]++; };

/** Replay one pair; `sink` receives every graded trade. */
function replayPair(
  modelId: string, bars: Bar[][], evalFrom: number, minGrade: MinGrade, expiryOverride: number | undefined,
  sink: (mode: "weights" | "trap", r: "win" | "loss" | "tie", t: number) => void,
): void {
  const m = WEIGHT_MODELS[modelId];
  const raw = m.features ?? FEATURE_NAMES;
  const perTf: (readonly FeatureName[])[] = Array.isArray(raw[0]) ? (raw as FeatureName[][]) : [0, 1, 2].map(() => raw as readonly FeatureName[]);
  const idx = perTf.map(fs => fs.map(f => ALL_FEATURES.indexOf(f)));
  const feats = bars.map(b => tfFeatureSeries(b));
  const low = bars[0], lowMs = TF_MS[m.tfs[0]], H = expiryOverride ?? m.horizon;
  const traps = new Map<number, "BUY" | "SELL">();
  // Candidates from one whole-series pass, each confirmed with the exact live
  // call (lastBarTrap on the 600 closed bars the bot holds) — no lookahead.
  if (modelId === "fast") for (const e of detectLiquidityTraps(low)) {
    const live = lastBarTrap(low.slice(Math.max(0, e.index - 599), e.index + 1));
    if (live) traps.set(e.index, live.dir);
  }
  const ptr = [0, 0, 0];
  let busyUntil = -1;
  for (let i = 0; i + H < low.length; i++) {
    const closeT = low[i].t + lowMs;
    // align the higher timeframes to their last CLOSED bar at this moment
    const x: number[] = [];
    let ok = true;
    for (let k = 0; k < 3; k++) {
      const B = bars[k], ms = TF_MS[m.tfs[k]];
      while (ptr[k] + 1 < B.length && B[ptr[k] + 1].t + ms <= closeT) ptr[k]++;
      const f = B.length && B[ptr[k]].t + ms <= closeT ? feats[k][ptr[k]] : undefined;
      if (!f || f.length !== ALL_FEATURES.length) { ok = false; break; }
      for (const j of idx[k]) x.push(f[j]);
    }
    if (!ok || low[i].t < evalFrom || i <= busyUntil || x.length !== m.w.length) continue;
    let z = m.b;
    x.forEach((v, j) => (z += m.w[j] * (v - m.mu[j]) / m.sd[j]));
    const p = 1 / (1 + Math.exp(-z));
    const grade = p >= 0.58 || p <= 0.42 ? "A" : p >= 0.56 || p <= 0.44 ? "B" : "-";
    const trapDir = traps.get(i);
    const d = decideSignal({ p, grade }, trapDir ? { dir: trapDir } : null, minGrade);
    if (!d) continue;
    if (modelId === "fast" && d.mode !== "trap" && process.env.HAYO_EXTREME_FILTER !== "0") {
      const check = freshExtremeNoLine(low.slice(Math.max(0, i - 599), i + 1), d.dir);
      if (check.blocked) continue;
    }
    if (modelId === "fast" && d.mode !== "trap" && bars.length >= 3) {
      const rawMode = (process.env.HAYO_TREND_GATE ?? "regime").trim().toLowerCase();
      const mode: TrendGateMode = rawMode === "0" || rawMode === "off" ? "off" : rawMode === "strict" ? "strict" : "regime";
      if (mode !== "off") {
        const closes15 = bars[2].slice(0, ptr[2] + 1).map(b => b.close);
        if (trendMisaligned(closes15, d.dir, mode, Number(process.env.HAYO_TREND_ER ?? 0.3)).blocked) continue;
      }
    }
    if (modelId === "fast" && META_ENABLED && bars.length >= 3) {
      const conf = metaConfidence(metaFeatures({
        p, dir: d.dir, trapDir: trapDir ?? null,
        c1: low.slice(Math.max(0, i - 599), i + 1),
        c5: bars[1].slice(0, ptr[1] + 1),
        c15: bars[2].slice(0, ptr[2] + 1),
      }));
      if (conf < META_MIN_CONF) continue;
    }
    if (low[i + H].t - low[i + 1].t > (H + 5) * lowMs) continue;   // expiry spans a market gap
    const entry = low[i + 1].open, exit = low[i + H].close;
    const r = exit === entry ? "tie" : (d.dir === "BUY" ? exit > entry : exit < entry) ? "win" : "loss";
    sink(d.mode, r, low[i].t);
    busyUntil = i + H;                                               // one open trade per pair
  }
}

export async function runRecentBacktest(opts: {
  pairs: { code: string; symbol: string }[]; modelId: string; days: number; minGrades: MinGrade[];
  /** Optional exploratory expiry in low-timeframe candles; the model signal itself is unchanged. */
  expiryOverride?: number;
  onProgress?: (done: number, total: number, pair: string) => void | Promise<void>;
  /** test hooks: data source, clock, pause between pages */
  fetcher?: Fetcher; now?: number; pauseMs?: number;
}): Promise<BacktestResult[]> {
  const m = WEIGHT_MODELS[opts.modelId];
  if (!m) throw new Error(`unknown model ${opts.modelId}`);
  const to = Math.floor((opts.now ?? Date.now()) / 60_000) * 60_000;
  const from = to - opts.days * 86_400_000;
  const results = opts.minGrades.map((g): BacktestResult => ({
    modelId: opts.modelId, horizon: opts.expiryOverride ?? m.horizon, lowTf: m.tfs[0], days: opts.days, minGrade: g, from, to,
    total: tally(), byMode: { weights: tally(), trap: tally() }, byPair: {}, byDay: {}, coveredFrom: {}, skipped: [],
  }));
  let done = 0;
  for (const { code, symbol } of opts.pairs) {
    await opts.onProgress?.(done, opts.pairs.length, code);
    const bars: Bar[][] = [];
    for (const tf of m.tfs) bars.push(await fetchHistory(symbol, tf, from - WARM_BARS * TF_MS[tf], to, opts.fetcher, opts.pauseMs));
    done++;
    if (bars.some(b => b.length < WARM_BARS / 2)) { results.forEach(r => r.skipped.push(code)); continue; }
    for (const res of results) {
      res.coveredFrom[code] = bars[0][0].t;
      replayPair(opts.modelId, bars, from, res.minGrade, opts.expiryOverride, (mode, r, t) => {
        add(res.total, r); add(res.byMode[mode], r);
        add(res.byPair[code] ??= tally(), r);
        add(res.byDay[new Date(t).toISOString().slice(0, 10)] ??= tally(), r);
      });
    }
  }
  return results;
}

/** Win rate over decided trades (ties refunded, excluded). */
export function winRate(t: Tally): number | null {
  const d = t.win + t.loss;
  return d ? (t.win / d) * 100 : null;
}
/** Net result in stakes: +payout per win, −1 per loss. */
export function netStakes(t: Tally, payout = BINARY_PAYOUT_BT): number {
  return t.win * payout - t.loss;
}
/** 95% margin of error of a win rate, in percentage points. */
export function margin95(t: Tally): number | null {
  const d = t.win + t.loss;
  if (!d) return null;
  const r = t.win / d;
  return 196 * Math.sqrt((r * (1 - r)) / d);
}


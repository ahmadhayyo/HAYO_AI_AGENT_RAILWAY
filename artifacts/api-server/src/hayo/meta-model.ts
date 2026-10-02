/**
 * META-LABELING confidence model for the convergence signals.
 *
 * The weights model answers "which direction?". This second-stage model answers
 * "how trustworthy is THIS signal?" by combining every layer the system already
 * computes — the weights edge, the liquidity trap, the strategy consensus on
 * 1m/5m/15m, the volatility regime, efficiency ratio, momentum and the session
 * hour — into one logistic "confidence" that was trained to predict a win.
 *
 * Validated out-of-sample on OANDA data, both directions of the 2018/2019 split:
 *   baseline grade-B win rate ≈ 55-56%
 *   keep only confidence ≥ 0.56 → ≈ 64-66% win rate, ~half the signals kept
 *   keep only confidence ≥ 0.60 → ≈ 66-69%, ~a third kept
 * The top drivers are the 5m/15m strategy consensus and the ATR volatility
 * regime — i.e. the strategies/filters layer, used as evidence rather than as a
 * single veto.
 *
 * The SAME feature builder is used offline (training) and live, so there is no
 * train/serve skew. Coefficients live in meta-model.json.
 */
import {
  calcRSI, calcMACD, calcBB, calcATR, calcStochastic, calcWilliamsR,
  calcPivotPoints, calcADX, calcStrategies, calcFilters,
} from "./market-analysis";
import model from "./meta-model.json";

export interface MiniBar { t?: number; time?: number; open: number; high: number; low: number; close: number; volume: number }

/** Bar timestamp in ms, tolerating offline `.t` (ms) and live `.time` (seconds). */
const tms = (b: MiniBar): number => (typeof b.t === "number" ? b.t : (b.time ?? 0) * 1000);
const smaN = (arr: number[], n: number) => (arr.length < n ? arr[arr.length - 1] ?? 0 : arr.slice(-n).reduce((a, b) => a + b, 0) / n);

/** Strategy-consensus + trend on one timeframe window (mirrors the live scan). */
export function tfAnalyze(win: MiniBar[]): { cons: 1 | -1 | 0; pct: number; rec: 1 | -1 | 0; trendUp: boolean | null } {
  const closes = win.map(b => b.close), highs = win.map(b => b.high), lows = win.map(b => b.low), opens = win.map(b => b.open), vols = win.map(b => b.volume);
  const price = closes[closes.length - 1];
  const RSI = calcRSI(closes), SMA20 = smaN(closes, 20), SMA50 = smaN(closes, 50), SMA200 = closes.length >= 200 ? smaN(closes, 200) : null;
  const MACD = calcMACD(closes), BB = calcBB(closes), ATR = calcATR(highs, lows, closes);
  const STOCH = calcStochastic(closes, highs, lows), WILLR = calcWilliamsR(closes, highs, lows);
  const PIVOTS = calcPivotPoints(highs, lows, closes, win.map(b => new Date(tms(b)).toISOString()));
  const ADX = calcADX(highs, lows, closes);
  const strategies: any[] = calcStrategies(closes, highs, lows, SMA20, SMA50, SMA200, RSI, MACD, BB, ATR, STOCH, WILLR, ADX, PIVOTS, opens, vols);
  const filters: any[] = calcFilters(price, SMA20, SMA50, SMA200, RSI, ATR, closes, { highs, lows, market24x7: false });
  const buys = strategies.filter(s => s.signal === "BUY").length, sells = strategies.filter(s => s.signal === "SELL").length;
  const dom = Math.max(buys, sells), dirn = buys + sells, pct = dirn ? Math.round((dom / dirn) * 100) : 0;
  const cons = buys === sells || dom < 4 ? 0 : buys > sells ? 1 : -1;
  const tf = filters.find(f => f.id === "trend_filter"); const trendUp = tf ? tf.allowsBuy : null;
  let vote = 0; for (const s of strategies) { if (s.signal === "BUY") vote += s.strength / 100; else if (s.signal === "SELL") vote -= s.strength / 100; }
  if (trendUp === true) vote += 1.2; else if (trendUp === false) vote -= 1.2;
  const norm = Math.max(-1, Math.min(1, vote / ((strategies.length + 1.2) * 0.5)));
  const rec = Math.abs(norm) < 0.18 ? 0 : norm > 0 ? 1 : -1;
  return { cons: cons as any, pct, rec: rec as any, trendUp };
}

const atr14 = (bars: MiniBar[]): number[] => {
  const o: number[] = []; let a = 0;
  bars.forEach((x, i) => { const tr = i ? Math.max(x.high - x.low, Math.abs(x.high - bars[i - 1].close), Math.abs(x.low - bars[i - 1].close)) : x.high - x.low; a = i < 14 ? (a * i + tr) / (i + 1) : a + (tr - a) / 14; o.push(a); });
  return o;
};

export const META_FEATURES = [
  "edge", "trapOn", "trapAg", "cons1", "cons5", "cons15", "rec1", "rec5", "rec15",
  "trend1", "trend5", "trend15", "atrPct", "er", "mom", "hsin", "hcos",
] as const;

/**
 * Build the meta feature vector for one signal. `c1/c5/c15` are the newest
 * candle windows per timeframe (≥200 bars for 1m/5m/15m), oldest→newest.
 * All direction-relative features are framed in the signal's direction.
 */
export function metaFeatures(opts: {
  p: number; dir: "BUY" | "SELL"; trapDir: "BUY" | "SELL" | null;
  c1: MiniBar[]; c5: MiniBar[]; c15: MiniBar[];
}): number[] {
  const { p, dir, trapDir, c1, c5, c15 } = opts;
  const sgn = dir === "BUY" ? 1 : -1;
  const edge = Math.abs(p - 0.5);
  const trapOn = trapDir ? 1 : 0;
  const trapAg = trapDir ? (trapDir === "BUY" ? p : 1 - p) : 0;
  const a1 = tfAnalyze(c1.slice(-200)), a5 = tfAnalyze(c5.slice(-200)), a15 = tfAnalyze(c15.slice(-200));
  const consAgree = (a: { cons: number; pct: number }) => (a.cons === 0 ? 0 : (a.cons === sgn ? 1 : -1) * (a.pct / 100));
  const recAgree = (a: { rec: number }) => (a.rec === 0 ? 0 : a.rec === sgn ? 1 : -1);
  const trendAgree = (a: { trendUp: boolean | null }) => (a.trendUp === null ? 0 : ((a.trendUp ? 1 : -1) === sgn ? 1 : -1));
  const A = atr14(c1); const i = c1.length - 1;
  const lo = Math.max(0, i - 500); let below = 0; for (let q = lo; q < i; q++) if (A[q] < A[i]) below++;
  const atrPct = i > lo ? below / (i - lo) : 0.5;
  let volsum = 0; for (let q = i - 19; q <= i && q > 0; q++) volsum += Math.abs(c1[q].close - c1[q - 1].close);
  const er = volsum > 0 ? Math.abs(c1[i].close - c1[Math.max(0, i - 20)].close) / volsum : 0;
  const mom = sgn * (c1[i].close - c1[Math.max(0, i - 20)].close) / (A[i] || 1e-9);
  const hr = new Date(tms(c1[i])).getUTCHours(); const hsin = Math.sin((2 * Math.PI * hr) / 24), hcos = Math.cos((2 * Math.PI * hr) / 24);
  return [edge, trapOn, trapAg, consAgree(a1), consAgree(a5), consAgree(a15), recAgree(a1), recAgree(a5), recAgree(a15),
    trendAgree(a1), trendAgree(a5), trendAgree(a15), atrPct, er, mom, hsin, hcos];
}

/** Win probability (0..1) from the trained logistic model. */
export function metaConfidence(features: number[]): number {
  const { mu, sd, w, b } = model as { mu: number[]; sd: number[]; w: number[]; b: number };
  let z = b;
  for (let j = 0; j < w.length; j++) z += w[j] * ((features[j] - mu[j]) / (sd[j] || 1));
  return 1 / (1 + Math.exp(-z));
}

/** Default confidence gate (env HAYO_META_MIN overrides; 0 disables the gate). */
export const META_MIN_CONF: number = (() => {
  const v = Number(process.env.HAYO_META_MIN);
  return Number.isFinite(v) ? v : (model as any).threshold ?? 0.56;
})();

export const META_ENABLED = META_MIN_CONF > 0;

/**
 * Learned multi-timeframe weighting model for the convergence scanner.
 *
 * 11 trend / momentum / extension features are computed on each of three
 * timeframes (low, mid, high) → 33 inputs → L2-regularised logistic regression
 * estimating P(price is higher H low-TF bars after entering at the next bar's
 * open). Trained on 2018 OANDA 1-minute data (EUR_USD, GBP_USD, AUD_USD,
 * USD_CAD, EUR_JPY, XAU_USD) and validated OUT-OF-SAMPLE on 2019 — see
 * scripts/train-weights.ts, which imports this exact feature code so research
 * and production cannot drift apart.
 *
 * All inputs are OLDEST-FIRST arrays of CLOSED bars.
 */
import MODELS from "./weights-model.json" with { type: "json" };

export interface OhlcBar { open: number; high: number; low: number; close: number }

export const FEATURE_NAMES = ["trend", "slope", "hist", "dhist", "di", "adxUp", "brk", "fresh", "ext", "rsi", "roc"] as const;
export const FEATURE_LABELS_AR: Record<(typeof FEATURE_NAMES)[number], string> = {
  trend: "اتجاه EMA20/50", slope: "ميل EMA20", hist: "هستوغرام MACD", dhist: "تسارع MACD",
  di: "+DI/−DI", adxUp: "صعود ADX", brk: "موقع السعر في نطاق 20", fresh: "حداثة تقاطع EMA9/21",
  ext: "الامتداد عن EMA21", rsi: "RSI", roc: "زخم 10 شموع",
};

// ── indicator series (identical definitions to the research harness) ──
function ema(a: number[], p: number): number[] {
  const o = new Array(a.length).fill(NaN); if (a.length < p) return o;
  const k = 2 / (p + 1); let e = 0; for (let i = 0; i < p; i++) e += a[i]; e /= p; o[p - 1] = e;
  for (let i = p; i < a.length; i++) { e = a[i] * k + e * (1 - k); o[i] = e; }
  return o;
}
function rma(a: number[], p: number): number[] {
  const o = new Array(a.length).fill(NaN); if (a.length < p) return o;
  let s = 0; for (let i = 0; i < p; i++) s += a[i]; let r = s / p; o[p - 1] = r;
  for (let i = p; i < a.length; i++) { r = (r * (p - 1) + a[i]) / p; o[i] = r; }
  return o;
}
function trueRange(h: number[], l: number[], c: number[]): number[] {
  const o = [h[0] - l[0]];
  for (let i = 1; i < h.length; i++) o.push(Math.max(h[i] - l[i], Math.abs(h[i] - c[i - 1]), Math.abs(l[i] - c[i - 1])));
  return o;
}
function rsi(c: number[], p = 14): number[] {
  const g = [0], l = [0];
  for (let i = 1; i < c.length; i++) { const d = c[i] - c[i - 1]; g.push(Math.max(d, 0)); l.push(Math.max(-d, 0)); }
  // Wilder RSI over the p changes after the first bar
  const ag = rma(g.slice(1), p), al = rma(l.slice(1), p);
  const o = [NaN];
  for (let i = 0; i < ag.length; i++) o.push(isNaN(ag[i]) ? NaN : al[i] === 0 ? 100 : 100 - 100 / (1 + ag[i] / al[i]));
  return o;
}
function adx(h: number[], l: number[], c: number[], p = 14) {
  const n = h.length, pdm = [0], mdm = [0];
  for (let i = 1; i < n; i++) {
    const up = h[i] - h[i - 1], dn = l[i - 1] - l[i];
    pdm.push(up > dn && up > 0 ? up : 0); mdm.push(dn > up && dn > 0 ? dn : 0);
  }
  const t = rma(trueRange(h, l, c), p), sp = rma(pdm, p), sm = rma(mdm, p);
  const pdi: number[] = [], mdi: number[] = [], dx: number[] = [];
  for (let i = 0; i < n; i++) {
    const P = 100 * sp[i] / t[i], M = 100 * sm[i] / t[i];
    pdi.push(P); mdi.push(M); dx.push(P + M > 0 ? 100 * Math.abs(P - M) / (P + M) : 0);
  }
  const first = dx.findIndex(v => !isNaN(v) && isFinite(v));
  const ax = new Array(n).fill(NaN);
  if (first >= 0) { const r = rma(dx.slice(first), p); for (let i = 0; i < r.length; i++) ax[first + i] = r[i]; }
  return { adx: ax, pdi, mdi };
}
function rollMax(a: number[], p: number) { const o = new Array(a.length).fill(NaN); for (let i = p - 1; i < a.length; i++) { let m = -Infinity; for (let j = i - p + 1; j <= i; j++) if (a[j] > m) m = a[j]; o[i] = m; } return o; }
function rollMin(a: number[], p: number) { const o = new Array(a.length).fill(NaN); for (let i = p - 1; i < a.length; i++) { let m = Infinity; for (let j = i - p + 1; j <= i; j++) if (a[j] < m) m = a[j]; o[i] = m; } return o; }
const clip = (x: number, a: number) => Math.max(-a, Math.min(a, x));

/** Feature rows for every bar (empty row until the indicators are warm). */
export function tfFeatureSeries(bars: OhlcBar[]): number[][] {
  const c = bars.map(x => x.close), h = bars.map(x => x.high), l = bars.map(x => x.low);
  const e9 = ema(c, 9), e20 = ema(c, 20), e21 = ema(c, 21), e50 = ema(c, 50);
  const e12 = ema(c, 12), e26 = ema(c, 26);
  const macd = c.map((_, i) => e12[i] - e26[i]);
  const sig = ema(macd.map(v => (isFinite(v) ? v : 0)), 9);
  const hist = macd.map((v, i) => v - sig[i]);
  const at = rma(trueRange(h, l, c), 14);
  const dx = adx(h, l, c);
  const r = rsi(c);
  const H20 = rollMax(h, 20), L20 = rollMin(l, 20);
  const out: number[][] = [];
  let since = 999, prevSide = 0;
  for (let i = 0; i < bars.length; i++) {
    const side = Math.sign(e9[i] - e21[i]);
    if (side !== 0 && side !== prevSide) { since = 0; prevSide = side; } else since++;
    const a = at[i];
    if (!(a > 0) || i < 60 || !isFinite(e50[i]) || !isFinite(dx.adx[i]) || !isFinite(H20[i])) { out.push([]); continue; }
    const half = (H20[i] - L20[i]) / 2 || a;
    out.push([
      clip((e20[i] - e50[i]) / a, 3) / 3,
      clip((e20[i] - e20[i - 5]) / a, 3) / 3,
      clip(hist[i] / a, 2) / 2,
      clip((hist[i] - hist[i - 3]) / a, 2) / 2,
      (dx.pdi[i] - dx.mdi[i]) / 100,
      Math.sign(dx.pdi[i] - dx.mdi[i]) * clip((dx.adx[i] - dx.adx[i - 3]) / 10, 1),
      clip((c[i] - (H20[i] + L20[i]) / 2) / half, 1.5),
      side * Math.exp(-since / 5),
      clip((c[i] - e21[i]) / a, 4) / 4,
      (r[i] - 50) / 50,
      clip((c[i] - c[i - 10]) / a, 4) / 4,
    ]);
  }
  return out;
}

/** Plain-language reading of a raw feature value (sign = bullish/bearish side). */
function readFeature(f: (typeof FEATURE_NAMES)[number], v: number): string {
  const up = v > 0;
  switch (f) {
    case "trend": return up ? "EMA20 فوق EMA50" : "EMA20 تحت EMA50";
    case "slope": return up ? "المتوسط يميل صعوداً" : "المتوسط يميل هبوطاً";
    case "hist": return up ? "زخم MACD إيجابي" : "زخم MACD سلبي";
    case "dhist": return up ? "زخم MACD يتسارع صعوداً" : "زخم MACD يتسارع هبوطاً";
    case "di": return up ? "+DI أقوى (ضغط شراء)" : "−DI أقوى (ضغط بيع)";
    case "adxUp": return v === 0 ? "ADX ثابت" : up ? "ADX يرتفع مع المشترين" : "ADX يرتفع مع البائعين";
    case "brk": return v > 0.6 ? "قرب قمة نطاق 20 شمعة" : v < -0.6 ? "قرب قاع نطاق 20 شمعة" : up ? "في النصف العلوي للنطاق" : "في النصف السفلي للنطاق";
    case "fresh": return Math.abs(v) < 0.05 ? "لا تقاطع حديث" : up ? "تقاطع EMA9/21 صاعد حديث" : "تقاطع EMA9/21 هابط حديث";
    case "ext": return up ? `السعر فوق EMA21 بـ ${(v * 4).toFixed(1)} ATR (امتداد)` : `السعر تحت EMA21 بـ ${(-v * 4).toFixed(1)} ATR (تصحيح)`;
    case "rsi": return `RSI ${(50 + v * 50).toFixed(0)}`;
    case "roc": return up ? "صعد خلال آخر 10 شموع" : "هبط خلال آخر 10 شموع";
  }
}

export interface WeightModel {
  id: string; tfs: string[]; horizon: number; trainedOn: string; validatedOn: string;
  w: number[]; b: number; mu: number[]; sd: number[];
  /** Out-of-sample (2019) hit rates by threshold, for display. */
  oos: Record<string, { n: number; winRate: number }>;
}
export const WEIGHT_MODELS = MODELS as unknown as Record<string, WeightModel>;

export interface WeightedVerdict {
  modelId: string;
  p: number;                           // P(up after `horizon` low-TF bars)
  dir: "BUY" | "SELL" | "HOLD";
  grade: "A" | "B" | "-";              // A: p≥0.58/≤0.42, B: p≥0.56/≤0.44
  edgePct: number;                     // |p − 0.5| × 200 (0–100)
  expectedWinRate: number | null;      // out-of-sample win rate for this grade
  horizon: number; lowTf: string;
  top: { tf: string; feature: string; label: string; reading: string; contribution: number }[];
}

/**
 * Score the latest closed bar of each timeframe (low, mid, high).
 * Returns null when a timeframe lacks enough warm bars.
 */
export function weightedVerdict(modelId: string, barsByTf: OhlcBar[][]): WeightedVerdict | null {
  const m = WEIGHT_MODELS[modelId];
  if (!m || barsByTf.length !== 3) return null;
  const x: number[] = [];
  for (const bars of barsByTf) {
    const rows = tfFeatureSeries(bars);
    const last = rows[rows.length - 1];
    if (!last || last.length !== FEATURE_NAMES.length) return null;
    x.push(...last);
  }
  let z = m.b;
  const contrib: WeightedVerdict["top"] = [];
  x.forEach((v, j) => {
    const cz = m.w[j] * (v - m.mu[j]) / m.sd[j];
    z += cz;
    const f = FEATURE_NAMES[j % FEATURE_NAMES.length];
    contrib.push({ tf: m.tfs[Math.floor(j / FEATURE_NAMES.length)], feature: f, label: FEATURE_LABELS_AR[f], reading: readFeature(f, v), contribution: cz });
  });
  const p = 1 / (1 + Math.exp(-z));
  const grade: WeightedVerdict["grade"] = p >= 0.58 || p <= 0.42 ? "A" : p >= 0.56 || p <= 0.44 ? "B" : "-";
  const dir: WeightedVerdict["dir"] = grade === "-" ? "HOLD" : p > 0.5 ? "BUY" : "SELL";
  const oosKey = grade === "A" ? "0.58" : grade === "B" ? "0.56" : "";
  const sign = dir === "SELL" ? -1 : 1;
  return {
    modelId, p, dir, grade,
    edgePct: Math.round(Math.abs(p - 0.5) * 200),
    expectedWinRate: oosKey && m.oos[oosKey] ? m.oos[oosKey].winRate : null,
    horizon: m.horizon, lowTf: m.tfs[0],
    // strongest drivers in the decided direction (or overall when HOLD)
    top: contrib.sort((a, b) => sign * b.contribution - sign * a.contribution).slice(0, 4),
  };
}

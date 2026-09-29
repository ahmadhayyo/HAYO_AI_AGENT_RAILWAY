/**
 * Shared market-analysis core: technical indicators + 16 trading strategies
 * + confirmation filters. Used by BOTH the web analysis (router.ts) and the
 * Telegram bot (telegram/bot.ts) so signals are identical everywhere.
 * Extracted verbatim from router.ts (single source of truth — no duplication).
 */
import { calcVolumeProfile } from "./volume-profile";

// ─── Technical Indicator Helpers ─────────────────────────────────────
// Standard definitions, matching TradingView / Wilder so the numbers users see
// here agree with their charts:
//  • EMA is seeded with the SMA of its first `period` values.
//  • RSI, ATR and ADX use Wilder's smoothing (RMA), not a simple average.
//  • ADX is the Wilder average of DX (not a single raw DX reading).
// All inputs are oldest-first; scalar helpers return the latest value.

/** Series helpers (oldest-first, NaN until the indicator is warmed up). */
function emaSeries(arr: number[], period: number): number[] {
  const out = new Array(arr.length).fill(NaN);
  if (arr.length < period) return out;
  const k = 2 / (period + 1);
  let e = 0;
  for (let i = 0; i < period; i++) e += arr[i];
  e /= period;
  out[period - 1] = e;
  for (let i = period; i < arr.length; i++) { e = arr[i] * k + e * (1 - k); out[i] = e; }
  return out;
}
function rmaSeries(arr: number[], period: number): number[] {
  const out = new Array(arr.length).fill(NaN);
  if (arr.length < period) return out;
  let r = 0;
  for (let i = 0; i < period; i++) r += arr[i];
  r /= period;
  out[period - 1] = r;
  for (let i = period; i < arr.length; i++) { r = (r * (period - 1) + arr[i]) / period; out[i] = r; }
  return out;
}
function trueRanges(highs: number[], lows: number[], closes: number[]): number[] {
  const trs: number[] = [];
  for (let i = 1; i < highs.length; i++) {
    trs.push(Math.max(highs[i] - lows[i], Math.abs(highs[i] - closes[i - 1]), Math.abs(lows[i] - closes[i - 1])));
  }
  return trs;
}
const last = (a: number[]) => a[a.length - 1];

function calcSMA(arr: number[], period: number): number {
  if (arr.length < period) return arr[arr.length - 1] ?? 0;
  const slice = arr.slice(-period);
  return slice.reduce((a, b) => a + b, 0) / period;
}
function calcEMA(arr: number[], period: number): number {
  if (arr.length === 0) return 0;
  if (arr.length < period) return arr.reduce((a, b) => a + b, 0) / arr.length;
  return last(emaSeries(arr, period));
}
function calcRSI(closes: number[], period = 14): number {
  if (closes.length < period + 1) return 50;
  const gains: number[] = [], losses: number[] = [];
  for (let i = 1; i < closes.length; i++) {
    const d = closes[i] - closes[i - 1];
    gains.push(Math.max(d, 0)); losses.push(Math.max(-d, 0));
  }
  const ag = last(rmaSeries(gains, period)), al = last(rmaSeries(losses, period));
  if (al === 0) return ag === 0 ? 50 : 100;
  return 100 - 100 / (1 + ag / al);
}
function calcMACD(closes: number[]) {
  if (closes.length < 26) return { macd: 0, signal: 0, histogram: 0 };
  const e12 = emaSeries(closes, 12), e26 = emaSeries(closes, 26);
  const line = closes.map((_, i) => e12[i] - e26[i]).slice(25); // valid from index 25
  const macdLine = last(line);
  const signalLine = line.length >= 9 ? last(emaSeries(line, 9)) : macdLine;
  return { macd: macdLine, signal: signalLine, histogram: macdLine - signalLine };
}
function calcBB(closes: number[], period = 20, mult = 2) {
  const middle = calcSMA(closes, period);
  const slice  = closes.slice(-period);
  const variance = slice.reduce((s, v) => s + Math.pow(v - middle, 2), 0) / period;
  const sd = Math.sqrt(variance);
  return { upper: middle + mult * sd, middle, lower: middle - mult * sd };
}
function calcATR(highs: number[], lows: number[], closes: number[], period = 14): number {
  const trs = trueRanges(highs, lows, closes);
  if (trs.length === 0) return 0;
  if (trs.length < period) return trs.reduce((a, b) => a + b, 0) / trs.length;
  return last(rmaSeries(trs, period));
}

// Stochastic Oscillator (%K, %D) — %D is the 3-period SMA of the last %K values
function calcStochastic(closes: number[], highs: number[], lows: number[], kPeriod = 14, dPeriod = 3): { k: number; d: number } {
  if (closes.length < kPeriod) return { k: 50, d: 50 };
  const kAt = (end: number) => { // %K using bars [end-kPeriod+1 .. end]
    const hh = Math.max(...highs.slice(end - kPeriod + 1, end + 1));
    const ll = Math.min(...lows.slice(end - kPeriod + 1, end + 1));
    return hh === ll ? 50 : ((closes[end] - ll) / (hh - ll)) * 100;
  };
  const n = closes.length - 1;
  const k = kAt(n);
  const ks: number[] = [];
  for (let e = n - dPeriod + 1; e <= n; e++) if (e >= kPeriod - 1) ks.push(kAt(e));
  const d = ks.length === dPeriod ? ks.reduce((a, b) => a + b, 0) / dPeriod : k;
  return { k, d };
}

// Williams %R
function calcWilliamsR(closes: number[], highs: number[], lows: number[], period = 14): number {
  if (closes.length < period) return -50;
  const recentHighs = highs.slice(-period);
  const recentLows = lows.slice(-period);
  const hh = Math.max(...recentHighs);
  const ll = Math.min(...recentLows);
  const range = hh - ll;
  return range === 0 ? -50 : ((hh - closes[closes.length - 1]) / range) * -100;
}

/** Parse a candle timestamp as UTC (TwelveData omits the zone when timezone=UTC). */
function toUtcMs(t: string | number): number {
  if (typeof t === "number") return t < 1e12 ? t * 1000 : t;
  const s = /[zZ]|[+-]\d\d:?\d\d$/.test(t) ? t : t.replace(" ", "T") + "Z";
  return Date.parse(s);
}

// Pivot Points (Standard, "floor" pivots) — from the PREVIOUS completed UTC day.
// With `times`, the prior day's high/low/close is reconstructed from the candles
// (basis "prevDay"). Without enough history (e.g. 1-min charts) it falls back
// to the whole window excluding the current bar (basis "window"); the pivot
// strategy only trades real prior-day pivots.
function calcPivotPoints(highs: number[], lows: number[], closes: number[], times?: Array<string | number>): {
  pivot: number; r1: number; r2: number; r3: number; s1: number; s2: number; s3: number; basis: "prevDay" | "window";
} {
  let h = NaN, l = NaN, c = NaN, basis: "prevDay" | "window" = "window";
  if (times && times.length === closes.length && closes.length > 1) {
    const day = (i: number) => Math.floor(toUtcMs(times[i]) / 86400000);
    const today = day(closes.length - 1);
    let end = closes.length - 1;
    while (end >= 0 && day(end) === today) end--;          // last bar of previous day
    if (end >= 0) {
      const prev = day(end);
      let start = end;
      while (start > 0 && day(start - 1) === prev) start--;
      if (start > 0) {                                      // the day is fully inside the window
        h = Math.max(...highs.slice(start, end + 1));
        l = Math.min(...lows.slice(start, end + 1));
        c = closes[end];
        basis = "prevDay";
      }
    }
  }
  if (basis === "window") {
    const n = Math.max(1, closes.length - 1);
    h = Math.max(...highs.slice(0, n)); l = Math.min(...lows.slice(0, n)); c = closes[n - 1] ?? 0;
  }
  const pivot = (h + l + c) / 3;
  return {
    pivot,
    r1: 2 * pivot - l, r2: pivot + (h - l), r3: h + 2 * (pivot - l),
    s1: 2 * pivot - h, s2: pivot - (h - l), s3: l - 2 * (h - pivot),
    basis,
  };
}

// ADX (Average Directional Index) — Wilder: smoothed ±DM/TR → ±DI → DX → RMA(DX)
function calcADX(highs: number[], lows: number[], closes: number[], period = 14): { adx: number; pdi: number; mdi: number } {
  if (highs.length < period * 2 + 1) return { adx: 0, pdi: 0, mdi: 0 };
  const pdm: number[] = [], mdm: number[] = [];
  for (let i = 1; i < highs.length; i++) {
    const upMove = highs[i] - highs[i - 1];
    const downMove = lows[i - 1] - lows[i];
    pdm.push(upMove > downMove && upMove > 0 ? upMove : 0);
    mdm.push(downMove > upMove && downMove > 0 ? downMove : 0);
  }
  const str = rmaSeries(trueRanges(highs, lows, closes), period);
  const spdm = rmaSeries(pdm, period), smdm = rmaSeries(mdm, period);
  const dx: number[] = [];
  let pdi = 0, mdi = 0;
  for (let i = period - 1; i < str.length; i++) {
    pdi = str[i] > 0 ? (spdm[i] / str[i]) * 100 : 0;
    mdi = str[i] > 0 ? (smdm[i] / str[i]) * 100 : 0;
    dx.push(pdi + mdi > 0 ? (Math.abs(pdi - mdi) / (pdi + mdi)) * 100 : 0);
  }
  const adx = dx.length >= period ? last(rmaSeries(dx, period)) : last(dx);
  return { adx, pdi, mdi };
}

// ─── Trading-cost awareness ───────────────────────────────────────────
/**
 * Typical retail spread per instrument, in price units (HAYO pair codes).
 * Used to express the round-trip cost as a fraction of the stop distance.
 * Measured on 2018-19 OANDA data: with a 1.5×ATR stop the spread alone costs
 * ~70-110% of 1R on 1-min charts, ~30-45% on 5-min, ~15-25% on 15-min and
 * ~7-12% on 1h — the dominant reason short-timeframe signals lose money.
 */
const TYPICAL_SPREAD: Record<string, number> = {
  EURUSD: 0.00012, GBPUSD: 0.00018, USDJPY: 0.014, GBPJPY: 0.03, USDCHF: 0.00018,
  AUDUSD: 0.00014, NZDUSD: 0.0002, USDCAD: 0.00018, EURGBP: 0.00015, EURJPY: 0.018,
  EURCHF: 0.0002, AUDCAD: 0.00025, XAUUSD: 0.35, XAGUSD: 0.03, BTCUSD: 25, ETHUSD: 2,
  USOIL: 0.04, US30: 3,
};

/** Spread as a % of the risk taken with a stop at `slAtrMult`×ATR (null if unknown). */
function spreadCostPct(pair: string, atr: number, slAtrMult = 1.5): number | null {
  const sp = TYPICAL_SPREAD[pair];
  if (!sp || !(atr > 0)) return null;
  return (sp / (slAtrMult * atr)) * 100;
}

// ─── Strategy & Filter Types ──────────────────────────────────────────
interface StrategySignal {
  id: string;
  name: string;
  signal: "BUY" | "SELL" | "NEUTRAL";
  strength: number;
  desc: string;
  emoji: string;
}
interface FilterResult {
  id: string;
  name: string;
  passed: boolean;
  allowsBuy: boolean;
  allowsSell: boolean;
  desc: string;
  emoji: string;
}

// ─── Strategy Calculators ─────────────────────────────────────────────
function calcStrategies(
  closes: number[], highs: number[], lows: number[],
  sma20: number, sma50: number, sma200: number | null,
  rsi: number, macd: { macd: number; signal: number; histogram: number },
  bb: { upper: number; middle: number; lower: number },
  atr: number,
  stoch?: { k: number; d: number },
  williamsR?: number,
  adx?: { adx: number; pdi: number; mdi: number },
  pivots?: { pivot: number; r1: number; r2: number; r3: number; s1: number; s2: number; s3: number; basis?: "prevDay" | "window" },
  opens?: number[],
  volumes?: number[],
): StrategySignal[] {
  const price = closes[closes.length - 1];
  const prevPrice = closes[closes.length - 2] || price;
  const signals: StrategySignal[] = [];
  const dec = price >= 1000 ? 2 : price >= 20 ? 3 : 5;       // display precision per asset
  const fmtP = (n: number) => n.toFixed(dec);
  const n = closes.length - 1;

  // 1 — Trend Following (SMA Alignment)
  {
    let sig: "BUY" | "SELL" | "NEUTRAL" = "NEUTRAL";
    let str = 0;
    if (sma200) {
      if (price > sma20 && sma20 > sma50 && sma50 > sma200) { sig = "BUY";  str = 88; }
      else if (price < sma20 && sma20 < sma50 && sma50 < sma200) { sig = "SELL"; str = 88; }
      else if (price > sma20 && sma20 > sma50) { sig = "BUY";  str = 65; }
      else if (price < sma20 && sma20 < sma50) { sig = "SELL"; str = 65; }
    } else {
      if (price > sma20 && sma20 > sma50) { sig = "BUY";  str = 70; }
      else if (price < sma20 && sma20 < sma50) { sig = "SELL"; str = 70; }
    }
    signals.push({ id: "trend_following", name: "تتبع الاتجاه", emoji: "🎯",
      signal: sig, strength: str,
      desc: sig === "BUY" ? "المتوسطات المتحركة في تصاعد متوافق (SMA20>50>200)" :
            sig === "SELL" ? "المتوسطات المتحركة في تراجع متوافق (SMA20<50<200)" :
            "لا توافق واضح بين المتوسطات المتحركة" });
  }

  // 2 — Bollinger squeeze BREAKOUT: bands were tight (width < 2.5×ATR, ≈ the
  // tightest 15% on FX) within the last 10 bars and the close now breaks OUT of
  // a band → trade in the breakout direction. (Previously this fired the
  // opposite way — a band touch was treated as a reversal, which duplicated
  // the mean-reversion strategies under a "breakout" name.)
  {
    let sig: "BUY" | "SELL" | "NEUTRAL" = "NEUTRAL";
    let str = 0;
    const bbWidth = (bb.upper - bb.lower) / bb.middle * 100;
    const widthAtr = (end: number) => {           // band width at bar `end`, in ATRs of that time
      if (end < 20 || atr <= 0) return Infinity;
      const w = closes.slice(end - 19, end + 1), m = w.reduce((x, y) => x + y, 0) / 20;
      const sd = Math.sqrt(w.reduce((x, y) => x + (y - m) ** 2, 0) / 20);
      return (4 * sd) / atr;
    };
    let squeezeRecently = false;
    for (let k = 1; k <= 10 && !squeezeRecently; k++) squeezeRecently = widthAtr(n - k) < 2.5;
    const squeezeNow = widthAtr(n) < 2.5;
    if (squeezeRecently && price > bb.upper) { sig = "BUY"; str = 78; }
    else if (squeezeRecently && price < bb.lower) { sig = "SELL"; str = 78; }
    signals.push({ id: "breakout", name: "الاختراق (Bollinger Squeeze)", emoji: "💥",
      signal: sig, strength: str,
      desc: sig === "BUY" ? "اختراق صعودي للنطاق العلوي بعد انضغاط — بداية حركة محتملة" :
            sig === "SELL" ? "اختراق هبوطي للنطاق السفلي بعد انضغاط — بداية حركة محتملة" :
            squeezeNow ? "النطاقات منضغطة — انتظار اختراق" :
            `لا انضغاط ولا اختراق (عرض النطاق ${bbWidth.toFixed(2)}%)` });
  }

  // 3 — RSI Momentum
  {
    let sig: "BUY" | "SELL" | "NEUTRAL" = "NEUTRAL";
    let str = 0;
    if      (rsi < 20) { sig = "BUY";  str = 92; }
    else if (rsi < 30) { sig = "BUY";  str = 78; }
    else if (rsi < 38) { sig = "BUY";  str = 58; }
    else if (rsi > 80) { sig = "SELL"; str = 92; }
    else if (rsi > 70) { sig = "SELL"; str = 78; }
    else if (rsi > 62) { sig = "SELL"; str = 58; }
    signals.push({ id: "rsi_momentum", name: "انعكاس RSI (ذروة بيع/شراء)", emoji: "⚡",
      signal: sig, strength: str,
      desc: `RSI = ${rsi.toFixed(1)} — ${rsi < 30 ? "ذروة بيع قوية 🔴" : rsi < 38 ? "اقتراب ذروة بيع" : rsi > 70 ? "ذروة شراء قوية 🟢" : rsi > 62 ? "اقتراب ذروة شراء" : "منطقة محايدة (38-62)"}` });
  }

  // 4 — MACD: a fresh CROSSOVER on this bar is the signal (strong); an
  // established position above/below the signal line is weaker. Strength
  // scales with |histogram| in ATRs (was divided by MACD itself, which blows
  // up near zero).
  {
    let sig: "BUY" | "SELL" | "NEUTRAL" = "NEUTRAL";
    let str = 0;
    const prev = closes.length > 35 ? calcMACD(closes.slice(0, -1)) : null;
    const crossUp = prev !== null && prev.histogram <= 0 && macd.histogram > 0;
    const crossDn = prev !== null && prev.histogram >= 0 && macd.histogram < 0;
    const histAtr = atr > 0 ? Math.abs(macd.histogram) / atr : 0;
    if (crossUp) { sig = "BUY"; str = 80; }
    else if (crossDn) { sig = "SELL"; str = 80; }
    else if (macd.histogram > 0) { sig = "BUY"; str = Math.min(70, 50 + Math.round(histAtr * 100)); }
    else if (macd.histogram < 0) { sig = "SELL"; str = Math.min(70, 50 + Math.round(histAtr * 100)); }
    signals.push({ id: "macd_crossover", name: "تقاطع MACD", emoji: "📊",
      signal: sig, strength: str,
      desc: crossUp ? "تقاطع صاعد جديد: MACD قطع خط الإشارة للأعلى على هذه الشمعة" :
            crossDn ? "تقاطع هابط جديد: MACD قطع خط الإشارة للأسفل على هذه الشمعة" :
            `MACD ${macd.histogram > 0 ? "فوق" : "تحت"} خط الإشارة (بلا تقاطع جديد) | Histogram: ${macd.histogram.toFixed(dec + 1)}` });
  }

  // 5 — Scalping (Mean Reversion from SMA20) — stretch measured in ATRs
  // (2.2 ATR ≈ the most stretched 15% of bars, 1.6 ATR ≈ 30%).
  {
    const dist = (price - sma20) / sma20 * 100;
    const distAtr = atr > 0 ? (price - sma20) / atr : 0;
    let sig: "BUY" | "SELL" | "NEUTRAL" = "NEUTRAL";
    let str = 0;
    if      (distAtr < -2.2) { sig = "BUY";  str = 75; }
    else if (distAtr < -1.6) { sig = "BUY";  str = 58; }
    else if (distAtr >  2.2) { sig = "SELL"; str = 75; }
    else if (distAtr >  1.6) { sig = "SELL"; str = 58; }
    signals.push({ id: "scalping", name: "سكالبينج (ارتداد)", emoji: "⚡",
      signal: sig, strength: str,
      desc: `البعد عن SMA20: ${dist >= 0 ? "+" : ""}${dist.toFixed(3)}% — ${sig === "BUY" ? "السعر بعيد أسفل المتوسط" : sig === "SELL" ? "السعر بعيد فوق المتوسط" : "السعر قريب من المتوسط"}` });
  }

  // 6 — Swing Trading (Pullback to SMA50)
  {
    const distSMA50 = Math.abs(price - sma50) / sma50 * 100;
    const nearSMA50 = atr > 0 ? Math.abs(price - sma50) < 0.5 * atr : distSMA50 < 0.18;
    let sig: "BUY" | "SELL" | "NEUTRAL" = "NEUTRAL";
    let str = 0;
    if (nearSMA50 && sma20 > sma50)          { sig = "BUY";  str = 74; }
    else if (nearSMA50 && sma20 < sma50)     { sig = "SELL"; str = 74; }
    else if (price > sma50 && rsi < 48)      { sig = "BUY";  str = 62; }
    else if (price < sma50 && rsi > 52)      { sig = "SELL"; str = 62; }
    signals.push({ id: "swing", name: "سوينغ ترادينج", emoji: "🌊",
      signal: sig, strength: str,
      desc: nearSMA50 ? `السعر قريب من SMA50 — نقطة انعكاس محتملة (${distSMA50.toFixed(3)}%)` :
            `انتظار تصحيح نحو SMA50 (بُعد: ${distSMA50.toFixed(3)}%)` });
  }

  // 7 — Support & Resistance (Swing Levels + Touch Count)
  {
    const pDecimals = price > 100 ? 2 : price > 10 ? 3 : 5;
    const fmt5 = (n: number) => n.toFixed(pDecimals);

    // Detect swing highs and lows (require 3 candles on each side)
    const swing = 3;
    const swingHighs: number[] = [];
    const swingLows:  number[] = [];
    for (let i = swing; i < highs.length - swing; i++) {
      let isH = true, isL = true;
      for (let j = i - swing; j <= i + swing; j++) {
        if (j === i) continue;
        if (highs[j] >= highs[i]) isH = false;
        if (lows[j]  <= lows[i])  isL = false;
      }
      if (isH) swingHighs.push(highs[i]);
      if (isL) swingLows.push(lows[i]);
    }

    // Cluster nearby swing levels (within 1 ATR = same zone)
    const clusterTol = atr;
    function clusterLevels(levels: number[]): { price: number; touches: number }[] {
      const groups: { price: number; count: number }[] = [];
      for (const lvl of levels) {
        const g = groups.find(g => Math.abs(g.price - lvl) <= clusterTol);
        if (g) {
          g.price = (g.price * g.count + lvl) / (g.count + 1); // weighted average
          g.count++;
        } else {
          groups.push({ price: lvl, count: 1 });
        }
      }
      return groups.map(g => ({ price: g.price, touches: g.count }));
    }

    const allRes = clusterLevels(swingHighs)
      .filter(l => l.price > price)
      .sort((a, b) => a.price - b.price); // nearest first

    const allSup = clusterLevels(swingLows)
      .filter(l => l.price < price)
      .sort((a, b) => b.price - a.price); // nearest first

    // Confirmed levels need ≥3 touches (2 bounces confirmed)
    // Potential levels: 2 touches (1 bounce confirmed — awaiting 3rd touch)
    // Weak levels: 1 touch only
    const validRes     = allRes.filter(l => l.touches >= 3); // confirmed resistance
    const validSup     = allSup.filter(l => l.touches >= 3); // confirmed support
    const potentialRes = allRes.filter(l => l.touches === 2); // 1 bounce, waiting 3rd
    const potentialSup = allSup.filter(l => l.touches === 2);
    const weakRes      = allRes.filter(l => l.touches === 1);
    const weakSup      = allSup.filter(l => l.touches === 1);

    const nearestRes = validRes[0] ?? null;
    const nearestSup = validSup[0] ?? null;
    const nearestPotRes = potentialRes[0] ?? null;
    const nearestPotSup = potentialSup[0] ?? null;
    const nearestWeakRes = weakRes[0] ?? null;
    const nearestWeakSup = weakSup[0] ?? null;

    // "Near" = within 0.5 ATR of a valid level
    const proximity = atr * 0.5;
    const nearRes    = nearestRes    && Math.abs(price - nearestRes.price)    <= proximity;
    const nearSup    = nearestSup    && Math.abs(price - nearestSup.price)    <= proximity;
    const nearPotRes = nearestPotRes && Math.abs(price - nearestPotRes.price) <= proximity;
    const nearPotSup = nearestPotSup && Math.abs(price - nearestPotSup.price) <= proximity;

    let sig: "BUY" | "SELL" | "NEUTRAL" = "NEUTRAL";
    let str = 0;
    let desc = "";

    if (nearSup && nearestSup) {
      // ✅ At confirmed support (3+ touches = 2 bounces confirmed) → strong BUY
      sig = "BUY";
      str = Math.min(95, 80 + nearestSup.touches * 4);
      desc = `دعم مؤكد عند ${fmt5(nearestSup.price)} (${nearestSup.touches} لمسات — ${nearestSup.touches - 1} ارتداد مؤكد ✅) — ارتداد صعودي قوي متوقع`;
    } else if (nearRes && nearestRes) {
      // ✅ At confirmed resistance (3+ touches = 2 bounces confirmed) → strong SELL
      sig = "SELL";
      str = Math.min(95, 80 + nearestRes.touches * 4);
      desc = `مقاومة مؤكدة عند ${fmt5(nearestRes.price)} (${nearestRes.touches} لمسات — ${nearestRes.touches - 1} ارتداد مؤكد ✅) — ارتداد هبوطي قوي متوقع`;
    } else if (nearPotSup && nearestPotSup) {
      // ⚡ Near potential support (2 touches = 1 bounce — await 3rd for confirmation)
      sig = "NEUTRAL";
      str = 0;
      desc = `⚡ مستوى دعم محتمل عند ${fmt5(nearestPotSup.price)} (لمستان، ارتداد واحد) — بانتظار اللمسة الثالثة للتأكيد`;
    } else if (nearPotRes && nearestPotRes) {
      // ⚡ Near potential resistance (2 touches = 1 bounce — await 3rd for confirmation)
      sig = "NEUTRAL";
      str = 0;
      desc = `⚡ مستوى مقاومة محتمل عند ${fmt5(nearestPotRes.price)} (لمستان، ارتداد واحد) — بانتظار اللمسة الثالثة للتأكيد`;
    } else {
      // 🟡 Between levels — show context
      const supLabel = nearestSup    ? `${fmt5(nearestSup.price)} (${nearestSup.touches}x ✅)`
                     : nearestPotSup ? `${fmt5(nearestPotSup.price)} (2x ⚡ محتمل)`
                     : nearestWeakSup ? `${fmt5(nearestWeakSup.price)} (1x ضعيف)` : "—";
      const resLabel = nearestRes    ? `${fmt5(nearestRes.price)} (${nearestRes.touches}x ✅)`
                     : nearestPotRes ? `${fmt5(nearestPotRes.price)} (2x ⚡ محتمل)`
                     : nearestWeakRes ? `${fmt5(nearestWeakRes.price)} (1x ضعيف)` : "—";
      desc = `السعر بين مستويات | أقرب دعم: ${supLabel} | أقرب مقاومة: ${resLabel}`;
    }

    signals.push({
      id: "support_resistance", name: "دعم ومقاومة", emoji: "🏛️",
      signal: sig, strength: str, desc,
    });
  }

  // 8 — Stochastic: a %K/%D CROSS inside the oversold/overbought zone
  // (previously only the current state %K>%D was checked, not a cross).
  if (stoch) {
    let sig: "BUY" | "SELL" | "NEUTRAL" = "NEUTRAL";
    let str = 0;
    const prev = closes.length > 17 ? calcStochastic(closes.slice(0, -1), highs.slice(0, -1), lows.slice(0, -1)) : null;
    const crossUp = prev !== null && prev.k <= prev.d && stoch.k > stoch.d;
    const crossDn = prev !== null && prev.k >= prev.d && stoch.k < stoch.d;
    if (crossUp && stoch.k < 20) { sig = "BUY"; str = 82; }
    else if (crossDn && stoch.k > 80) { sig = "SELL"; str = 82; }
    else if (crossUp && stoch.k < 30) { sig = "BUY"; str = 65; }
    else if (crossDn && stoch.k > 70) { sig = "SELL"; str = 65; }
    signals.push({ id: "stochastic", name: "تقاطع Stochastic", emoji: "🔄",
      signal: sig, strength: str,
      desc: `%K=${stoch.k.toFixed(1)} %D=${stoch.d.toFixed(1)} — ${
        crossUp ? (stoch.k < 30 ? "تقاطع صاعد في منطقة ذروة البيع" : "تقاطع صاعد خارج منطقة ذروة البيع") :
        crossDn ? (stoch.k > 70 ? "تقاطع هابط في منطقة ذروة الشراء" : "تقاطع هابط خارج منطقة ذروة الشراء") :
        stoch.k < 20 ? "ذروة بيع (بلا تقاطع)" : stoch.k > 80 ? "ذروة شراء (بلا تقاطع)" : "لا تقاطع"
      }` });
  }

  // 9 — ADX Trend Strength Confirmation
  if (adx) {
    let sig: "BUY" | "SELL" | "NEUTRAL" = "NEUTRAL";
    let str = 0;
    if (adx.adx > 25 && adx.pdi > adx.mdi) { sig = "BUY"; str = Math.min(90, 55 + Math.round(adx.adx)); }
    else if (adx.adx > 25 && adx.mdi > adx.pdi) { sig = "SELL"; str = Math.min(90, 55 + Math.round(adx.adx)); }
    signals.push({ id: "adx_trend", name: "قوة الاتجاه ADX", emoji: "💪",
      signal: sig, strength: str,
      desc: `ADX=${adx.adx.toFixed(1)} | +DI=${adx.pdi.toFixed(1)} -DI=${adx.mdi.toFixed(1)} — ${
        adx.adx > 40 ? "اتجاه قوي جداً 🔥" : adx.adx > 25 ? "اتجاه واضح" : "سوق جانبي — لا إشارة"
      }` });
  }

  // 10 — Pivot Point Bounce
  if (pivots && pivots.basis !== "window") {
    const price = closes[closes.length - 1];
    const tolerance = atr * 0.3;
    let sig: "BUY" | "SELL" | "NEUTRAL" = "NEUTRAL";
    let str = 0;
    let desc = "";
    if (Math.abs(price - pivots.s1) < tolerance) { sig = "BUY"; str = 75; desc = `ارتداد من S1 (${fmtP(pivots.s1)})`; }
    else if (Math.abs(price - pivots.s2) < tolerance) { sig = "BUY"; str = 85; desc = `ارتداد من S2 (${fmtP(pivots.s2)}) — دعم قوي`; }
    else if (Math.abs(price - pivots.r1) < tolerance) { sig = "SELL"; str = 75; desc = `ارتداد من R1 (${fmtP(pivots.r1)})`; }
    else if (Math.abs(price - pivots.r2) < tolerance) { sig = "SELL"; str = 85; desc = `ارتداد من R2 (${fmtP(pivots.r2)}) — مقاومة قوية`; }
    else if (price > pivots.pivot) { desc = `فوق Pivot (${fmtP(pivots.pivot)}) — نطاق صعودي`; }
    else { desc = `تحت Pivot (${fmtP(pivots.pivot)}) — نطاق هبوطي`; }
    signals.push({ id: "pivot_bounce", name: "ارتداد Pivot", emoji: "📍",
      signal: sig, strength: str, desc });
  }

  // ═══════════ Price-Action layer (deterministic) ═══════════

  // Shared swing detection (fractal, 2 bars each side) — indices + values.
  const sw = 2;
  const swHi: { i: number; v: number }[] = [];
  const swLo: { i: number; v: number }[] = [];
  for (let i = sw; i < highs.length - sw; i++) {
    let isH = true, isL = true;
    for (let j = i - sw; j <= i + sw; j++) {
      if (j === i) continue;
      if (highs[j] >= highs[i]) isH = false;
      if (lows[j] <= lows[i]) isL = false;
    }
    if (isH) swHi.push({ i, v: highs[i] });
    if (isL) swLo.push({ i, v: lows[i] });
  }

  // 11 — Market Structure (BOS / CHoCH) — smart-money structure
  {
    let sig: "BUY" | "SELL" | "NEUTRAL" = "NEUTRAL";
    let str = 0;
    let desc = "لا تتوفر بيانات كافية لبنية السوق";
    if (swHi.length >= 2 && swLo.length >= 2) {
      const lastHi = swHi[swHi.length - 1], prevHi = swHi[swHi.length - 2];
      const lastLo = swLo[swLo.length - 1], prevLo = swLo[swLo.length - 2];
      const hh = lastHi.v > prevHi.v;   // higher high
      const hl = lastLo.v > prevLo.v;   // higher low
      const lh = lastHi.v < prevHi.v;   // lower high
      const ll = lastLo.v < prevLo.v;   // lower low
      const priorUp = hl || hh;          // prior bullish structure
      const priorDown = lh || ll;        // prior bearish structure
      if (price > lastHi.v && hl) {
        sig = "BUY"; str = 84;
        desc = `اختراق صعودي للبنية (BOS) فوق ${fmtP(lastHi.v)} مع قيعان صاعدة — استمرار صعودي`;
      } else if (price < lastLo.v && lh) {
        sig = "SELL"; str = 84;
        desc = `كسر هبوطي للبنية (BOS) تحت ${fmtP(lastLo.v)} مع قمم هابطة — استمرار هبوطي`;
      } else if (price > lastHi.v && priorDown) {
        sig = "BUY"; str = 70;
        desc = `تغيّر الطابع (CHoCH) صعودي — كسر آخر قمة بعد هيكل هابط — انعكاس محتمل للأعلى`;
      } else if (price < lastLo.v && priorUp) {
        sig = "SELL"; str = 70;
        desc = `تغيّر الطابع (CHoCH) هبوطي — كسر آخر قاع بعد هيكل صاعد — انعكاس محتمل للأسفل`;
      } else if (hh && hl) {
        sig = "BUY"; str = 55; desc = "بنية صاعدة (قمم وقيعان أعلى) — تحيّز شرائي";
      } else if (lh && ll) {
        sig = "SELL"; str = 55; desc = "بنية هابطة (قمم وقيعان أدنى) — تحيّز بيعي";
      } else {
        desc = "بنية متذبذبة/عرضية — لا اتجاه هيكلي واضح";
      }
    }
    signals.push({ id: "market_structure", name: "بنية السوق (BOS/CHoCH)", emoji: "🏗️", signal: sig, strength: str, desc });
  }

  // 12 — Fibonacci golden zone on the DOMINANT leg: the highest high and
  // lowest low of the last 60 bars (previously the last 2-bar fractals, i.e.
  // legs of a few pips, so price was "in the zone" almost every bar). The leg
  // must be ≥ 3×ATR to count as an impulse; a close beyond the 0.786 level
  // invalidates the setup.
  {
    let sig: "BUY" | "SELL" | "NEUTRAL" = "NEUTRAL";
    let str = 0;
    let desc = "لا يوجد اندفاع واضح لحساب فيبوناتشي";
    const look = Math.min(60, highs.length);
    const start = highs.length - look;
    let hiI = start, loI = start;
    for (let k = start; k < highs.length; k++) { if (highs[k] > highs[hiI]) hiI = k; if (lows[k] < lows[loI]) loI = k; }
    const hi = highs[hiI], lo = lows[loI], range = hi - lo;
    const up = loI < hiI;                          // low first, then high → bullish impulse
    const extremeIsCurrent = (up ? hiI : loI) >= n - 1; // still extending: nothing to retrace yet
    if (range > 0 && atr > 0 && range >= 3 * atr && !extremeIsCurrent) {
      const fib = (r: number) => (up ? hi - range * r : lo + range * r);
      const z382 = fib(0.382), z50 = fib(0.5), z618 = fib(0.618), z786 = fib(0.786);
      const inGolden = up ? price <= z50 && price >= z618 : price >= z50 && price <= z618;
      const nearGolden = Math.min(Math.abs(price - z50), Math.abs(price - z618)) <= 0.3 * atr;
      const invalid = up ? price < z786 : price > z786;
      if (!invalid && (inGolden || nearGolden)) {
        sig = up ? "BUY" : "SELL"; str = inGolden ? 78 : 66;
        desc = `تصحيح إلى المنطقة الذهبية لاندفاع ${up ? "صاعد" : "هابط"} (${fmtP(lo)}→${fmtP(hi)}): 0.5=${fmtP(z50)} · 0.618=${fmtP(z618)} — احتمال استمرار الاتجاه`;
      } else {
        desc = `اندفاع ${up ? "صاعد" : "هابط"} ${fmtP(lo)}→${fmtP(hi)} | 0.382=${fmtP(z382)} · 0.5=${fmtP(z50)} · 0.618=${fmtP(z618)}${invalid ? " — تجاوز 0.786 (الإعداد ملغى)" : ""}`;
      }
    } else if (range > 0 && extremeIsCurrent) {
      desc = "السعر عند طرف الاندفاع الحالي — لا تصحيح بعد";
    }
    signals.push({ id: "fibonacci", name: "فيبوناتشي (منطقة ذهبية)", emoji: "🌀", signal: sig, strength: str, desc });
  }

  // 13 — RSI Divergence (price vs momentum)
  {
    let sig: "BUY" | "SELL" | "NEUTRAL" = "NEUTRAL";
    let str = 0;
    let desc = "لا يوجد دايفرجنس واضح على RSI";
    const rsiAt = (idx: number): number | null => {
      if (idx < 15) return null;
      return calcRSI(closes.slice(0, idx + 1), 14);
    };
    // The second swing must be recent (≤ 15 bars ago) and the two swings
    // 5–60 bars apart — otherwise the "divergence" is stale or meaningless.
    const valid = (a: { i: number }, b: { i: number }) => n - b.i <= 15 && b.i - a.i >= 5 && b.i - a.i <= 60;
    if (swHi.length >= 2) {
      const a = swHi[swHi.length - 2], b = swHi[swHi.length - 1];
      const ra = rsiAt(a.i), rb = rsiAt(b.i);
      if (valid(a, b) && ra !== null && rb !== null && b.v > a.v && rb < ra - 2) {
        sig = "SELL"; str = 83;
        desc = `دايفرجنس هبوطي: قمة سعرية أعلى (${fmtP(a.v)}→${fmtP(b.v)}) مقابل RSI أدنى (${ra.toFixed(1)}→${rb.toFixed(1)}) — ضعف زخم صاعد`;
      }
    }
    if (sig === "NEUTRAL" && swLo.length >= 2) {
      const a = swLo[swLo.length - 2], b = swLo[swLo.length - 1];
      const ra = rsiAt(a.i), rb = rsiAt(b.i);
      if (valid(a, b) && ra !== null && rb !== null && b.v < a.v && rb > ra + 2) {
        sig = "BUY"; str = 83;
        desc = `دايفرجنس صعودي: قاع سعري أدنى (${fmtP(a.v)}→${fmtP(b.v)}) مقابل RSI أعلى (${ra.toFixed(1)}→${rb.toFixed(1)}) — ضعف زخم هابط`;
      }
    }
    signals.push({ id: "rsi_divergence", name: "دايفرجنس RSI", emoji: "🔀", signal: sig, strength: str, desc });
  }

  // 14 — Candlestick Pattern (engulfing / pin bar) — needs opens
  if (opens && opens.length === closes.length && closes.length >= 2) {
    let sig: "BUY" | "SELL" | "NEUTRAL" = "NEUTRAL";
    let str = 0;
    let desc = "لا يوجد نموذج شمعة انعكاسي واضح";
    const o = opens[n], c = closes[n], h = highs[n], l = lows[n];
    // Reversal patterns only mean something after a move INTO them: the 3 bars
    // before the pattern must have declined (bullish) / risen (bearish).
    const priorDecline = n >= 4 && closes[n - 1] < closes[n - 4];
    const priorRise = n >= 4 && closes[n - 1] > closes[n - 4];
    const po = opens[n - 1], pc = closes[n - 1];
    const body = Math.abs(c - o), range = (h - l) || 1e-9;
    const upperWick = h - Math.max(o, c), lowerWick = Math.min(o, c) - l;
    // Bullish/bearish engulfing
    if (priorDecline && c > o && pc < po && c >= po && o <= pc) { sig = "BUY"; str = 78; desc = "ابتلاع شرائي (Bullish Engulfing) بعد هبوط — انعكاس صعودي"; }
    else if (priorRise && c < o && pc > po && c <= po && o >= pc) { sig = "SELL"; str = 78; desc = "ابتلاع بيعي (Bearish Engulfing) بعد صعود — انعكاس هبوطي"; }
    // Pin bars (hammer after a decline / shooting star after a rise)
    else if (priorDecline && lowerWick > body * 2 && upperWick < body && body / range < 0.4) { sig = "BUY"; str = 70; desc = "شمعة مطرقة (Hammer) بعد هبوط — رفض للأسعار المنخفضة"; }
    else if (priorRise && upperWick > body * 2 && lowerWick < body && body / range < 0.4) { sig = "SELL"; str = 70; desc = "شمعة نجمة ساقطة (Shooting Star) بعد صعود — رفض للأسعار المرتفعة"; }
    // Confluence with S/R proximity boosts strength (structure levels)
    signals.push({ id: "candlestick", name: "نماذج الشموع", emoji: "🕯️", signal: sig, strength: str, desc });
  }

  // 15 — Momentum (Rate of Change)
  {
    let sig: "BUY" | "SELL" | "NEUTRAL" = "NEUTRAL";
    let str = 0;
    const look = Math.min(10, closes.length - 1);
    const roc = look > 0 ? (price - closes[closes.length - 1 - look]) / closes[closes.length - 1 - look] * 100 : 0;
    // Move over `look` bars in ATRs: > 2.8 ATR ≈ the strongest 15% of moves.
    const rocAtr = look > 0 && atr > 0 ? (price - closes[closes.length - 1 - look]) / atr : 0;
    if (rocAtr > 2.8) { sig = "BUY"; str = Math.min(85, 55 + Math.round((rocAtr - 2.8) * 10)); }
    else if (rocAtr < -2.8) { sig = "SELL"; str = Math.min(85, 55 + Math.round((Math.abs(rocAtr) - 2.8) * 10)); }
    signals.push({ id: "momentum_roc", name: "الزخم (ROC)", emoji: "🚀", signal: sig, strength: str,
      desc: `معدّل التغيّر خلال ${look} شمعة: ${roc >= 0 ? "+" : ""}${roc.toFixed(3)}% — ${
        rocAtr > 2.8 ? "زخم صاعد" : rocAtr < -2.8 ? "زخم هابط" : "زخم ضعيف/محايد"
      }` });
  }

  // 16 — POC / Volume Profile (Point of Control + 70% Value Area, last 100 bars)
  //   • Pullback to the POC from above with a bullish close in an up-leaning
  //     market → BUY (the POC acts as support); mirror for SELL.
  //   • Fresh acceptance outside the Value Area (close breaks VAH/VAL after
  //     closing inside it) → trade the breakout.
  {
    let sig: "BUY" | "SELL" | "NEUTRAL" = "NEUTRAL";
    let str = 0;
    let desc = "بيانات غير كافية لملف الحجم";
    const vp = calcVolumeProfile(highs, lows, closes, volumes, 100, 30);
    if (vp && atr > 0) {
      const kind = vp.source === "volume" ? "حجم" : "زمن-سعر (TPO)";
      desc = `POC ${fmtP(vp.poc)} | منطقة القيمة ${fmtP(vp.val)}–${fmtP(vp.vah)} (${kind})`;
      const k = Math.min(10, n);
      let avg = 0; for (let i = n - k + 1; i <= n; i++) avg += closes[i]; avg /= k;
      const lowN = lows[n], highN = highs[n], openN = opens?.[n] ?? prevPrice;
      const nearPoc = Math.abs(price - vp.poc) <= 0.35 * atr;
      if (prevPrice <= vp.vah && price > vp.vah) {
        sig = "BUY"; str = 65; desc += " — إغلاق فوق أعلى منطقة القيمة (قبول سعري صاعد)";
      } else if (prevPrice >= vp.val && price < vp.val) {
        sig = "SELL"; str = 65; desc += " — إغلاق تحت أدنى منطقة القيمة (قبول سعري هابط)";
      } else if (nearPoc && avg > vp.poc && lowN <= vp.poc + 0.1 * atr && price > openN && price >= vp.poc) {
        sig = "BUY"; str = 70; desc += " — ارتداد صاعد من POC كدعم";
      } else if (nearPoc && avg < vp.poc && highN >= vp.poc - 0.1 * atr && price < openN && price <= vp.poc) {
        sig = "SELL"; str = 70; desc += " — ارتداد هابط من POC كمقاومة";
      } else {
        desc += price > vp.vah ? " — السعر فوق منطقة القيمة" : price < vp.val ? " — السعر تحت منطقة القيمة" : " — السعر داخل منطقة القيمة";
      }
    }
    signals.push({ id: "poc", name: "نقطة التحكم POC (ملف الحجم)", emoji: "🎚️", signal: sig, strength: str, desc });
  }

  return signals;
}

// ─── Filter Calculators ───────────────────────────────────────────────
function calcFilters(
  price: number, sma20: number, sma50: number, sma200: number | null,
  rsi: number, atr: number, closes: number[],
  opts: { market24x7?: boolean; highs?: number[]; lows?: number[] } = {},
): FilterResult[] {
  const filters: FilterResult[] = [];

  // 1 — Major Trend Filter
  {
    const ref = sma200 || sma50;
    const bull = price > ref;
    filters.push({ id: "trend_filter", name: "الاتجاه الرئيسي", emoji: "🧭",
      passed: true, allowsBuy: bull, allowsSell: !bull,
      desc: bull
        ? `📈 اتجاه صاعد (السعر فوق ${sma200 ? "SMA200" : "SMA50"}) — الشراء مع الاتجاه، والبيع عكسه`
        : `📉 اتجاه هابط (السعر تحت ${sma200 ? "SMA200" : "SMA50"}) — البيع مع الاتجاه، والشراء عكسه` });
  }

  // 2 — Volatility regime: current volatility vs its OWN long-run average
  // (ATR14 / mean true range over the last 100 bars). Previously ATR was divided
  // by the mean close-to-close move of the same 20 bars — two measures of the
  // same thing, so the ratio was ~1.5 regardless of the regime.
  {
    let cur: number, base: number;
    if (opts.highs && opts.lows && opts.highs.length === closes.length) {
      const trs = trueRanges(opts.highs, opts.lows, closes);
      cur = atr;
      const tail = trs.slice(-100);
      base = tail.reduce((x, y) => x + y, 0) / (tail.length || 1);
    } else {
      const moves = closes.slice(1).map((c, i) => Math.abs(c - closes[i]));
      const avg = (a: number[]) => a.reduce((x, y) => x + y, 0) / (a.length || 1);
      cur = avg(moves.slice(-14)); base = avg(moves.slice(-100));
    }
    const ratio = base > 0 ? cur / base : 1;
    const high = ratio > 2.0;
    const low  = ratio < 0.5;
    filters.push({ id: "volatility_filter", name: "فلتر التقلب", emoji: "📉",
      passed: !high, allowsBuy: !high, allowsSell: !high,
      desc: high ? `⚠️ تقلب مفرط (${ratio.toFixed(2)}x المعدل) — خطر عالٍ` :
            low  ? `😴 تقلب منخفض جداً (${ratio.toFixed(2)}x المعدل) — سوق راكد` :
            `✅ تقلب طبيعي (${ratio.toFixed(2)}x المعدل)` });
  }

  // 3 — RSI Confirmation Filter
  {
    const buyOk  = rsi < 65;
    const sellOk = rsi > 35;
    filters.push({ id: "rsi_filter", name: "تأكيد RSI", emoji: "📡",
      passed: true, allowsBuy: buyOk, allowsSell: sellOk,
      desc: `RSI = ${rsi.toFixed(1)} — ${buyOk && sellOk ? "يسمح بكلا الاتجاهين" : buyOk ? "✅ يدعم الشراء فقط" : "✅ يدعم البيع فقط"}` });
  }

  // 4 — Session Filter (UTC) — FX sessions don't apply to 24/7 crypto markets
  if (opts.market24x7) {
    filters.push({ id: "session_filter", name: "فلتر الجلسة", emoji: "🕐",
      passed: true, allowsBuy: true, allowsSell: true,
      desc: "سوق يعمل 24/7 — فلتر جلسات الفوركس لا ينطبق" });
  } else {
    const h = new Date().getUTCHours();
    const overlap  = h >= 13 && h < 16;
    const london   = h >= 8  && h < 16;
    const newYork  = h >= 13 && h < 21;
    const asian    = h >= 0  && h < 8;
    const active   = london || newYork;
    const session  = overlap ? "تداخل London/NY 🔥" : london ? "جلسة London 🇬🇧" : newYork ? "جلسة New York 🇺🇸" : asian ? "جلسة آسيا 🌏" : "بين الجلسات";
    filters.push({ id: "session_filter", name: "فلتر الجلسة", emoji: "🕐",
      passed: active, allowsBuy: active, allowsSell: active,
      desc: `${session} — UTC ${String(h).padStart(2, "0")}:${String(new Date().getUTCMinutes()).padStart(2, "0")} ${active ? "✅ جلسة نشطة" : "⚠️ خارج الجلسات الرئيسية"}` });
  }

  return filters;
}

export {
  calcSMA, calcEMA, calcRSI, calcMACD, calcBB, calcATR, calcStochastic,
  calcWilliamsR, calcPivotPoints, calcADX, calcStrategies, calcFilters,
  spreadCostPct, TYPICAL_SPREAD, toUtcMs,
};
export type { StrategySignal, FilterResult };

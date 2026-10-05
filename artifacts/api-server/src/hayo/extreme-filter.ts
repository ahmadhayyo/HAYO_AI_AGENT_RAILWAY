/**
 * "Fresh extreme without a reversal line" filter for the 1-minute weights
 * (convergence) signals — from the owner's live observation, confirmed on
 * OANDA 1m data (6 instruments, grade A, 10-bar expiry):
 *   all signals                                   59.1% (2018) / 54.1% (2019)
 *   after blocking fresh extremes w/o a line      63.8%        / 56.2%
 * A BUY whose last 3 candles made the lowest low of the previous 500 candles,
 * with fewer than 2 confirmed swing lows (±10 candles) within 0.5 ATR of it,
 * is price falling into "empty" territory (no historical support) → blocked.
 * Mirror for SELL at a fresh high. Not applied to the 5m model (no gain there).
 */
export interface FilterBar { high: number; low: number; close: number }
export interface ExtremeCheck { fresh: boolean; touches: number; blocked: boolean }

export function freshExtremeNoLine(bars: FilterBar[], dir: "BUY" | "SELL", lookback = 500, swingW = 10, tolAtr = 0.5, minTouches = 2): ExtremeCheck {
  const i = bars.length - 1;
  const lb = Math.min(lookback, i - swingW - 20);
  if (lb < 100) return { fresh: false, touches: 0, blocked: false };   // not enough history: never block
  const buy = dir === "BUY";
  let atr = 0;
  for (let q = i - 13; q <= i; q++) {
    const b = bars[q], p = bars[q - 1];
    atr += Math.max(b.high - b.low, Math.abs(b.high - p.close), Math.abs(b.low - p.close));
  }
  atr /= 14;
  let ext = buy ? Infinity : -Infinity;
  for (let q = i - lb; q < i; q++) ext = buy ? Math.min(ext, bars[q].low) : Math.max(ext, bars[q].high);
  const cur = buy ? Math.min(bars[i].low, bars[i - 1].low, bars[i - 2].low) : Math.max(bars[i].high, bars[i - 1].high, bars[i - 2].high);
  const fresh = buy ? cur <= ext : cur >= ext;
  let touches = 0;
  for (let q = i - lb; q <= i - swingW - 1; q++) {
    let swing = true;
    for (let j = q - swingW; j <= q + swingW && swing; j++) {
      if (j === q) continue;
      if (buy ? bars[j].low < bars[q].low : bars[j].high > bars[q].high) swing = false;
    }
    if (!swing) continue;
    const lvl = buy ? bars[q].low : bars[q].high;
    if (Math.abs(lvl - cur) <= tolAtr * atr) touches++;
  }
  return { fresh, touches, blocked: fresh && touches < minTouches };
}

/**
 * Trend-alignment ("anti-knife") gate for the 1-minute weights (convergence)
 * signals — from the owner's live losses (counter-trend reversion in a collapse
 * chart), confirmed on OANDA 1m (6 instruments, grade B, 10-bar expiry, OOS 2019):
 *   all grade-B signals                               54.9%
 *   trend-aligned only (dir == 15m trend)             58.9%
 *   counter-trend                                     53.1%
 *   counter-trend in a STRONG 15m regime (ER>0.4)     46.9%  ← systematic loser
 * Trend on 15m = price vs SMA200 (SMA50 fallback), the server's own trend_filter.
 * Efficiency ratio (ER) = |net move| / |path| over the last `erBars` 15m bars;
 * high ER = a clean directional trend (a collapse/run), where catching the
 * reverse is a falling knife.
 *   mode "regime" (default): block counter-trend only when ER >= erMin.
 *   mode "strict": block every counter-trend signal (trade with the trend only).
 *   mode "off": never block.
 */
export type TrendGateMode = "off" | "regime" | "strict";
export interface TrendGateCheck { trendUp: boolean | null; counter: boolean; er: number; blocked: boolean }

export function trendMisaligned(
  closes15: number[], dir: "BUY" | "SELL",
  mode: TrendGateMode = "regime", erMin = 0.3, erBars = 30,
): TrendGateCheck {
  const n = closes15.length;
  if (mode === "off" || n < 60) return { trendUp: null, counter: false, er: 0, blocked: false };
  const period = n >= 200 ? 200 : 50;
  let s = 0; for (let i = n - period; i < n; i++) s += closes15[i];
  const ma = s / period;
  const price = closes15[n - 1];
  const trendUp = price > ma;
  const counter = dir === "BUY" ? !trendUp : trendUp;
  const lb = Math.min(erBars, n - 1);
  let path = 0; for (let i = n - lb; i < n; i++) path += Math.abs(closes15[i] - closes15[i - 1]);
  const er = path > 0 ? Math.abs(price - closes15[n - 1 - lb]) / path : 0;
  const blocked = counter && (mode === "strict" || er >= erMin);
  return { trendUp, counter, er, blocked };
}

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

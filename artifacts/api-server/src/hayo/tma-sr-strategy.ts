/**
 * Causal server-side port of the signal path in TMA_SR_Confluence.mq4.
 *
 * Arrow rule: price first arms beyond a TMA band, then the same direction is
 * emitted only when the candle touches an active multi-timeframe S/R level and
 * the EMA/ADX mode allows it. The source's centered TMA uses the forming candle
 * when evaluating the last closed bar; this port intentionally uses only closed
 * candles so an alert cannot depend on a value that may repaint intrabar.
 */
export interface TmaSrBar { open: number; high: number; low: number; close: number; time?: number }
export interface TmaSrEvent { dir: "BUY" | "SELL"; band: number; level: number; levelType: "horizontal" | "trend"; adx: number; barsArmed: number }

const HALF_LENGTH = 20;
const BAND_DEVIATIONS = 1.85;
const SIGNAL_MODE = 2;
const EMA_PERIOD = 50;
const ADX_PERIOD = 10;
const ADX_MIN = 20;
const SR_TOL_ATR = 0.5;
const COOLDOWN_BARS = 20;
function atrWilderLast(bars: TmaSrBar[], period: number): number {
  if (bars.length < period + 1) return 0;
  const trv: number[] = [];
  for (let i = 1; i < bars.length; i++) trv.push(tr(bars[i], bars[i - 1].close));
  let v = trv.slice(0, period).reduce((a, x) => a + x, 0) / period;
  for (let i = period; i < trv.length; i++) v = (v * (period - 1) + trv[i]) / period;
  return v;
}

function reverse<T>(a: T[]): T[] { return [...a].reverse(); }
function tr(b: TmaSrBar, prevClose: number): number { return Math.max(b.high - b.low, Math.abs(b.high - prevClose), Math.abs(b.low - prevClose)); }
function atrSeries(bars: TmaSrBar[], period = 14): number[] {
  const out = new Array<number>(bars.length).fill(0);
  for (let i = 0; i < bars.length; i++) {
    const vals: number[] = [];
    for (let j = Math.max(0, i - period + 1); j <= i; j++) vals.push(tr(bars[j], j ? bars[j - 1].close : bars[j].close));
    out[i] = vals.reduce((a, v) => a + v, 0) / Math.max(1, vals.length);
  }
  return out;
}
function emaSeries(values: number[], period: number): number[] {
  if (!values.length) return [];
  const k = 2 / (period + 1), out = new Array<number>(values.length);
  out[0] = values[0];
  for (let i = 1; i < values.length; i++) out[i] = values[i] * k + out[i - 1] * (1 - k);
  return out;
}
function adxLast(bars: TmaSrBar[], period: number): number {
  if (bars.length < period * 2 + 1) return 0;
  const trv: number[] = [], pdm: number[] = [], mdm: number[] = [];
  for (let i = 1; i < bars.length; i++) {
    const up = bars[i].high - bars[i - 1].high, down = bars[i - 1].low - bars[i].low;
    pdm.push(up > down && up > 0 ? up : 0); mdm.push(down > up && down > 0 ? down : 0);
    trv.push(tr(bars[i], bars[i - 1].close));
  }
  let str = trv.slice(0, period).reduce((a, v) => a + v, 0);
  let sp = pdm.slice(0, period).reduce((a, v) => a + v, 0);
  let sm = mdm.slice(0, period).reduce((a, v) => a + v, 0);
  const dx: number[] = [];
  for (let i = period - 1; i < trv.length; i++) {
    if (i >= period) { str = str - str / period + trv[i]; sp = sp - sp / period + pdm[i]; sm = sm - sm / period + mdm[i]; }
    const p = str > 0 ? sp / str * 100 : 0, m = str > 0 ? sm / str * 100 : 0;
    dx.push(p + m > 0 ? Math.abs(p - m) / (p + m) * 100 : 0);
  }
  if (dx.length < period) return dx[dx.length - 1] ?? 0;
  let adx = dx.slice(0, period).reduce((a, v) => a + v, 0) / period;
  for (let i = period; i < dx.length; i++) adx = (adx * (period - 1) + dx[i]) / period;
  return adx;
}

/** Causal triangular center and asymmetric variance bands, closed candles only. */
function tmaBands(bars: TmaSrBar[]): { mid: number[]; upper: number[]; lower: number[] } {
  const n = bars.length, mid = new Array<number>(n).fill(0), upper = new Array<number>(n).fill(0), lower = new Array<number>(n).fill(0);
  const full = 2 * HALF_LENGTH + 1;
  const wu = new Array<number>(n).fill(0), wd = new Array<number>(n).fill(0);
  for (let i = 0; i < n; i++) {
    let sum = (HALF_LENGTH + 1) * ((bars[i].high + bars[i].low + 2 * bars[i].close) / 4), sw = HALF_LENGTH + 1;
    for (let j = 1; j <= HALF_LENGTH && i - j >= 0; j++) {
      const w = HALF_LENGTH + 1 - j, b = bars[i - j];
      sum += w * ((b.high + b.low + 2 * b.close) / 4); sw += w;
    }
    mid[i] = sum / sw;
    const p = (bars[i].high + bars[i].low + 2 * bars[i].close) / 4, d = p - mid[i];
    if (i === 0) { wu[i] = d >= 0 ? d * d : 0; wd[i] = d < 0 ? d * d : 0; }
    else {
      wu[i] = d >= 0 ? (wu[i - 1] * (full - 1) + d * d) / full : wu[i - 1] * (full - 1) / full;
      wd[i] = d < 0 ? (wd[i - 1] * (full - 1) + d * d) / full : wd[i - 1] * (full - 1) / full;
    }
    upper[i] = mid[i] + BAND_DEVIATIONS * Math.sqrt(wu[i]);
    lower[i] = mid[i] - BAND_DEVIATIONS * Math.sqrt(wd[i]);
  }
  return { mid, upper, lower };
}

interface Pivot { p: number; t: number; tf: number; high: boolean; w: number }
function pivots(bars: TmaSrBar[], tf: number, kAtr: number, now: number): { ps: Pivot[]; atr: number } {
  const s = reverse(bars), atrs = atrSeries(s), atr = atrs[atrs.length - 1] ?? 0, thr = kAtr * atr, ps: Pivot[] = [];
  if (s.length < 16 || !(thr > 0)) return { ps, atr };
  const start = s.length - 1; let dir = 0, hi = s[start].high, lo = s[start].low, hiIdx = start, loIdx = start;
  const add = (idx: number, high: boolean) => {
    const b = s[idx], age = Math.max(0, (now - (b.time ?? now)) / 60000), decay = Math.pow(0.5, age / 600);
    const range = b.high - b.low, wick = range > 0 ? (high ? b.high - Math.max(b.open, b.close) : Math.min(b.open, b.close) - b.low) / range : 0;
    ps.push({ p: high ? b.high : b.low, t: b.time ?? now, tf, high, w: decay * (0.6 + 0.4 * wick) });
  };
  for (let i = start - 1; i >= 0; i--) {
    const b = s[i];
    if (dir === 0) {
      if (b.high > hi) { hi = b.high; hiIdx = i; }
      if (b.low < lo) { lo = b.low; loIdx = i; }
      if (hi - lo >= thr) { if (hiIdx > loIdx) { add(hiIdx, true); dir = -1; } else if (loIdx > hiIdx) { add(loIdx, false); dir = 1; } }
    } else if (dir > 0) {
      if (b.high > hi) { hi = b.high; hiIdx = i; }
      else if (hi - b.low >= thr) { add(hiIdx, true); dir = -1; lo = b.low; loIdx = i; }
    } else {
      if (b.low < lo) { lo = b.low; loIdx = i; }
      else if (b.high - lo >= thr) { add(loIdx, false); dir = 1; hi = b.high; hiIdx = i; }
    }
  }
  return { ps, atr };
}

/** Current chart S/R candidate levels from the indicator's weighted MTF pivots. */
function horizontalLevels(m1: TmaSrBar[], m5: TmaSrBar[], m15: TmaSrBar[], px: number, now: number): number[] {
  const sets = [pivots(m1, 0, 1.5, now), pivots(m5, 1, 1.2, now), pivots(m15, 2, 1.0, now)];
  let avail = 0; for (let f = 0; f < 3; f++) if (sets[f].atr > 0 && (f === 0 ? m1.length >= 60 : f === 1 ? m5.length >= 12 : m15.length >= 8) && sets[f].ps.length >= 2) avail |= 1 << f;
  if ([0, 1, 2].filter(f => (avail & (1 << f)) !== 0).length < 2) return [];
  const a5 = sets[1].atr || sets[0].atr * 2.2, a15 = sets[2].atr || a5 * 1.7;
  const all = sets.flatMap(x => x.ps), tol = 0.3 * a5, hw = tol;
  if (all.length < 8 || !(hw > 0)) return [];
  const nW = [0, 0, 0]; for (const p of all) nW[p.tf] += p.w;
  const used = new Set<number>(), levels: { p: number; tier: number; score: number }[] = [];
  const cover = (f: number, center: number) => {
    const bs = [m1, m5, m15][f]; let total = 0;
    for (let j = 0; j < 9; j++) { const x = center - hw + 2 * hw * j / 8; for (const b of bs) if (b.low <= x && b.high >= x) total++; }
    return total / 9;
  };
  const tfw = [1, 2, 3];
  for (let iter = 0; iter < 48; iter++) {
    let bi = -1, bw = 0;
    for (let a = 0; a < all.length; a++) {
      if (used.has(a)) continue;
      let w = 0; for (let b = 0; b < all.length; b++) if (!used.has(b) && Math.abs(all[b].p - all[a].p) <= hw) w += all[b].w * tfw[all[b].tf];
      if (w > bw) { bw = w; bi = a; }
    }
    if (bi < 0) break;
    let sw = 0, sp = 0;
    for (let b = 0; b < all.length; b++) if (!used.has(b) && Math.abs(all[b].p - all[bi].p) <= hw) { const w = all[b].w * tfw[all[b].tf]; sw += w; sp += w * all[b].p; }
    if (!(sw > 0)) { used.add(bi); continue; }
    const center = sp / sw, cnt = [0, 0, 0], ws = [0, 0, 0];
    for (let b = 0; b < all.length; b++) if (!used.has(b) && Math.abs(all[b].p - center) <= hw) { used.add(b); cnt[all[b].tf]++; ws[all[b].tf] += all[b].w; }
    let mask = 0, score = 0;
    for (let f = 0; f < 3; f++) if (cnt[f]) {
      mask |= 1 << f;
      if (sets[f].atr > 0) {
        const frameBars = [m1, m5, m15][f], area = frameBars.reduce((a, x) => a + x.high - x.low, 0);
        const e = area > 0 ? nW[f] * cover(f, center) * 2 * hw / area : 0;
        score += tfw[f] * Math.max(0, Math.min(4, (ws[f] - e) / Math.sqrt(e + 0.5)));
      }
    }
    const full = ((mask & avail) === avail) && [0, 1, 2].filter(f => (avail & (1 << f)) !== 0).length >= 2;
    if (full && score >= 2 && Math.abs(center - px) <= 4 * a15) levels.push({ p: center, tier: score >= 9 ? 3 : 2, score });
  }
  levels.sort((a, b) => b.tier - a.tier || b.score - a.score);
  const chosen: number[] = [];
  for (const l of levels) {
    if (chosen.filter(x => x > px).length >= 3 && l.p > px) continue;
    if (chosen.filter(x => x < px).length >= 3 && l.p < px) continue;
    if (chosen.some(x => Math.abs(x - l.p) <= hw)) continue;
    chosen.push(l.p);
  }
  return chosen;
}

/** Trendline support/resistance candidates (M5/M15 pivots, 3+ distinct touches). */
function trendLevels(m1: TmaSrBar[], m5: TmaSrBar[], m15: TmaSrBar[], px: number, now: number): number[] {
  const sets = [pivots(m1, 0, 1.5, now), pivots(m5, 1, 1.2, now), pivots(m15, 2, 1.0, now)];
  let avail = 0; for (let f = 0; f < 3; f++) if (sets[f].atr > 0 && (f === 0 ? m1.length >= 60 : f === 1 ? m5.length >= 12 : m15.length >= 8) && sets[f].ps.length >= 2) avail |= 1 << f;
  const availBits = [0, 1, 2].filter(f => avail & (1 << f)).length;
  if (availBits < 2) return [];
  const all = sets.flatMap(x => x.ps), atr15 = sets[2].atr || (sets[1].atr || sets[0].atr * 2.2) * 1.7;
  const atr5 = sets[1].atr || sets[0].atr * 2.2;
  if (all.length < 8 || !(atr15 > 0 && atr5 > 0)) return [];
  const tol = 0.3 * atr5, tolW = 1.5 * tol, tolC = 0.25 * tol;
  const candidates: { level: number; type: "support" | "resistance"; touches: number; rank: number }[] = [];
  for (const highSide of [true, false]) {
    const want = highSide, type = highSide ? "resistance" : "support";
    for (const tf of [1, 2]) {
      const anchors = sets[tf].ps.filter(p => p.high === want).slice(-6);
      for (let a = 0; a < anchors.length; a++) for (let b = a + 1; b < anchors.length; b++) {
        const p1 = anchors[a], p2 = anchors[b], span = (p2.t - p1.t) / 60000;
        if (span < 90) continue;
        const slope = (p2.p - p1.p) / ((p2.t - p1.t) / 1000), slopeHour = slope * 3600;
        if (Math.abs(slopeHour) < 0.1 * atr15 || Math.abs(slopeHour) > 2.5 * atr15) continue;
        const lineAt = (t: number) => p1.p + slope * (t - p1.t);
        let violations = 0, bad = false, ext = 0;
        for (const c of m1) {
          if (!c.time || c.time < p1.t || c.time > now) continue;
          const lp = lineAt(c.time);
          if (!highSide) {
            if (c.close < lp - tolC) { bad = true; break; }
            if (c.low < lp - tolW && ++violations > 2) { bad = true; break; }
            ext = Math.max(ext, c.high - lp);
          } else {
            if (c.close > lp + tolC) { bad = true; break; }
            if (c.high > lp + tolW && ++violations > 2) { bad = true; break; }
            ext = Math.max(ext, lp - c.low);
          }
        }
        if (bad) continue;
        const level = lineAt(now);
        if (Math.abs(level - px) > 4 * atr15 || (highSide && px > level + tol) || (!highSide && px < level - tol)) continue;
        const touched = new Set<number>(); let mask = 0, lastTouch = 0;
        for (const p of all) {
          if (p.high !== want || p.t < p1.t - 120_000 || Math.abs(p.p - lineAt(p.t)) > tol) continue;
          const bucket = Math.floor(p.t / 300_000);
          if (touched.has(bucket)) continue;
          touched.add(bucket); mask |= 1 << p.tf; lastTouch = Math.max(lastTouch, p.t);
        }
        const touches = touched.size, spanBars = span;
        if (touches < 4 || (mask & avail) !== avail || (now - lastTouch) / 60000 > 720) continue;
        const rank = (touches >= 6 && spanBars >= 180 ? 3 : 2) * 100 + 2 * touches + ([1, 2, 4].filter(x => mask & x).length) + Math.min(span / 60, 10) / 5;
        candidates.push({ level, type, touches, rank });
      }
    }
  }
  candidates.sort((a, b) => b.rank - a.rank);
  const result: number[] = [];
  for (const c of candidates) {
    if (result.filter(x => (x > px) === (c.type === "resistance")).length >= 2) continue;
    if (result.some(x => Math.abs(x - c.level) <= tol)) continue;
    result.push(c.level);
  }
  return result;
}

/** Returns an event only when the newest closed bar satisfies this engine. */
export function lastBarTmaSrSignal(chartBars: TmaSrBar[], srM1: TmaSrBar[], srM5: TmaSrBar[], srM15: TmaSrBar[]): TmaSrEvent | null {
  if (chartBars.length < 100 || srM1.length < 60 || srM5.length < 16 || srM15.length < 16) return null;
  const b = chartBars[chartBars.length - 1];
  if (!b) return null;
  const bands = tmaBands(chartBars), i = chartBars.length - 1, atr = atrWilderLast(chartBars, 14);
  if (!(bands.upper[i] > 0 && bands.lower[i] > 0 && atr > 0)) return null;
  const closes = chartBars.map(x => x.close), emaValues = emaSeries(closes, EMA_PERIOD), ema = emaValues[emaValues.length - 1] ?? 0, adx = adxLast(chartBars, ADX_PERIOD);
  const up = b.close > ema, down = b.close < ema, trending = adx > ADX_MIN;
  const allowBuy = SIGNAL_MODE === 0 || (SIGNAL_MODE === 1 ? up : (!trending || up));
  const allowSell = SIGNAL_MODE === 0 || (SIGNAL_MODE === 1 ? down : (!trending || down));
  const levels = horizontalLevels(srM1, srM5, srM15, b.close, b.time ?? Date.now());
  const tol = SR_TOL_ATR * atr;
  const tLevels = trendLevels(srM1, srM5, srM15, b.close, b.time ?? Date.now());
  const supportLevel = levels.find(l => l < b.close && b.low <= l + tol) ?? tLevels.find(l => l < b.close && b.low <= l + tol);
  const resistanceLevel = levels.find(l => l > b.close && b.high >= l - tol) ?? tLevels.find(l => l > b.close && b.high >= l - tol);
  const support = supportLevel !== undefined;
  const resistance = resistanceLevel !== undefined;
  // Reconstruct the current armed state from closed candles. The source arms on
  // an excursion beyond a band and resets when price closes across the center.
  let armedBuy = false, armedSell = false, latestBuyArm = -1, latestSellArm = -1;
  const start = Math.max(0, i - 300);
  for (let k = start; k <= i; k++) {
    if (chartBars[k].close < bands.mid[k]) { armedSell = false; latestSellArm = -1; }
    if (chartBars[k].close > bands.mid[k]) { armedBuy = false; latestBuyArm = -1; }
    if (chartBars[k].high > bands.upper[k]) { armedSell = true; latestSellArm = k; }
    if (chartBars[k].low < bands.lower[k]) { armedBuy = true; latestBuyArm = k; }
  }
  if (armedSell && allowSell && resistance && latestSellArm >= i - COOLDOWN_BARS) return { dir: "SELL", band: bands.upper[i], level: resistanceLevel!, levelType: levels.includes(resistanceLevel!) ? "horizontal" : "trend", adx, barsArmed: i - latestSellArm };
  if (armedBuy && allowBuy && support && latestBuyArm >= i - COOLDOWN_BARS) return { dir: "BUY", band: bands.lower[i], level: supportLevel!, levelType: levels.includes(supportLevel!) ? "horizontal" : "trend", adx, barsArmed: i - latestBuyArm };
  return null;
}


/**
 * LIQUIDITY TRAP — port of "FX AI SMC Fusion v27.0" (Ahmad Hayo), Breaker-box
 * engine + Value Chart. When a Breaker-box ENTRY candle is already stretched
 * far beyond its 5-bar value (Value Chart ≥ 8) it is the late-comers' candle
 * (= liquidity): the signal is its REVERSE.
 *
 * Evidence (OANDA 1-minute, 6 instruments, HZ filter OFF, entry = next open):
 *   trap alone      1m: 54.1% (2018) / 54.8% (2019) over 10 bars
 *   trap + weights model agreeing (p ≥ 0.53): 55.7% / 55.8%
 * The box / sensor / counter signals of the same indicator were ~47–51% with
 * or without HZ, so only the trap is used. HZ halved the trap count without
 * improving it, so it is not applied.
 *
 * Input: OLDEST-FIRST closed bars. Internally uses MT4 series indexing
 * (0 = newest) so the logic reads line-for-line like the MQL4 source.
 */
export interface TrapBar { open: number; high: number; low: number; close: number }
export interface TrapEvent {
  index: number;                 // oldest-first index of the signal bar
  dir: "BUY" | "SELL";           // trade direction (the reverse of the box entry)
  vc: number;                    // Value Chart of the entry candle
  boxTop: number; boxBot: number; boxScore: number;
}

const VC_Period = 5, VC_Extreme = 8, SwingWindow = 10, AdaptSmooth = 100;
const W_Sweep = 0.30, W_Speed = 0.20, W_Disp = 0.25, W_VC = 0.25, FVG_Bonus = 15;
const Min_Draw = 25, Min_Signal = 60, ATR_Expiry = 3.0, Trap_VC_Min = 8.0;

export function detectLiquidityTraps(bars: TrapBar[]): TrapEvent[] {
  const n = bars.length;
  if (n < 150) return [];
  const O = new Float64Array(n), H = new Float64Array(n), L = new Float64Array(n), C = new Float64Array(n);
  for (let k = 0; k < n; k++) { const x = bars[n - 1 - k]; O[k] = x.open; H[k] = x.high; L[k] = x.low; C[k] = x.close; }
  // MT4 iATR(14): simple average of true range
  const TR = new Float64Array(n);
  for (let k = 0; k < n; k++) TR[k] = k + 1 < n ? Math.max(H[k] - L[k], Math.abs(H[k] - C[k + 1]), Math.abs(L[k] - C[k + 1])) : H[k] - L[k];
  const pre = new Float64Array(n + 1); for (let k = 0; k < n; k++) pre[k + 1] = pre[k] + TR[k];
  const atr14 = (i: number) => (i + 14 <= n ? (pre[i + 14] - pre[i]) / 14 : 0);
  const swCache = new Map<string, Uint8Array>();
  const swing = (w: number, high: boolean) => {
    const key = `${w}${high}`; let a = swCache.get(key); if (a) return a;
    a = new Uint8Array(n);
    for (let idx = w; idx + w < n; idx++) {
      const v = high ? H[idx] : L[idx]; let ok = true;
      for (let j = idx - w; j <= idx + w && ok; j++) {
        if (j === idx) continue;
        const u = high ? H[j] : L[j];
        if (high ? (u > v || (u === v && j < idx)) : (u < v || (u === v && j < idx))) ok = false;
      }
      a[idx] = ok ? 1 : 0;
    }
    swCache.set(key, a); return a;
  };
  const recentSwing = (high: boolean, start: number, w: number) => {
    let maxLb = start + 200; if (maxLb > n - w) maxLb = n - w;
    const a = swing(w, high);
    for (let idx = start + w; idx < maxLb; idx++) if (a[idx]) return idx;
    return -1;
  };
  const breakerCandle = (pivot: number, bull: boolean, w: number) => {
    let s = pivot + Math.floor(w / 2); if (s > n - 1) s = n - 1;
    let e = pivot - Math.floor(w / 2); if (e < 0) e = 0;
    let r = pivot;
    for (let k = s; k >= e; k--) { if (bull && C[k] > O[k]) r = k; if (!bull && C[k] < O[k]) r = k; }
    return r;
  };
  const vc = (shift: number, high: boolean) => {
    if (shift + VC_Period >= n) return 0;
    let m = 0, a = 0; for (let k = shift; k < shift + VC_Period; k++) { m += (H[k] + L[k]) / 2; a += H[k] - L[k]; }
    m /= VC_Period; let at = 0.2 * (a / VC_Period); if (at === 0) at = 1e-8;
    return high ? (H[shift] - m) / at : (L[shift] - m) / at;
  };
  const score = (depth: number, barsEl: number, disp: number, vcAbs: number, fvg: boolean) => {
    const s1 = Math.min(100, Math.max(0, depth / 2) * 100), s2 = Math.min(100, Math.max(0, 1 - barsEl / 10) * 100);
    const s3 = Math.min(100, Math.max(0, disp) * 100), s4 = Math.min(100, Math.max(0, vcAbs / (VC_Extreme * 1.5)) * 100);
    let s = (W_Sweep * s1 + W_Speed * s2 + W_Disp * s3 + W_VC * s4) / (W_Sweep + W_Speed + W_Disp + W_VC);
    if (fvg) s += FVG_Bonus; return Math.max(0, Math.min(100, s));
  };
  type Box = { top: number; bot: number; open: number; score: number } | null;
  let bull: Box = null, bear: Box = null, bias = 0, atrAvg = -1;
  const out: TrapEvent[] = [];
  // i = 0 would be the forming bar; the caller passes closed bars only, so the
  // newest closed bar is i = 0 here. "Open[i-1]" (next bar's open, FVG check)
  // is unknown for it, so the FVG bonus uses the bar's own close instead.
  for (let i = n - 100; i >= 0; i--) {
    let atr = atr14(i); if (!(atr > 0)) atr = 1e-5;
    atrAvg = atrAvg < 0 ? atr : atrAvg + (atr - atrAvg) / AdaptSmooth;
    let w = SwingWindow;
    if (atrAvg > 0) { w = Math.round(SwingWindow * atr / atrAvg); w = Math.max(Math.max(3, Math.floor(SwingWindow / 3)), Math.min(SwingWindow * 3, w)); }
    const nextOpen = i > 0 ? O[i - 1] : C[i];
    { const sh = recentSwing(true, i, w);
      if (sh > 0 && C[i] > H[sh] && C[i + 1] <= H[sh]) {
        const sl = recentSwing(false, sh, w); let sw = -1;
        if (sl > 0) for (let k = sh; k >= i; k--) if (L[k] < L[sl]) { sw = k; break; }
        if (sl > 0 && sw >= 0) {
          bias = 1;
          const bb = breakerCandle(sh, true, w);
          let sb = 0, cnt = 0; for (let q = i + 1; q <= i + 20 && q < n; q++) { sb += Math.abs(C[q] - O[q]); cnt++; }
          const disp = cnt && sb ? Math.abs(C[i] - O[i]) / (sb / cnt) : 1;
          const sc = score((L[sl] - L[sw]) / atr, sw - i, disp, Math.abs(vc(sw, false)), nextOpen > H[i + 1]);
          if (sc >= Min_Draw) { bull = { top: H[bb], bot: L[bb], open: O[bb], score: sc }; bear = null; }
        }
      } }
    { const sl = recentSwing(false, i, w);
      if (sl > 0 && C[i] < L[sl] && C[i + 1] >= L[sl]) {
        const sh = recentSwing(true, sl, w); let sw = -1;
        if (sh > 0) for (let k = sl; k >= i; k--) if (H[k] > H[sh]) { sw = k; break; }
        if (sh > 0 && sw >= 0) {
          bias = -1;
          const bb = breakerCandle(sl, false, w);
          let sb = 0, cnt = 0; for (let q = i + 1; q <= i + 20 && q < n; q++) { sb += Math.abs(C[q] - O[q]); cnt++; }
          const disp = cnt && sb ? Math.abs(C[i] - O[i]) / (sb / cnt) : 1;
          const sc = score((H[sw] - H[sh]) / atr, sw - i, disp, Math.abs(vc(sw, true)), nextOpen < L[i + 1]);
          if (sc >= Min_Draw) { bear = { top: H[bb], bot: L[bb], open: O[bb], score: sc }; bull = null; }
        }
      } }
    // invalidation
    if (bull && (C[i] < bull.bot || C[i] - bull.top > ATR_Expiry * atr)) bull = null;
    if (bear && (C[i] > bear.top || bear.bot - C[i] > ATR_Expiry * atr)) bear = null;
    // breaker entries → liquidity trap
    if (bull && bias > 0 && bull.score >= Min_Signal) {
      const key = Math.max(bull.open, (bull.top + bull.bot) / 2);
      if (L[i] <= bull.top && L[i] <= key && C[i] > O[i] && C[i] > H[i + 1]) {
        const v = vc(i, true);
        if (v >= Trap_VC_Min) out.push({ index: n - 1 - i, dir: "SELL", vc: v, boxTop: bull.top, boxBot: bull.bot, boxScore: bull.score });
        bull = null;
      }
    }
    if (bear && bias < 0 && bear.score >= Min_Signal) {
      const key = Math.min(bear.open, (bear.top + bear.bot) / 2);
      if (H[i] >= bear.bot && H[i] >= key && C[i] < O[i] && C[i] < L[i + 1]) {
        const v = vc(i, false);
        if (v <= -Trap_VC_Min) out.push({ index: n - 1 - i, dir: "BUY", vc: v, boxTop: bear.top, boxBot: bear.bot, boxScore: bear.score });
        bear = null;
      }
    }
  }
  return out;
}

/** Trap fired on the NEWEST closed bar, or null. */
export function lastBarTrap(bars: TrapBar[]): TrapEvent | null {
  const ev = detectLiquidityTraps(bars);
  const last = ev[ev.length - 1];
  return last && last.index === bars.length - 1 ? last : null;
}

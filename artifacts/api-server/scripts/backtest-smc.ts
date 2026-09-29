/**
 * Backtest of the owner's MT4 indicator "FX AI SMC Fusion v27.0 — LIQUIDITY TRAP".
 * Usage: pnpm backtest-smc <DATA_DIR> [tfMinutes=1,5,15]   (HZ=1 to enable the HZ filter)
 * DATA_DIR = FutureSharks/financial-data OANDA layout (see scripts/train-weights.ts).
 *
 * Faithful port of "FX AI SMC Fusion v27.0 — LIQUIDITY TRAP" (MQL4) signal logic
 * for an evidence test on real OANDA 1-minute data (2018 + 2019, 6 instruments).
 * Series indexing like MT4: index 0 = newest bar; the history loop runs
 * i = n-100 … 1 exactly like OnCalculate on first load. HZ filter NOT ported
 * (tested with HZ off; noted in the report). Defaults = the indicator inputs.
 */
import fs from "node:fs";
import path from "node:path";

interface Bar { t: number; o: number; h: number; l: number; c: number }
const DATA_DIR = process.argv[2];
const INSTS = ["EUR_USD", "GBP_USD", "AUD_USD", "USD_CAD", "EUR_JPY", "XAU_USD"];
const SPREAD: Record<string, number> = { EUR_USD: 0.00012, GBP_USD: 0.00018, AUD_USD: 0.00014, USD_CAD: 0.00018, EUR_JPY: 0.018, XAU_USD: 0.35 };
function load(inst: string, year: number, tfMin: number): Bar[] {
  const dir = path.join(DATA_DIR, inst, String(year));
  const files = fs.readdirSync(dir).filter(f => f.endsWith(".csv")).sort((a, b) => +a.match(/-(\d+)\.csv/)![1] - +b.match(/-(\d+)\.csv/)![1]);
  const out: Bar[] = []; let cur: Bar | null = null; const step = tfMin * 60000;
  for (const f of files) for (const L of fs.readFileSync(path.join(dir, f), "utf8").split("\n").slice(1)) {
    if (!L) continue; const [ts, c, h, l, o] = L.split(","); const t = Date.parse(ts.replace(" ", "T") + "Z"); if (!isFinite(t)) continue;
    const k = Math.floor(t / step) * step;
    if (!cur || cur.t !== k) { if (cur) out.push(cur); cur = { t: k, o: +o, h: +h, l: +l, c: +c }; }
    else { cur.h = Math.max(cur.h, +h); cur.l = Math.min(cur.l, +l); cur.c = +c; }
  }
  if (cur) out.push(cur);
  return out;
}

const VC_Period = 5, VC_Extreme = 8, Sensor_Lookback = 20, SwingWindow = 10, AdaptSmooth = 100;
const W_Sweep = 0.30, W_Speed = 0.20, W_Disp = 0.25, W_VC = 0.25, FVG_Bonus = 15;
const Min_Draw = 25, Min_Signal = 60, ATR_Expiry = 3.0, SL_ATR = 1.0, Trap_VC_Min = 8.0;

type Sig = { kind: string; dir: 1 | -1; i: number; sl?: number; entryC?: number };

const POINT: Record<string, number> = { EUR_USD: 1e-5, GBP_USD: 1e-5, AUD_USD: 1e-5, USD_CAD: 1e-5, EUR_JPY: 1e-3, XAU_USD: 1e-2 };
function run(inst: string, year: number, tf: number, opt: { hz?: boolean } = {}) {
  const useHZ = !!opt.hz;
  const Point = POINT[inst] ?? 1e-5;
  const b = load(inst, year, tf);
  const n = b.length;
  const O = new Float64Array(n), H = new Float64Array(n), L = new Float64Array(n), C = new Float64Array(n);
  for (let k = 0; k < n; k++) { const x = b[n - 1 - k]; O[k] = x.o; H[k] = x.h; L[k] = x.l; C[k] = x.c; }
  // MT4 iATR(14) = SMA of true range
  const TR = new Float64Array(n);
  for (let k = 0; k < n; k++) TR[k] = k + 1 < n ? Math.max(H[k] - L[k], Math.abs(H[k] - C[k + 1]), Math.abs(L[k] - C[k + 1])) : H[k] - L[k];
  const pre = new Float64Array(n + 1); for (let k = 0; k < n; k++) pre[k + 1] = pre[k] + TR[k];
  const atr14 = (i: number) => (i + 14 <= n ? (pre[i + 14] - pre[i]) / 14 : 0);
  // swing flags per window, lazily: isSH[w][idx] ⇔ iHighest(2w+1, idx-w) == idx (first max wins)
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
  const score = (depth: number, bars: number, disp: number, vcAbs: number, fvg: boolean) => {
    const s1 = Math.min(100, Math.max(0, depth / 2) * 100), s2 = Math.min(100, Math.max(0, 1 - bars / 10) * 100);
    const s3 = Math.min(100, Math.max(0, disp) * 100), s4 = Math.min(100, Math.max(0, vcAbs / (VC_Extreme * 1.5)) * 100);
    let s = (W_Sweep * s1 + W_Speed * s2 + W_Disp * s3 + W_VC * s4) / (W_Sweep + W_Speed + W_Disp + W_VC);
    if (fvg) s += FVG_Bonus; return Math.max(0, Math.min(100, s));
  };
  const iLowest = (cnt: number, st: number) => { let bi = st; for (let k = st; k < st + cnt && k < n; k++) if (L[k] < L[bi]) bi = k; return bi; };
  const iHighest = (cnt: number, st: number) => { let bi = st; for (let k = st; k < st + cnt && k < n; k++) if (H[k] > H[bi]) bi = k; return bi; };

  // ── HZ smart horizontal S/R (v23/v26 port) ──
  const HS = 8, HZ_LB = 300, HZ_MAXLV = 20, PROM = 0.7, TOLB = 5, TOLA = 0.25, T2 = 1.0, T1 = 2.0, MINT = 2, AGE = 500, SPACE = 15;
  type Lv = { p: number; t: number; b: number };
  let SUP: Lv[] = [], RES: Lv[] = [], builtFor = -1;
  const hzAtr = (idx: number) => { const a = atr14(idx); return a > 0 ? a : 10 * Point; };
  const promLow = (k: number, th: number, off: number) => {
    if (k + HS >= n || k - HS < off) return false;
    for (let j = 1; j <= HS; j++) { if (L[k + j] < L[k]) return false; if (L[k - j] < L[k]) return false; }
    const ref = L[k]; let lp = ref, rp = ref; const scan = Math.max(HS * 4, 20);
    for (let j = 1; j <= scan; j++) { const x = k + j; if (x >= n) break; if (L[x] < ref) break; if (H[x] > lp) lp = H[x]; }
    for (let j = 1; j <= scan; j++) { const x = k - j; if (x < off - 1 || x < 0) break; const bh = x === off - 1 ? O[x] : H[x], bl = x === off - 1 ? O[x] : L[x]; if (bl < ref) break; if (bh > rp) rp = bh; }
    return Math.min(lp, rp) - ref >= th;
  };
  const promHigh = (k: number, th: number, off: number) => {
    if (k + HS >= n || k - HS < off) return false;
    for (let j = 1; j <= HS; j++) { if (H[k + j] > H[k]) return false; if (H[k - j] > H[k]) return false; }
    const ref = H[k]; let lv = ref, rv = ref; const scan = Math.max(HS * 4, 20);
    for (let j = 1; j <= scan; j++) { const x = k + j; if (x >= n) break; if (H[x] > ref) break; if (L[x] < lv) lv = L[x]; }
    for (let j = 1; j <= scan; j++) { const x = k - j; if (x < off - 1 || x < 0) break; const bh = x === off - 1 ? O[x] : H[x], bl = x === off - 1 ? O[x] : L[x]; if (bh > ref) break; if (bl < rv) rv = bl; }
    return ref - Math.max(lv, rv) >= th;
  };
  const trim = (arr: Lv[]) => {
    arr = arr.filter(x => x.b <= AGE);
    arr.sort((a, b2) => a.p - b2.p); // stable insertion-sort equivalent
    const out: Lv[] = []; const minSp = SPACE * Point;
    for (const x of arr) {
      if (out.length && x.p - out[out.length - 1].p < minSp) { if (x.t > out[out.length - 1].t) out[out.length - 1] = { ...x }; continue; }
      out.push({ ...x });
    }
    return out.slice(0, HZ_MAXLV);
  };
  const rebuild = (off: number) => {
    const sup: Lv[] = [], res: Lv[] = [];
    if (n < HS * 4 + 30 + off) { SUP = []; RES = []; return; }
    const th = hzAtr(off) * PROM; const st = HS + off; const en = Math.min(st + HZ_LB, n - HS - 1);
    const tol = TOLB * Point * 2;
    for (let k = st; k < en; k++) {
      if (promLow(k, th, off)) { const pr = L[k]; const m = sup.find(x => Math.abs(x.p - pr) <= tol);
        if (m) { m.p = (m.p * m.t + pr) / (m.t + 1); m.t++; if (k - off < m.b) m.b = k - off; } else if (sup.length < 80) sup.push({ p: pr, t: 1, b: k - off }); }
      if (promHigh(k, th, off)) { const pr = H[k]; const m = res.find(x => Math.abs(x.p - pr) <= tol);
        if (m) { m.p = (m.p * m.t + pr) / (m.t + 1); m.t++; if (k - off < m.b) m.b = k - off; } else if (res.length < 80) res.push({ p: pr, t: 1, b: k - off }); }
    }
    SUP = trim(sup); RES = trim(res);
  };
  const ensure = (i: number) => { if (builtFor !== i) { rebuild(i); builtFor = i; } };
  const tierBuy = (i: number) => {
    if (!SUP.length) return 0; const tol = Math.max(TOLB * Point, hzAtr(i) * TOLA); let best = 0;
    for (const { p: lv } of SUP) { if (lv <= 0) continue; const d = Math.abs(L[i] - lv);
      if (d <= tol * 0.5) { if (C[i] > lv) best = Math.max(best, 3); }
      else if (d <= tol * T2) { if (C[i] > lv) best = Math.max(best, 2); }
      else if (d <= tol * T1) { if (C[i] > O[i] && C[i] > lv) best = Math.max(best, 1); }
      if (L[i] < lv && C[i] > lv + tol * 0.3) best = Math.max(best, 3); }
    return best;
  };
  const tierSell = (i: number) => {
    if (!RES.length) return 0; const tol = Math.max(TOLB * Point, hzAtr(i) * TOLA); let best = 0;
    for (const { p: lv } of RES) { if (lv <= 0) continue; const d = Math.abs(H[i] - lv);
      if (d <= tol * 0.5) { if (C[i] < lv) best = Math.max(best, 3); }
      else if (d <= tol * T2) { if (C[i] < lv) best = Math.max(best, 2); }
      else if (d <= tol * T1) { if (C[i] < O[i] && C[i] < lv) best = Math.max(best, 1); }
      if (H[i] > lv && C[i] < lv - tol * 0.3) best = Math.max(best, 3); }
    return best;
  };
  const buyOK = (i: number) => !useHZ || (ensure(i), tierBuy(i) >= MINT);
  const sellOK = (i: number) => !useHZ || (ensure(i), tierSell(i) >= MINT);
  // ── Counter engine (v25/v26) ──
  let pDir = 0, pEntry = 0, pBar = -1, pCountered = false;
  const ceReset = () => { pDir = 0; pEntry = 0; pBar = -1; pCountered = false; };
  const ceExpired = (i: number) => { if (pDir === 0) return true; const since = pBar - (i - 1); return since >= 0 && since > 30; };
  const nearestRes = (e: number, md: number) => { let best = -1, bd = 1e12; for (const { p: lv } of RES) { const d = lv - e; if (lv <= 0 || d < md) continue; if (d < bd) { bd = d; best = lv; } } return best; };
  const nearestSup = (e: number, md: number) => { let best = -1, bd = 1e12; for (const { p: lv } of SUP) { const d = e - lv; if (lv <= 0 || d < md) continue; if (d < bd) { bd = d; best = lv; } } return best; };

  let bull = { top: NaN, bot: NaN, open: NaN, score: NaN }, bear = { top: NaN, bot: NaN, open: NaN, score: NaN };
  let bias = 0, atrAvg = -1;
  const sigs: Sig[] = [];
  const clearBull = () => (bull = { top: NaN, bot: NaN, open: NaN, score: NaN });
  const clearBear = () => (bear = { top: NaN, bot: NaN, open: NaN, score: NaN });
  for (let i = n - 100; i >= 1; i--) {
    let atr = atr14(i); if (!(atr > 0)) atr = 1e-5;
    atrAvg = atrAvg < 0 ? atr : atrAvg + (atr - atrAvg) / AdaptSmooth;
    let w = SwingWindow;
    if (atrAvg > 0) { w = Math.round(SwingWindow * atr / atrAvg); w = Math.max(Math.max(3, Math.floor(SwingWindow / 3)), Math.min(SwingWindow * 3, w)); }
    // A — breaker boxes
    { const sh = recentSwing(true, i, w);
      if (sh > 0 && C[i] > H[sh] && C[i + 1] <= H[sh]) {
        const sl = recentSwing(false, sh, w); let sw = -1;
        if (sl > 0) for (let k = sh; k >= i; k--) if (L[k] < L[sl]) { sw = k; break; }
        if (sl > 0 && sw >= 0) {
          bias = 1;
          const bb = breakerCandle(sh, true, w);
          let sb = 0, cnt = 0; for (let q = i + 1; q <= i + 20 && q < n; q++) { sb += Math.abs(C[q] - O[q]); cnt++; }
          const disp = cnt && sb ? Math.abs(C[i] - O[i]) / (sb / cnt) : 1;
          const sc = score((L[sl] - L[sw]) / atr, sw - i, disp, Math.abs(vc(sw, false)), O[i - 1] > H[i + 1]);
          if (sc >= Min_Draw) { bull = { top: H[bb], bot: L[bb], open: O[bb], score: sc }; clearBear(); }
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
          const sc = score((H[sw] - H[sh]) / atr, sw - i, disp, Math.abs(vc(sw, true)), O[i - 1] < L[i + 1]);
          if (sc >= Min_Draw) { bear = { top: H[bb], bot: L[bb], open: O[bb], score: sc }; clearBull(); }
        }
      } }
    const up = bias > 0, dn = bias < 0; // BIAS_STRUCTURE
    let pBuy = NaN, pSell = NaN;
    // B — sensor (liquidity sweep)
    { const li = iLowest(Sensor_Lookback, i + 2);
      if (li > 0 && up) { const s = L[li];
        if (L[i + 1] < s && C[i + 1] > s && C[i] > H[i + 1] && vc(i + 1, false) <= -VC_Extreme && buyOK(i)) { sigs.push({ kind: "sensor", dir: 1, i }); pBuy = L[i + 1]; } }
      const hi = iHighest(Sensor_Lookback, i + 2);
      if (hi > 0 && dn) { const s = H[hi];
        if (H[i + 1] > s && C[i + 1] < s && C[i] < L[i + 1] && vc(i + 1, true) >= VC_Extreme && sellOK(i)) { sigs.push({ kind: "sensor", dir: -1, i }); pSell = H[i + 1]; } } }
    // C — invalidation
    if (!isNaN(bull.bot) && C[i] < bull.bot) clearBull();
    if (!isNaN(bull.top) && C[i] - bull.top > ATR_Expiry * atr) clearBull();
    if (!isNaN(bear.top) && C[i] > bear.top) clearBear();
    if (!isNaN(bear.top) && bear.bot - C[i] > ATR_Expiry * atr) clearBear();
    // D — breaker entry + liquidity trap
    if (!isNaN(bull.top) && up && bull.score >= Min_Signal) {
      const key = Math.max(bull.open, (bull.top + bull.bot) / 2);
      if (L[i] <= bull.top && L[i] <= key && C[i] > O[i] && C[i] > H[i + 1] && buyOK(i)) {
        if (vc(i, true) >= Trap_VC_Min) sigs.push({ kind: "trap", dir: -1, i });
        else sigs.push({ kind: "box", dir: 1, i, sl: bull.bot - atr * SL_ATR, entryC: C[i] });
        clearBull(); pBuy = L[i];
      }
    }
    if (!isNaN(bear.top) && dn && bear.score >= Min_Signal) {
      const key = Math.min(bear.open, (bear.top + bear.bot) / 2);
      if (H[i] >= bear.bot && H[i] >= key && C[i] < O[i] && C[i] < L[i + 1] && sellOK(i)) {
        if (vc(i, false) <= -Trap_VC_Min) sigs.push({ kind: "trap", dir: 1, i });
        else sigs.push({ kind: "box", dir: -1, i, sl: bear.top + atr * SL_ATR, entryC: C[i] });
        clearBear(); pSell = H[i];
      }
    }
    // primary registration + Counter engine (needs HZ)
    if (!isNaN(pBuy)) { pDir = 1; pEntry = pBuy; pBar = i; pCountered = false; }
    else if (!isNaN(pSell)) { pDir = -1; pEntry = pSell; pBar = i; pCountered = false; }
    if (useHZ) {
      if (pDir === 1 && !pCountered) {
        if (ceExpired(i)) ceReset();
        else { const md = atr, tol = atr * 0.3;
          if (!(H[i] < pEntry + md - tol)) { ensure(i); const tg = nearestRes(pEntry, md); const rg = H[i] - L[i];
            if (tg > 0 && rg > 0 && H[i] >= tg - tol && H[i] <= tg + tol && (H[i] - Math.max(O[i], C[i])) / rg >= 0.4 && C[i] < tg) { sigs.push({ kind: "counter", dir: -1, i }); pCountered = true; } } }
      }
      if (pDir === -1 && !pCountered) {
        if (ceExpired(i)) ceReset();
        else { const md = atr, tol = atr * 0.3;
          if (!(L[i] > pEntry - md + tol)) { ensure(i); const tg = nearestSup(pEntry, md); const rg = H[i] - L[i];
            if (tg > 0 && rg > 0 && L[i] <= tg + tol && L[i] >= tg - tol && (Math.min(O[i], C[i]) - L[i]) / rg >= 0.4 && C[i] > tg) { sigs.push({ kind: "counter", dir: 1, i }); pCountered = true; } } }
      }
    }
  }
  return { O, H, L, C, n, sigs };
}

// ── evaluation ──
type Acc = { n: number; w: number; r: number };
const acc = () => ({ n: 0, w: 0, r: 0 });
const add = (a: Acc, won: boolean, r = 0) => { a.n++; if (won) a.w++; a.r += r; };
const fmt = (a: Acc, r = false) => a.n ? `n=${String(a.n).padStart(6)} win=${(a.w / a.n * 100).toFixed(1).padStart(5)}% ±${(196 * Math.sqrt((a.w / a.n) * (1 - a.w / a.n) / a.n)).toFixed(1)}${r ? ` avgR=${(a.r / a.n >= 0 ? "+" : "")}${(a.r / a.n).toFixed(3)}` : ""}` : "n=0";
const Hs = [1, 3, 5, 10];

if (!DATA_DIR) { console.error("usage: backtest-smc.ts <DATA_DIR> [tfMinutes=1,5,15]"); process.exit(1); }
for (const tf of (process.argv[3] ?? "1,5,15").split(",").map(Number)) for (const year of [2018, 2019]) {
  const T: Record<string, Acc> = {};
  const get = (k: string) => (T[k] ??= acc());
  for (const inst of INSTS) {
    const { O, H, L, C, sigs } = run(inst, year, tf, { hz: process.env.HZ === "1" });
    const spread = SPREAD[inst];
    for (const s of sigs) {
      const e = O[s.i - 1]; // enter at next bar open
      for (const h of Hs) { if (s.i - h < 0) continue; const x = C[s.i - h]; if (x === e) continue; add(get(`${s.kind} binary ${h}`), s.dir > 0 ? x > e : x < e); }
      add(get(`${s.kind} ALL coin-ref`), (s.i % 2) === 0);
      if (s.kind === "box" && s.sl !== undefined && s.entryC !== undefined) {
        const en = s.entryC, risk = Math.abs(en - s.sl); if (!(risk > 0)) continue;
        for (const m of [1, 2]) {
          const tp = en + s.dir * m * risk; let res = 0;
          for (let k = s.i - 1; k >= Math.max(0, s.i - 300); k--) {
            const hitSL = s.dir > 0 ? L[k] <= s.sl : H[k] >= s.sl, hitTP = s.dir > 0 ? H[k] >= tp : L[k] <= tp;
            if (hitSL) { res = -1; break; } if (hitTP) { res = m; break; }
          }
          if (res === 0) continue;
          add(get(`box forex TP${m} (1:${m})`), res > 0, res - spread / risk);
        }
      }
    }
  }
  console.log(`\n=== TF ${tf}m  ${year}  (6 instruments, HZ filter ${process.env.HZ === "1" ? "ON" : "off"}) ===`);
  for (const k of Object.keys(T).sort()) if (!k.includes("coin")) console.log(k.padEnd(26), fmt(T[k], k.includes("forex")));
}

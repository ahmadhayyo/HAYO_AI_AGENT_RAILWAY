/**
 * Walk-forward backtest of the trading-signal engine on REAL historical data.
 *
 * Measures what the platform actually does: at every CLOSED bar it runs the
 * shared engine (market-analysis.ts: 15 strategies → majority vote, and the
 * analyzeMarket "technical verdict"), enters at the NEXT bar's open paying the
 * spread, and exits at SL = 1.5×ATR / TP = 2.5×ATR (the platform's own rule) or
 * after 48 bars. One position at a time per signal source. SL is assumed hit
 * first when a bar touches both (pessimistic). A coin-flip trader with the same
 * exits is the control: a signal is only useful if it beats the coin.
 *
 * Data: 1-minute OANDA mid bars in the FutureSharks/financial-data layout
 *   <DATA_DIR>/<INSTRUMENT>/<YEAR>/oanda-<INSTRUMENT>-<YEAR>-<M>.csv
 *   (time,close,high,low,open,volume)
 * Get it with a sparse clone of https://github.com/FutureSharks/financial-data
 * (path pyfinancialdata/data/currencies/oanda).
 *
 * Usage:
 *   pnpm backtest \
 *     <DATA_DIR> [year=2019] [tfMinutes=60] [instruments=EUR_USD,GBP_USD,...]
 *
 * Break-even win rate with these exits is 1.5 / (1.5 + 2.5) = 37.5% before
 * costs; "avgR" is the average result per trade in units of risk, net of spread.
 * |t| < 2 means the result is indistinguishable from luck.
 */
import fs from "node:fs";
import path from "node:path";
import * as M from "../src/hayo/market-analysis.ts";

interface Bar { t: number; o: number; h: number; l: number; c: number }

const [dataDir, yearArg = "2019", tfArg = "60", instArg] = process.argv.slice(2);
if (!dataDir) {
  console.error("usage: backtest-signals.ts <DATA_DIR> [year] [tfMinutes] [instruments]");
  process.exit(1);
}
const YEAR = Number(yearArg), TF = Number(tfArg), WINDOW = 250, HTF = TF >= 60 ? 1440 : 240;
const INSTRUMENTS = (instArg ?? "EUR_USD,GBP_USD,AUD_USD,USD_CAD,EUR_JPY,XAU_USD").split(",");

function loadBars(inst: string, year: number, tfMin: number): Bar[] {
  const dir = path.join(dataDir, inst, String(year));
  const month = (f: string) => Number(f.match(/-(\d+)\.csv$/)?.[1] ?? 0);
  const files = fs.readdirSync(dir).filter(f => f.endsWith(".csv")).sort((a, b) => month(a) - month(b));
  const step = tfMin * 60_000, out: Bar[] = [];
  let cur: Bar | null = null;
  for (const f of files) {
    const lines = fs.readFileSync(path.join(dir, f), "utf8").split("\n");
    for (let i = 1; i < lines.length; i++) {
      if (!lines[i]) continue;
      const [ts, c, h, l, o] = lines[i].split(",");
      const t = Date.parse(ts.replace(" ", "T") + "Z");
      if (!Number.isFinite(t)) continue;
      const bucket = Math.floor(t / step) * step;
      if (!cur || cur.t !== bucket) {
        if (cur) out.push(cur);
        cur = { t: bucket, o: +o, h: +h, l: +l, c: +c };
      } else {
        cur.h = Math.max(cur.h, +h); cur.l = Math.min(cur.l, +l); cur.c = +c;
      }
    }
  }
  if (cur) out.push(cur);
  return out;
}

/** Enter at bar i+1 open (after bar i closed); returns [R net of spread, exit index]. */
function trade(bars: Bar[], i: number, dir: 1 | -1, atr: number, spread: number): [number, number] {
  const entry = bars[i + 1].o + dir * spread, risk = 1.5 * atr;
  const sl = entry - dir * risk, tp = entry + dir * 2.5 * atr;
  const end = Math.min(bars.length - 1, i + 48);
  for (let j = i + 1; j <= end; j++) {
    if (dir > 0 ? bars[j].l <= sl : bars[j].h >= sl) return [-1, j];
    if (dir > 0 ? bars[j].h >= tp : bars[j].l <= tp) return [2.5 / 1.5, j];
  }
  return [(dir * (bars[end].c - entry)) / risk, end];
}

class Stats {
  n = 0; wins = 0; sum = 0; sum2 = 0;
  add(r: number) { this.n++; if (r > 0) this.wins++; this.sum += r; this.sum2 += r * r; }
  toString() {
    if (!this.n) return "n=0";
    const m = this.sum / this.n, sd = Math.sqrt(Math.max(0, this.sum2 / this.n - m * m));
    const t = sd > 0 ? m / (sd / Math.sqrt(this.n)) : 0;
    return `n=${String(this.n).padStart(5)}  win=${((this.wins / this.n) * 100).toFixed(1).padStart(5)}%  avgR=${m >= 0 ? "+" : ""}${m.toFixed(3)}  t=${t.toFixed(2).padStart(6)}`;
  }
}

const perStrategy: Record<string, Stats> = {};
const majority = new Stats(), verdict = new Stats(), coin = new Stats();
let seed = 12345;
const rand = () => (seed = (seed * 1664525 + 1013904223) % 4294967296) / 4294967296;

for (const inst of INSTRUMENTS) {
  const pair = inst.replace("_", "");
  const spread = M.TYPICAL_SPREAD[pair] ?? 0;
  const bars = loadBars(inst, YEAR, TF), hbars = loadBars(inst, YEAR, HTF);
  const busy: Record<string, number> = {};
  let hj = 0;
  for (let i = WINDOW; i < bars.length - 2; i++) {
    const w = bars.slice(i - WINDOW + 1, i + 1);
    const C = w.map(b => b.c), H = w.map(b => b.h), L = w.map(b => b.l), O = w.map(b => b.o);
    const atr = M.calcATR(H, L, C);
    if (!(atr > 0)) continue;
    const sma20 = M.calcSMA(C, 20), sma50 = M.calcSMA(C, 50), sma200 = M.calcSMA(C, 200);
    const strategies = M.calcStrategies(
      C, H, L, sma20, sma50, sma200, M.calcRSI(C), M.calcMACD(C), M.calcBB(C), atr,
      M.calcStochastic(C, H, L), M.calcWilliamsR(C, H, L), M.calcADX(H, L, C),
      M.calcPivotPoints(H, L, C, w.map(b => b.t)), O,
    );
    const take = (key: string, dir: 1 | -1, stats: Stats) => {
      if (i < (busy[key] ?? 0)) return;
      const [r, exit] = trade(bars, i, dir, atr, spread);
      stats.add(r); busy[key] = exit;
    };

    for (const s of strategies) {
      if (s.signal !== "NEUTRAL") take(s.id, s.signal === "BUY" ? 1 : -1, (perStrategy[s.id] ??= new Stats()));
    }
    const buys = strategies.filter(s => s.signal === "BUY").length;
    const sells = strategies.filter(s => s.signal === "SELL").length;
    if (buys !== sells) take("majority", buys > sells ? 1 : -1, majority);

    // analyzeMarket technicalVerdict: strategy strengths + main trend + HTF bias, cost-gated
    while (hj + 1 < hbars.length && hbars[hj + 1].t + HTF * 60_000 <= bars[i].t + TF * 60_000) hj++;
    let vote = 0;
    for (const s of strategies) vote += s.signal === "BUY" ? s.strength / 100 : s.signal === "SELL" ? -s.strength / 100 : 0;
    vote += C[C.length - 1] > sma200 ? 1.2 : -1.2;
    if (hj >= 20) {
      const hc = hbars.slice(Math.max(0, hj - 59), hj + 1).map(b => b.c);
      const hp = hc[hc.length - 1], h20 = M.calcSMA(hc, 20), h50 = hc.length >= 50 ? M.calcSMA(hc, 50) : h20;
      if (hp > h20 && h20 >= h50) vote += 2; else if (hp < h20 && h20 <= h50) vote -= 2;
    }
    const norm = Math.max(-1, Math.min(1, vote / ((strategies.length + 3.2) * 0.55)));
    const cost = M.spreadCostPct(pair, atr);
    if (Math.abs(norm) >= 0.18 && !(cost !== null && cost >= 25)) take("verdict", norm > 0 ? 1 : -1, verdict);

    take("coin", rand() < 0.5 ? 1 : -1, coin);
  }
}

console.log(`\nBacktest ${YEAR}, ${TF}-min bars, ${INSTRUMENTS.join(" ")} — spread included, SL 1.5×ATR / TP 2.5×ATR (break-even ≈ 37.5% before costs)\n`);
for (const [id, s] of Object.entries(perStrategy).sort()) console.log(id.padEnd(22), String(s));
console.log("-".repeat(78));
console.log("majority vote".padEnd(22), String(majority));
console.log("technical verdict".padEnd(22), String(verdict));
console.log("COIN FLIP (control)".padEnd(22), String(coin));

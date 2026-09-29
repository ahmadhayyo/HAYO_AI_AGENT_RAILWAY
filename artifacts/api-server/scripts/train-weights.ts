/**
 * Train + validate the convergence weighting model (src/hayo/weights-model.ts).
 *
 * Uses the PRODUCTION feature code (tfFeatureSeries) so research and bot are
 * identical. Train year → fit L2 logistic regression; test year → report
 * out-of-sample hit rates; writes src/hayo/weights-model.json.
 *
 * Data: 1-minute OANDA mid bars, FutureSharks/financial-data layout
 *   <DATA_DIR>/<INSTRUMENT>/<YEAR>/oanda-<INSTRUMENT>-<YEAR>-<M>.csv (time,close,high,low,open,volume)
 *
 * Usage:
 *   pnpm train-weights <DATA_DIR> <modelId> <lowMin,midMin,highMin> <H> [trainYear=2018] [testYear=2019]
 * e.g. pnpm train-weights ~/oanda fast 1,5,15 10
 * Env: FEATURES=base | poc | poc-low (default: POC features on the low TF only);
 *      L2=<regularisation, default 0.001>; DRY=1 reports without writing the JSON.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { tfFeatureSeries, ALL_FEATURES, FEATURE_NAMES, type FeatureName, type OhlcBar } from "../src/hayo/weights-model";

type Bar = OhlcBar & { t: number };
const [dataDir, modelId, tfArg, hArg, trainY = "2018", testY = "2019"] = process.argv.slice(2);
if (!dataDir || !modelId || !tfArg || !hArg) {
  console.error("usage: train-weights.ts <DATA_DIR> <modelId> <low,mid,high minutes> <H> [trainYear] [testYear]");
  process.exit(1);
}
const TFS = tfArg.split(",").map(Number);
const H = Number(hArg);
// Feature set per timeframe [low, mid, high]. FEATURES=base → 11 trend/momentum
// features everywhere; poc → + POC/value-area on every TF; poc-low (default) →
// POC/value-area on the LOW timeframe only (on higher TFs it memorised the
// training year's drift and failed out-of-sample).
const BASE = [...FEATURE_NAMES];
const FSET = process.env.FEATURES ?? "poc-low";
const FEATS: FeatureName[][] = FSET === "base" ? [BASE, BASE, BASE]
  : FSET === "poc" ? [[...ALL_FEATURES], [...ALL_FEATURES], [...ALL_FEATURES]]
  : [[...ALL_FEATURES], BASE, BASE];
const FIDX = FEATS.map(fs => fs.map(f => ALL_FEATURES.indexOf(f)));
const L2 = Number(process.env.L2 ?? 1e-3);
const INSTS = ["EUR_USD", "GBP_USD", "AUD_USD", "USD_CAD", "EUR_JPY", "XAU_USD"];
const TF_KEY: Record<number, string> = { 1: "1m", 5: "5m", 15: "15m", 30: "30m", 60: "1h", 240: "4h", 1440: "1d" };

function load(inst: string, year: number, tfMin: number): Bar[] {
  const dir = path.join(dataDir, inst, String(year));
  const month = (f: string) => Number(f.match(/-(\d+)\.csv$/)?.[1] ?? 0);
  const files = fs.readdirSync(dir).filter(f => f.endsWith(".csv")).sort((a, b) => month(a) - month(b));
  const step = tfMin * 60_000, out: Bar[] = [];
  let cur: Bar | null = null;
  for (const f of files) {
    const lines = fs.readFileSync(path.join(dir, f), "utf8").split("\n");
    for (let i = 1; i < lines.length; i++) {
      if (!lines[i]) continue;
      const [ts, c, h, l, o, vol] = lines[i].split(",");
      const t = Date.parse(ts.replace(" ", "T") + "Z");
      if (!Number.isFinite(t)) continue;
      const k = Math.floor(t / step) * step;
      const v = Number(vol) || 0;
      if (!cur || cur.t !== k) { if (cur) out.push(cur); cur = { t: k, open: +o, high: +h, low: +l, close: +c, volume: v }; }
      else { cur.high = Math.max(cur.high, +h); cur.low = Math.min(cur.low, +l); cur.close = +c; cur.volume = (cur.volume ?? 0) + v; }
    }
  }
  if (cur) out.push(cur);
  return out;
}

interface Sample { x: number[]; y: number; inst: string }
function build(year: number): Sample[] {
  const S: Sample[] = [];
  for (const inst of INSTS) {
    const bars = TFS.map(tf => load(inst, year, tf));
    const feats = bars.map(tfFeatureSeries);
    const low = bars[0], lowMs = TFS[0] * 60_000;
    const ptr = [0, 0, 0];
    for (let i = 0; i + H + 1 < low.length; i++) {
      const closeT = low[i].t + lowMs;
      const row: number[] = [];
      let ok = true;
      for (let k = 0; k < 3; k++) {
        const ms = TFS[k] * 60_000, B = bars[k];
        while (ptr[k] + 1 < B.length && B[ptr[k] + 1].t + ms <= closeT) ptr[k]++;
        if (B[ptr[k]].t + ms > closeT) { ok = false; break; }   // no CLOSED bar yet
        const f = feats[k][ptr[k]];
        if (!f || f.length === 0) { ok = false; break; }
        row.push(...FIDX[k].map(j => f[j]));
      }
      if (!ok || i % 3 !== 0) continue;                          // thin out overlapping labels
      if (low[i + H].t - low[i + 1].t > (H + 5) * lowMs) continue; // horizon spans a market gap
      const entry = low[i + 1].open, exit = low[i + H].close;       // enter next bar open
      if (exit === entry) continue;
      S.push({ x: row, y: exit > entry ? 1 : 0, inst });
    }
  }
  return S;
}

/**
 * L2 logistic regression by gradient descent with BACKTRACKING: a step that
 * raises the loss is undone and the learning rate halved. (Correlated inputs
 * such as POC distance vs. EMA extension make a fixed step diverge.)
 */
function fit(S: Sample[], l2 = 1e-3, iters = 400, lr0 = 0.5) {
  const d = S[0].x.length;
  const mu = new Array(d).fill(0), sd = new Array(d).fill(0);
  for (const s of S) s.x.forEach((v, j) => (mu[j] += v));
  mu.forEach((_, j) => (mu[j] /= S.length));
  for (const s of S) s.x.forEach((v, j) => (sd[j] += (v - mu[j]) ** 2));
  sd.forEach((_, j) => (sd[j] = Math.sqrt(sd[j] / S.length) || 1));
  const X = S.map(s => s.x.map((v, j) => (v - mu[j]) / sd[j]));
  const lossGrad = (w: number[], b: number, withGrad: boolean) => {
    let loss = 0; const g = new Array(d).fill(0); let gb = 0;
    for (let n = 0; n < X.length; n++) {
      let z = b; for (let j = 0; j < d; j++) z += w[j] * X[n][j];
      const p = 1 / (1 + Math.exp(-z)), y = S[n].y;
      loss -= y ? Math.log(Math.max(p, 1e-12)) : Math.log(Math.max(1 - p, 1e-12));
      if (withGrad) { const e = p - y; for (let j = 0; j < d; j++) g[j] += e * X[n][j]; gb += e; }
    }
    let reg = 0; for (let j = 0; j < d; j++) reg += w[j] * w[j];
    return { loss: loss / X.length + 0.5 * l2 * reg, g: g.map((v, j) => v / X.length + l2 * w[j]), gb: gb / X.length };
  };
  let w = new Array(d).fill(0), b = 0, lr = lr0;
  let cur = lossGrad(w, b, true);
  for (let it = 0; it < iters && lr > 1e-6; it++) {
    const w2 = w.map((v, j) => v - lr * cur.g[j]), b2 = b - lr * cur.gb;
    const nxt = lossGrad(w2, b2, true);
    if (nxt.loss <= cur.loss) { w = w2; b = b2; cur = nxt; lr = Math.min(lr * 1.1, 4); }
    else lr *= 0.5;
  }
  console.log(`  train loss ${cur.loss.toFixed(6)} (log2 baseline ${Math.log(2).toFixed(6)})`);
  return { w, b, mu, sd };
}

const train = build(Number(trainY)), test = build(Number(testY));
const m = fit(train, L2);
const prob = (x: number[]) => { let z = m.b; x.forEach((v, j) => (z += m.w[j] * (v - m.mu[j]) / m.sd[j])); return 1 / (1 + Math.exp(-z)); };
const oos: Record<string, { n: number; winRate: number }> = {};
console.log(`${modelId}: TFs ${TFS.join("/")}m H=${H} — train ${trainY} n=${train.length}, test ${testY} n=${test.length}`);
{
  let n = 0, win = 0;
  for (const s of train) { const p = prob(s.x); const dir = p >= 0.56 ? 1 : p <= 0.44 ? -1 : 0; if (!dir) continue; n++; if (dir > 0 ? s.y === 1 : s.y === 0) win++; }
  console.log(`  in-sample p≥0.56: n=${n} win=${n ? (win / n * 100).toFixed(1) : 0}%`);
}
for (const th of [0.54, 0.56, 0.58]) {
  let n = 0, win = 0;
  const per: Record<string, [number, number]> = {};
  for (const s of test) {
    const p = prob(s.x); const dir = p >= th ? 1 : p <= 1 - th ? -1 : 0;
    if (!dir) continue;
    const ok = dir > 0 ? s.y === 1 : s.y === 0;
    n++; if (ok) win++;
    const e = (per[s.inst] ??= [0, 0]); e[0]++; if (ok) e[1]++;
  }
  oos[th.toFixed(2)] = { n, winRate: n ? Math.round(win / n * 1000) / 10 : 0 };
  console.log(`  OOS p≥${th}: n=${n} win=${oos[th.toFixed(2)].winRate}%  | ` +
    Object.entries(per).map(([k, [a, b]]) => `${k} ${(b / a * 100).toFixed(1)}%`).join(" "));
}
const names = ["low", "mid", "high"].flatMap((t, k) => FEATS[k].map(f => `${t}.${f}`));
console.log("  strongest weights:", names.map((nm, j) => [nm, m.w[j]] as const).sort((a, b) => Math.abs(b[1]) - Math.abs(a[1])).slice(0, 8).map(([nm, v]) => `${nm}=${v.toFixed(3)}`).join(" "));

const out = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../src/hayo/weights-model.json");
const all = fs.existsSync(out) ? JSON.parse(fs.readFileSync(out, "utf8")) : {};
const r6 = (v: number) => Math.round(v * 1e6) / 1e6;
all[modelId] = {
  id: modelId, tfs: TFS.map(t => TF_KEY[t] ?? `${t}m`), horizon: H, features: FEATS,
  trainedOn: `OANDA 1m ${trainY} (${INSTS.join(", ")})`, validatedOn: `${testY} out-of-sample`,
  w: m.w.map(r6), b: r6(m.b), mu: m.mu.map(r6), sd: m.sd.map(r6), oos,
};
if (process.env.DRY) { console.log("  (DRY — JSON not written)"); process.exit(0); }
fs.writeFileSync(out, JSON.stringify(all, null, 1) + "\n");
console.log(`  → wrote ${modelId} to ${out}`);

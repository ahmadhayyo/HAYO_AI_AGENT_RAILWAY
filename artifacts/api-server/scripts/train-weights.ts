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
 *   node --experimental-strip-types --no-warnings scripts/train-weights.ts <DATA_DIR> <modelId> <lowMin,midMin,highMin> <H> [trainYear=2018] [testYear=2019]
 * e.g. scripts/train-weights.ts ~/oanda fast 1,5,15 10
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { tfFeatureSeries, FEATURE_NAMES, type OhlcBar } from "../src/hayo/weights-model.ts";

type Bar = OhlcBar & { t: number };
const [dataDir, modelId, tfArg, hArg, trainY = "2018", testY = "2019"] = process.argv.slice(2);
if (!dataDir || !modelId || !tfArg || !hArg) {
  console.error("usage: train-weights.ts <DATA_DIR> <modelId> <low,mid,high minutes> <H> [trainYear] [testYear]");
  process.exit(1);
}
const TFS = tfArg.split(",").map(Number);
const H = Number(hArg);
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
      const [ts, c, h, l, o] = lines[i].split(",");
      const t = Date.parse(ts.replace(" ", "T") + "Z");
      if (!Number.isFinite(t)) continue;
      const k = Math.floor(t / step) * step;
      if (!cur || cur.t !== k) { if (cur) out.push(cur); cur = { t: k, open: +o, high: +h, low: +l, close: +c }; }
      else { cur.high = Math.max(cur.high, +h); cur.low = Math.min(cur.low, +l); cur.close = +c; }
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
        row.push(...f);
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

function fit(S: Sample[], l2 = 1e-3, iters = 300, lr = 0.5) {
  const d = S[0].x.length;
  const mu = new Array(d).fill(0), sd = new Array(d).fill(0);
  for (const s of S) s.x.forEach((v, j) => (mu[j] += v));
  mu.forEach((_, j) => (mu[j] /= S.length));
  for (const s of S) s.x.forEach((v, j) => (sd[j] += (v - mu[j]) ** 2));
  sd.forEach((_, j) => (sd[j] = Math.sqrt(sd[j] / S.length) || 1));
  const X = S.map(s => s.x.map((v, j) => (v - mu[j]) / sd[j]));
  const w = new Array(d).fill(0); let b = 0;
  for (let it = 0; it < iters; it++) {
    const g = new Array(d).fill(0); let gb = 0;
    for (let n = 0; n < X.length; n++) {
      let z = b; for (let j = 0; j < d; j++) z += w[j] * X[n][j];
      const e = 1 / (1 + Math.exp(-z)) - S[n].y;
      for (let j = 0; j < d; j++) g[j] += e * X[n][j];
      gb += e;
    }
    for (let j = 0; j < d; j++) w[j] -= lr * (g[j] / X.length + l2 * w[j]);
    b -= lr * gb / X.length;
  }
  return { w, b, mu, sd };
}

const train = build(Number(trainY)), test = build(Number(testY));
const m = fit(train);
const prob = (x: number[]) => { let z = m.b; x.forEach((v, j) => (z += m.w[j] * (v - m.mu[j]) / m.sd[j])); return 1 / (1 + Math.exp(-z)); };
const oos: Record<string, { n: number; winRate: number }> = {};
console.log(`${modelId}: TFs ${TFS.join("/")}m H=${H} — train ${trainY} n=${train.length}, test ${testY} n=${test.length}`);
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
const names = ["low", "mid", "high"].flatMap(t => FEATURE_NAMES.map(f => `${t}.${f}`));
console.log("  strongest weights:", names.map((nm, j) => [nm, m.w[j]] as const).sort((a, b) => Math.abs(b[1]) - Math.abs(a[1])).slice(0, 8).map(([nm, v]) => `${nm}=${v.toFixed(3)}`).join(" "));

const out = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../src/hayo/weights-model.json");
const all = fs.existsSync(out) ? JSON.parse(fs.readFileSync(out, "utf8")) : {};
const r6 = (v: number) => Math.round(v * 1e6) / 1e6;
all[modelId] = {
  id: modelId, tfs: TFS.map(t => TF_KEY[t] ?? `${t}m`), horizon: H,
  trainedOn: `OANDA 1m ${trainY} (${INSTS.join(", ")})`, validatedOn: `${testY} out-of-sample`,
  w: m.w.map(r6), b: r6(m.b), mu: m.mu.map(r6), sd: m.sd.map(r6), oos,
};
fs.writeFileSync(out, JSON.stringify(all, null, 1) + "\n");
console.log(`  → wrote ${modelId} to ${out}`);

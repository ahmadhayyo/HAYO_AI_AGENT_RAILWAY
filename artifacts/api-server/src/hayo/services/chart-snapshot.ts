/**
 * Live chart snapshot for vision-capable AI models.
 *
 * Renders the SAME closed candles the indicators were computed from into a
 * TradingView-style chart (TradingView's open-source lightweight-charts
 * library, in headless Chromium) and returns a PNG. Because image and numbers
 * come from identical data, a model can genuinely cross-check what it sees
 * (structure, levels, patterns) against the indicator/strategy readout.
 *
 * Layout: price pane (candles, SMA20/50/200, Bollinger Bands, pivot/price
 * lines), RSI(14) pane with 30/70, MACD(12,26,9) pane. A legend names every
 * line so the model can map colours to indicators.
 *
 * Never throws: returns null when Chromium or the chart library is unavailable,
 * and the analysis simply continues text-only.
 */
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";

export interface SnapshotCandle { time: number; open: number; high: number; low: number; close: number } // time: epoch seconds, oldest-first
export interface SnapshotLevel { price: number; label: string; color: string }
export interface SnapshotInput {
  title: string;              // e.g. "EUR/USD · 1h"
  candles: SnapshotCandle[];  // closed candles, oldest-first
  decimals: number;
  levels?: SnapshotLevel[];
  maxBars?: number;           // how many recent bars to show (default 150)
}

const LIB_VERSION = "5.2.1";
const LIB_FILE = "dist/lightweight-charts.standalone.production.js";
let libSource: string | null = null;

/** Chart library source: env path → local node_modules → pinned CDN (cached in memory). */
async function loadChartLib(): Promise<string | null> {
  if (libSource) return libSource;
  const local: string[] = [];
  if (process.env.HAYO_CHART_LIB_PATH) local.push(process.env.HAYO_CHART_LIB_PATH);
  try {
    const req = createRequire(import.meta.url);
    local.push(path.join(path.dirname(req.resolve("lightweight-charts/package.json")), LIB_FILE));
  } catch { /* not installed locally */ }
  for (const p of local) {
    try { if (fs.existsSync(p)) return (libSource = fs.readFileSync(p, "utf8")); } catch { /* next */ }
  }
  for (const url of [
    `https://cdn.jsdelivr.net/npm/lightweight-charts@${LIB_VERSION}/${LIB_FILE}`,
    `https://unpkg.com/lightweight-charts@${LIB_VERSION}/${LIB_FILE}`,
  ]) {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(15000) });
      if (res.ok) {
        const txt = await res.text();
        if (txt.includes("LightweightCharts")) return (libSource = txt);
      }
    } catch { /* next */ }
  }
  console.warn("[ChartSnapshot] lightweight-charts unavailable — chart snapshots disabled");
  return null;
}

// ── One shared headless browser (launched lazily, relaunched if it dies) ──
let browserPromise: Promise<any> | null = null;
async function getBrowser(): Promise<any | null> {
  if (browserPromise) {
    const b = await browserPromise.catch(() => null);
    if (b && b.connected !== false) return b;
    browserPromise = null;
  }
  const candidates = [process.env.PUPPETEER_EXECUTABLE_PATH, "/usr/bin/chromium", "/usr/bin/chromium-browser", "/usr/bin/google-chrome"]
    .filter(Boolean) as string[];
  const executablePath = candidates.find(p => { try { return fs.existsSync(p); } catch { return false; } });
  if (!executablePath) { console.warn("[ChartSnapshot] Chromium not found — chart snapshots disabled"); return null; }
  browserPromise = (async () => {
    const puppeteer = (await import("puppeteer-core")).default;
    return puppeteer.launch({
      executablePath, headless: true,
      args: ["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage", "--disable-gpu", "--font-render-hinting=none"],
    });
  })();
  return browserPromise.catch((e) => { console.warn("[ChartSnapshot] launch failed:", e?.message); browserPromise = null; return null; });
}

// ── Indicator series (oldest-first, null until warm) — same definitions as market-analysis ──
function smaS(v: number[], p: number): (number | null)[] {
  let s = 0; return v.map((x, i) => { s += x; if (i >= p) s -= v[i - p]; return i >= p - 1 ? s / p : null; });
}
function emaS(v: number[], p: number): (number | null)[] {
  const out: (number | null)[] = new Array(v.length).fill(null); if (v.length < p) return out;
  const k = 2 / (p + 1); let e = v.slice(0, p).reduce((a, b) => a + b, 0) / p; out[p - 1] = e;
  for (let i = p; i < v.length; i++) { e = v[i] * k + e * (1 - k); out[i] = e; } return out;
}
function rsiS(c: number[], p = 14): (number | null)[] {
  const out: (number | null)[] = new Array(c.length).fill(null); if (c.length <= p) return out;
  let g = 0, l = 0;
  for (let i = 1; i <= p; i++) { const d = c[i] - c[i - 1]; if (d > 0) g += d; else l -= d; }
  g /= p; l /= p; out[p] = l === 0 ? 100 : 100 - 100 / (1 + g / l);
  for (let i = p + 1; i < c.length; i++) { const d = c[i] - c[i - 1]; g = (g * (p - 1) + Math.max(d, 0)) / p; l = (l * (p - 1) + Math.max(-d, 0)) / p; out[i] = l === 0 ? 100 : 100 - 100 / (1 + g / l); }
  return out;
}
function bbS(c: number[], p = 20, m = 2) {
  const mid = smaS(c, p);
  const up = c.map((_, i) => { const md = mid[i]; if (md === null) return null; let s = 0; for (let j = i - p + 1; j <= i; j++) s += (c[j] - md) ** 2; return md + m * Math.sqrt(s / p); });
  const lo = up.map((u, i) => (u === null || mid[i] === null ? null : 2 * (mid[i] as number) - u));
  return { up, lo };
}

export async function renderChartSnapshot(input: SnapshotInput): Promise<Buffer | null> {
  let page: any = null;
  try {
    if (!input.candles || input.candles.length < 30) return null;
    const [lib, browser] = await Promise.all([loadChartLib(), getBrowser()]);
    if (!lib || !browser) return null;

    // Indicators on the FULL history, then crop to the visible window.
    const all = input.candles, c = all.map(x => x.close);
    const sma20 = smaS(c, 20), sma50 = smaS(c, 50), sma200 = smaS(c, 200), bb = bbS(c);
    const rsi = rsiS(c), e12 = emaS(c, 12), e26 = emaS(c, 26);
    const macd = c.map((_, i) => (e12[i] === null || e26[i] === null ? null : (e12[i] as number) - (e26[i] as number)));
    const firstMacd = macd.findIndex(v => v !== null);
    const sigRaw = firstMacd >= 0 ? emaS(macd.slice(firstMacd) as number[], 9) : [];
    const signal = macd.map((_, i) => (i < firstMacd || firstMacd < 0 ? null : sigRaw[i - firstMacd] ?? null));

    const from = Math.max(0, all.length - (input.maxBars ?? 150));
    const pts = (arr: (number | null)[]) => arr.slice(from).map((v, k) => (v === null ? null : { time: all[from + k].time, value: v })).filter(Boolean);
    const data = {
      title: input.title, decimals: input.decimals,
      candles: all.slice(from),
      sma20: pts(sma20), sma50: pts(sma50), sma200: pts(sma200), bbUp: pts(bb.up), bbLo: pts(bb.lo),
      rsi: pts(rsi), macd: pts(macd), signal: pts(signal),
      hist: macd.slice(from).map((m, k) => { const s = signal[from + k]; return m === null || s === null ? null : { time: all[from + k].time, value: m - s, color: m - s >= 0 ? "#26a69a" : "#ef5350" }; }).filter(Boolean),
      levels: input.levels ?? [],
      last: all[all.length - 1],
      stamp: new Date(all[all.length - 1].time * 1000).toISOString().slice(0, 16).replace("T", " ") + " UTC",
    };

    const html = `<!doctype html><html><head><meta charset="utf-8"><style>
      html,body{margin:0;background:#131722;font-family:Arial,Helvetica,sans-serif}
      #hdr{position:absolute;top:6px;left:10px;z-index:5;color:#d1d4dc;font-size:15px;font-weight:bold}
      #leg{position:absolute;top:28px;left:10px;z-index:5;font-size:12px;color:#d1d4dc}
      #leg span{margin-right:12px}
      #c{position:absolute;top:0;left:0;width:1280px;height:820px}
    </style></head><body><div id="hdr"></div><div id="leg"></div><div id="c"></div>
    <script>${lib}</script>
    <script>
      const D = ${JSON.stringify(data)};
      const L = LightweightCharts;
      const fmt = v => v.toFixed(D.decimals);
      document.getElementById("hdr").textContent = D.title + "  ·  " + D.stamp + "  ·  last close " + fmt(D.last.close) + "  (closed candles)";
      document.getElementById("leg").innerHTML =
        '<span style="color:#ff9800">━ SMA20</span><span style="color:#2962ff">━ SMA50</span><span style="color:#ab47bc">━ SMA200</span>' +
        '<span style="color:#787b86">┅ Bollinger(20,2)</span>' + D.levels.map(l => '<span style="color:' + l.color + '">— ' + l.label + '</span>').join("");
      const chart = L.createChart(document.getElementById("c"), {
        width: 1280, height: 820,
        layout: { background: { type: "solid", color: "#131722" }, textColor: "#d1d4dc", panes: { separatorColor: "#2a2e39" } },
        grid: { vertLines: { color: "#1e222d" }, horzLines: { color: "#1e222d" } },
        rightPriceScale: { borderColor: "#2a2e39" },
        timeScale: { borderColor: "#2a2e39", timeVisible: true, secondsVisible: false, rightOffset: 4 },
      });
      const candles = chart.addSeries(L.CandlestickSeries, { upColor: "#26a69a", downColor: "#ef5350", borderVisible: false, wickUpColor: "#26a69a", wickDownColor: "#ef5350", priceFormat: { type: "price", precision: D.decimals, minMove: Math.pow(10, -D.decimals) } });
      candles.setData(D.candles);
      const pricePrec = { type: "price", precision: D.decimals, minMove: Math.pow(10, -D.decimals) };
      const line = (pts, color, width, style, pane, priceFormat) => { const s = chart.addSeries(L.LineSeries, { color, lineWidth: width, lineStyle: style || 0, priceLineVisible: false, lastValueVisible: false, crosshairMarkerVisible: false, priceFormat: priceFormat || pricePrec }, pane || 0); s.setData(pts); return s; };
      line(D.sma20, "#ff9800", 2); line(D.sma50, "#2962ff", 2); line(D.sma200, "#ab47bc", 2);
      line(D.bbUp, "#787b86", 1, 2); line(D.bbLo, "#787b86", 1, 2);
      for (const lv of D.levels) candles.createPriceLine({ price: lv.price, color: lv.color, lineWidth: 1, lineStyle: 1, axisLabelVisible: true, title: lv.label });
      const rsi = line(D.rsi, "#7e57c2", 2, 0, 1, { type: "price", precision: 1, minMove: 0.1 });
      rsi.createPriceLine({ price: 70, color: "#ef5350", lineWidth: 1, lineStyle: 2, axisLabelVisible: true, title: "70" });
      rsi.createPriceLine({ price: 30, color: "#26a69a", lineWidth: 1, lineStyle: 2, axisLabelVisible: true, title: "30" });
      const macdPrec = { type: "price", precision: D.decimals + 1, minMove: Math.pow(10, -(D.decimals + 1)) };
      const hist = chart.addSeries(L.HistogramSeries, { priceLineVisible: false, lastValueVisible: false, priceFormat: macdPrec }, 2); hist.setData(D.hist);
      line(D.macd, "#2962ff", 1, 0, 2, macdPrec); line(D.signal, "#ff6d00", 1, 0, 2, macdPrec);
      const panes = chart.panes();
      panes[0].setStretchFactor(4); panes[1].setStretchFactor(1.2); panes[2].setStretchFactor(1.2);
      L.createTextWatermark(panes[1], { horzAlign: "left", vertAlign: "top", lines: [{ text: "RSI(14)", color: "#9598a1", fontSize: 12 }] });
      L.createTextWatermark(panes[2], { horzAlign: "left", vertAlign: "top", lines: [{ text: "MACD(12,26,9)  blue=MACD  orange=signal", color: "#9598a1", fontSize: 12 }] });
      chart.timeScale().fitContent();
      requestAnimationFrame(() => requestAnimationFrame(() => { window.__ready = true; }));
    </script></body></html>`;

    page = await browser.newPage();
    await page.setViewport({ width: 1280, height: 820, deviceScaleFactor: 1 });
    await page.setContent(html, { waitUntil: "load", timeout: 20000 });
    await page.waitForFunction("window.__ready === true", { timeout: 15000 });
    const png = await page.screenshot({ type: "png", clip: { x: 0, y: 0, width: 1280, height: 820 } });
    return Buffer.from(png);
  } catch (err: any) {
    console.warn("[ChartSnapshot] render failed:", err?.message);
    return null;
  } finally {
    if (page) { try { await page.close(); } catch { /* ignore */ } }
  }
}

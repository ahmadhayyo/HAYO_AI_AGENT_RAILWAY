/**
 * Shared market-data provider fallbacks used by BOTH the web analysis
 * (router.ts) and the Telegram bot (telegram/bot.ts): OANDA → Yahoo.
 *
 * Each returns the TwelveData shape ({ status:"ok", values:[...] } with values
 * NEWEST-first) so callers can treat all providers identically. TwelveData
 * itself stays in each caller (it needs their key-rotation state). Symbols use
 * the TwelveData convention ("EUR/USD", "XAU/USD", "BTC/USD", "DJIA", "CL").
 */

// TwelveData symbol → OANDA instrument (no crypto on OANDA → skipped, caught by Yahoo)
const OANDA_INSTRUMENT: Record<string, string> = {
  "EUR/USD": "EUR_USD", "USD/JPY": "USD_JPY", "GBP/USD": "GBP_USD", "GBP/JPY": "GBP_JPY",
  "USD/CHF": "USD_CHF", "AUD/USD": "AUD_USD", "NZD/USD": "NZD_USD", "USD/CAD": "USD_CAD",
  "EUR/GBP": "EUR_GBP", "EUR/JPY": "EUR_JPY", "EUR/CHF": "EUR_CHF", "AUD/CAD": "AUD_CAD",
  "XAU/USD": "XAU_USD", "XAG/USD": "XAG_USD", "DJIA": "US30_USD", "CL": "WTICO_USD",
};
const OANDA_GRAN: Record<string, string> = { "1min": "M1", "5min": "M5", "15min": "M15", "30min": "M30", "1h": "H1", "4h": "H4", "1day": "D", "1week": "W" };

// TwelveData symbol → Yahoo Finance ticker
const YAHOO_TICKER: Record<string, string> = {
  "EUR/USD": "EURUSD=X", "USD/JPY": "USDJPY=X", "GBP/USD": "GBPUSD=X", "GBP/JPY": "GBPJPY=X",
  "USD/CHF": "USDCHF=X", "AUD/USD": "AUDUSD=X", "NZD/USD": "NZDUSD=X", "USD/CAD": "USDCAD=X",
  "EUR/GBP": "EURGBP=X", "EUR/JPY": "EURJPY=X", "EUR/CHF": "EURCHF=X", "AUD/CAD": "AUDCAD=X",
  "XAU/USD": "XAUUSD=X", "XAG/USD": "XAGUSD=X", "BTC/USD": "BTC-USD", "ETH/USD": "ETH-USD",
  "DJIA": "^DJI", "CL": "CL=F",
};
// Yahoo has no 4h bars: 4h is built by aggregating 60m bars (see fetchFromYahoo).
const YAHOO_INTERVAL: Record<string, string> = { "1min": "1m", "5min": "5m", "15min": "15m", "30min": "30m", "1h": "60m", "4h": "60m", "1day": "1d", "1week": "1wk" };
// Ranges sized to give ≥ 250 closed bars (SMA200 + warm-up) where Yahoo allows it.
const YAHOO_RANGE: Record<string, string> = { "1min": "5d", "5min": "1mo", "15min": "1mo", "30min": "2mo", "1h": "3mo", "4h": "2y", "1day": "2y", "1week": "10y" };

export interface OhlcResult { status: "ok"; values: any[]; meta: { source: string } }

const INTERVAL_MS: Record<string, number> = {
  "1min": 60_000, "5min": 300_000, "15min": 900_000, "30min": 1_800_000,
  "1h": 3_600_000, "4h": 14_400_000, "1day": 86_400_000, "1week": 604_800_000,
};

/** Candle timestamp → epoch ms, treating zone-less strings as UTC. */
function candleMs(dt: string): number {
  const s = /[zZ]|[+-]\d\d:?\d\d$/.test(dt) ? dt : dt.replace(" ", "T") + "Z";
  return Date.parse(s);
}

/**
 * Drop the still-forming candle (values NEWEST-first). Signals must be computed
 * on CLOSED candles only — otherwise they repaint as the bar develops and each
 * provider (OANDA omits it, TwelveData/Yahoo include it) yields a different
 * answer for the same moment.
 */
export function dropFormingCandle(values: any[], interval: string, now = Date.now()): any[] {
  const ms = INTERVAL_MS[interval];
  if (!ms || !Array.isArray(values) || values.length === 0) return values;
  const t = candleMs(String(values[0]?.datetime ?? ""));
  if (!isFinite(t)) return values;
  return t + ms > now ? values.slice(1) : values;
}

export async function fetchFromOanda(symbol: string, interval: string, outputsize: number): Promise<OhlcResult | null> {
  const token = process.env.OANDA_API_TOKEN || process.env.OANDA_TOKEN;
  const inst = OANDA_INSTRUMENT[symbol];
  const gran = OANDA_GRAN[interval];
  if (!token || !inst || !gran) return null;
  const env = (process.env.OANDA_ENV || "practice").toLowerCase();
  const base = env === "live" ? "https://api-fxtrade.oanda.com/v3" : "https://api-fxpractice.oanda.com/v3";
  const url = `${base}/instruments/${inst}/candles?granularity=${gran}&count=${Math.min(outputsize, 500)}&price=M`;
  const res = await fetch(url, { headers: { Authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(10000) });
  if (!res.ok) return null;
  const j = await res.json() as any;
  if (!Array.isArray(j?.candles) || j.candles.length === 0) return null;
  const values = j.candles
    .filter((c: any) => c.mid && c.complete !== false)
    .map((c: any) => ({ datetime: c.time, open: c.mid.o, high: c.mid.h, low: c.mid.l, close: c.mid.c, volume: String(c.volume ?? 0) }))
    .reverse(); // OANDA is oldest-first → TwelveData is newest-first
  if (values.length === 0) return null;
  return { status: "ok", values, meta: { source: "oanda" } };
}

export async function fetchFromYahoo(symbol: string, interval: string, outputsize: number): Promise<OhlcResult | null> {
  const tk = YAHOO_TICKER[symbol];
  const yi = YAHOO_INTERVAL[interval];
  const range = YAHOO_RANGE[interval] || "1mo";
  if (!tk || !yi) return null;
  const url = `https://query1.finance.yahoo.com/v8/finance/chart/${encodeURIComponent(tk)}?interval=${yi}&range=${range}`;
  const res = await fetch(url, { headers: { "User-Agent": "Mozilla/5.0" }, signal: AbortSignal.timeout(10000) });
  if (!res.ok) return null;
  const j = await res.json() as any;
  const r = j?.chart?.result?.[0];
  const ts: number[] = r?.timestamp;
  const q = r?.indicators?.quote?.[0];
  if (!Array.isArray(ts) || !q || !Array.isArray(q.close)) return null;
  const rows: any[] = [];
  for (let i = 0; i < ts.length; i++) {
    if (q.open[i] == null || q.close[i] == null || q.high[i] == null || q.low[i] == null) continue;
    rows.push({ datetime: new Date(ts[i] * 1000).toISOString(), open: String(q.open[i]), high: String(q.high[i]), low: String(q.low[i]), close: String(q.close[i]), volume: String(q.volume?.[i] ?? 0) });
  }
  if (rows.length === 0) return null;
  const bars = interval === "4h" ? aggregateBars(rows, INTERVAL_MS["4h"]) : rows;
  const values = bars.slice(-outputsize).reverse(); // newest-first
  return { status: "ok", values, meta: { source: "yahoo" } };
}

/** Aggregate oldest-first OHLC rows into UTC-aligned buckets of `ms`. */
function aggregateBars(rows: any[], ms: number): any[] {
  const out: any[] = [];
  let cur: any = null, curKey = NaN;
  for (const r of rows) {
    const key = Math.floor(candleMs(r.datetime) / ms) * ms;
    if (cur && key === curKey) {
      cur.high = String(Math.max(+cur.high, +r.high));
      cur.low = String(Math.min(+cur.low, +r.low));
      cur.close = r.close;
      cur.volume = String(+cur.volume + +r.volume);
    } else {
      if (cur) out.push(cur);
      cur = { ...r, datetime: new Date(key).toISOString() };
      curKey = key;
    }
  }
  if (cur) out.push(cur);
  return out;
}

/**
 * Latest real-time price (a live quote, not the last closed candle). Used so the
 * analysis "current price" tracks the live chart instead of lagging a whole bar.
 * OANDA live pricing (if configured) → Yahoo regularMarketPrice. Never throws.
 */
const BINANCE_SYMBOL: Record<string, string> = { "BTC/USD": "BTCUSDT", "ETH/USD": "ETHUSDT" };

export async function fetchRealtimePrice(symbol: string): Promise<{ price: number; source: string } | null> {
  // 0) Crypto → Binance spot: matches the BINANCE:*USDT TradingView chart EXACTLY.
  try {
    const b = BINANCE_SYMBOL[symbol];
    if (b) {
      const res = await fetch(`https://api.binance.com/api/v3/ticker/price?symbol=${b}`, { signal: AbortSignal.timeout(8000) });
      if (res.ok) {
        const j = await res.json() as any;
        const p = parseFloat(j?.price);
        if (isFinite(p) && p > 0) return { price: p, source: "binance-live" };
      }
    }
  } catch { /* next */ }
  // 0.5) Twelve Data /price (uses the rotating key) — real-time quote for FX/metals/indices.
  try {
    const { getTwelveDataKey, markKeyExhausted, isRateLimitError } = await import("../lib/twelvedata-keys.js");
    const key = getTwelveDataKey();
    if (key) {
      const res = await fetch(`https://api.twelvedata.com/price?symbol=${encodeURIComponent(symbol)}&apikey=${key}`, { signal: AbortSignal.timeout(8000) });
      if (res.ok) {
        const j = await res.json() as any;
        if (isRateLimitError(j)) { markKeyExhausted(key); }
        else {
          const p = parseFloat(j?.price);
          if (isFinite(p) && p > 0) return { price: p, source: "twelvedata-live" };
        }
      }
    }
  } catch { /* next */ }
  // 1) OANDA live mid price (bid/ask) — needs token + account id
  try {
    const token = process.env.OANDA_API_TOKEN || process.env.OANDA_TOKEN;
    const acct = process.env.OANDA_ACCOUNT_ID;
    const inst = OANDA_INSTRUMENT[symbol];
    if (token && acct && inst) {
      const env = (process.env.OANDA_ENV || "practice").toLowerCase();
      const base = env === "live" ? "https://api-fxtrade.oanda.com/v3" : "https://api-fxpractice.oanda.com/v3";
      const res = await fetch(`${base}/accounts/${acct}/pricing?instruments=${inst}`, {
        headers: { Authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(8000),
      });
      if (res.ok) {
        const j = await res.json() as any;
        const p = j?.prices?.[0];
        const bid = parseFloat(p?.bids?.[0]?.price), ask = parseFloat(p?.asks?.[0]?.price);
        if (isFinite(bid) && isFinite(ask) && bid > 0 && ask > 0) return { price: (bid + ask) / 2, source: "oanda-live" };
      }
    }
  } catch { /* next */ }
  // 2) Yahoo regularMarketPrice — keyless, close to what TradingView shows for FX
  try {
    const tk = YAHOO_TICKER[symbol];
    if (tk) {
      const res = await fetch(`https://query1.finance.yahoo.com/v8/finance/chart/${encodeURIComponent(tk)}?interval=1m&range=1d`, {
        headers: { "User-Agent": "Mozilla/5.0" }, signal: AbortSignal.timeout(8000),
      });
      if (res.ok) {
        const j = await res.json() as any;
        const p = j?.chart?.result?.[0]?.meta?.regularMarketPrice;
        if (typeof p === "number" && p > 0) return { price: p, source: "yahoo-live" };
      }
    }
  } catch { /* next */ }
  return null;
}

/** OANDA → Yahoo, returning the first that yields data (or null if both fail). */
export async function fetchOhlcFallback(symbol: string, interval: string, outputsize: number): Promise<OhlcResult | null> {
  try { const o = await fetchFromOanda(symbol, interval, outputsize); if (o) return o; } catch { /* next */ }
  try { const y = await fetchFromYahoo(symbol, interval, outputsize); if (y) return y; } catch { /* next */ }
  return null;
}

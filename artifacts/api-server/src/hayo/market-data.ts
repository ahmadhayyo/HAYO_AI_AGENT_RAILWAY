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
const OANDA_GRAN: Record<string, string> = { "1min": "M1", "5min": "M5", "15min": "M15", "30min": "M30", "1h": "H1", "4h": "H4", "1day": "D" };

// TwelveData symbol → Yahoo Finance ticker
const YAHOO_TICKER: Record<string, string> = {
  "EUR/USD": "EURUSD=X", "USD/JPY": "USDJPY=X", "GBP/USD": "GBPUSD=X", "GBP/JPY": "GBPJPY=X",
  "USD/CHF": "USDCHF=X", "AUD/USD": "AUDUSD=X", "NZD/USD": "NZDUSD=X", "USD/CAD": "USDCAD=X",
  "EUR/GBP": "EURGBP=X", "EUR/JPY": "EURJPY=X", "EUR/CHF": "EURCHF=X", "AUD/CAD": "AUDCAD=X",
  "XAU/USD": "XAUUSD=X", "XAG/USD": "XAGUSD=X", "BTC/USD": "BTC-USD", "ETH/USD": "ETH-USD",
  "DJIA": "^DJI", "CL": "CL=F",
};
const YAHOO_INTERVAL: Record<string, string> = { "1min": "1m", "5min": "5m", "15min": "15m", "30min": "30m", "1h": "60m", "4h": "60m", "1day": "1d" };
const YAHOO_RANGE: Record<string, string> = { "1min": "5d", "5min": "1mo", "15min": "1mo", "30min": "2mo", "1h": "3mo", "4h": "3mo", "1day": "1y" };

export interface OhlcResult { status: "ok"; values: any[]; meta: { source: string } }

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
  const values = rows.slice(-outputsize).reverse(); // newest-first
  return { status: "ok", values, meta: { source: "yahoo" } };
}

/** OANDA → Yahoo, returning the first that yields data (or null if both fail). */
export async function fetchOhlcFallback(symbol: string, interval: string, outputsize: number): Promise<OhlcResult | null> {
  try { const o = await fetchFromOanda(symbol, interval, outputsize); if (o) return o; } catch { /* next */ }
  try { const y = await fetchFromYahoo(symbol, interval, outputsize); if (y) return y; } catch { /* next */ }
  return null;
}

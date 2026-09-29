/**
 * HAYO Trading Bot — Button-driven + Auto-Signals (owner-only)
 *
 * Manual flow:  /start → [Pair] → [Timeframe] → [Analysis type] → Results
 * Auto-signals: Periodic scan → strategies ≥ threshold → AI check → send alert
 */

import TelegramBot from "node-telegram-bot-api";
import { callProvider, callProviderVision, isProviderAvailable, PROVIDER_CONFIGS, type AIProvider } from "../hayo/providers";
import { renderChartSnapshot } from "../hayo/services/chart-snapshot";
import { getTwelveDataKey, markKeyExhausted, isRateLimitError, rotateToNextKey, checkAndMarkIfDailyExhausted, getKeyStats } from "../lib/twelvedata-keys";
import { fetchOhlcFallback, dropFormingCandle, assessData, fetchRealtimePrice } from "../hayo/market-data";
import { weightedVerdict, WEIGHT_MODELS, type WeightedVerdict } from "../hayo/weights-model";
import {
  calcRSI, calcMACD, calcBB, calcATR, calcStochastic, calcWilliamsR,
  calcPivotPoints, calcADX, calcStrategies, calcFilters, spreadCostPct, toUtcMs,
  type StrategySignal, type FilterResult,
} from "../hayo/market-analysis";

// ─── Config ───────────────────────────────────────────────────────────
const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
// Owner Telegram chat id. The env var takes precedence; the fallback is the
// platform owner's own chat id so the bot still starts and replies even when
// TELEGRAM_OWNER_CHAT_ID isn't set in the environment (a chat id is not a
// secret). startTelegramBot early-returns when this is empty, which is what
// left the bot receiving webhooks but never processing them.
const OWNER_ID  = process.env.TELEGRAM_OWNER_CHAT_ID || "34498339";

interface PairInfo { tdSymbol: string; label: string; flag: string; decimals: number }
const PAIRS: Record<string, PairInfo> = {
  EURUSD: { tdSymbol: "EUR/USD", label: "EUR/USD", flag: "🇪🇺🇺🇸", decimals: 5 },
  USDJPY: { tdSymbol: "USD/JPY", label: "USD/JPY", flag: "🇺🇸🇯🇵", decimals: 3 },
  GBPUSD: { tdSymbol: "GBP/USD", label: "GBP/USD", flag: "🇬🇧🇺🇸", decimals: 5 },
  GBPJPY: { tdSymbol: "GBP/JPY", label: "GBP/JPY", flag: "🇬🇧🇯🇵", decimals: 3 },
  USDCHF: { tdSymbol: "USD/CHF", label: "USD/CHF", flag: "🇺🇸🇨🇭", decimals: 5 },
  AUDUSD: { tdSymbol: "AUD/USD", label: "AUD/USD", flag: "🇦🇺🇺🇸", decimals: 5 },
  NZDUSD: { tdSymbol: "NZD/USD", label: "NZD/USD", flag: "🇳🇿🇺🇸", decimals: 5 },
  USDCAD: { tdSymbol: "USD/CAD", label: "USD/CAD", flag: "🇺🇸🇨🇦", decimals: 5 },
  EURGBP: { tdSymbol: "EUR/GBP", label: "EUR/GBP", flag: "🇪🇺🇬🇧", decimals: 5 },
  EURJPY: { tdSymbol: "EUR/JPY", label: "EUR/JPY", flag: "🇪🇺🇯🇵", decimals: 3 },
  EURCHF: { tdSymbol: "EUR/CHF", label: "EUR/CHF", flag: "🇪🇺🇨🇭", decimals: 5 },
  AUDCAD: { tdSymbol: "AUD/CAD", label: "AUD/CAD", flag: "🇦🇺🇨🇦", decimals: 5 },
  XAUUSD: { tdSymbol: "XAU/USD", label: "XAU/USD", flag: "🥇",     decimals: 2 },
  XAGUSD: { tdSymbol: "XAG/USD", label: "XAG/USD", flag: "🥈",     decimals: 4 },
  BTCUSD: { tdSymbol: "BTC/USD", label: "BTC/USD", flag: "₿",      decimals: 2 },
  ETHUSD: { tdSymbol: "ETH/USD", label: "ETH/USD", flag: "⟠",      decimals: 2 },
  USOIL:  { tdSymbol: "CL",     label: "US Oil",   flag: "🛢️",     decimals: 2 },
  US30:   { tdSymbol: "DJIA",   label: "US30/DJI", flag: "🏛️",     decimals: 0 },
};

// TwelveData interval config per bot timeframe key
interface TfConfig { interval: string; outputsize: number; label: string }
const TIMEFRAMES: Record<string, TfConfig> = {
  "1m":  { interval: "1min",  outputsize: 250, label: "1 دقيقة"  },
  "5m":  { interval: "5min",  outputsize: 250, label: "5 دقائق"  },
  "15m": { interval: "15min", outputsize: 250, label: "15 دقيقة" },
  "30m": { interval: "30min", outputsize: 250, label: "30 دقيقة" },
  "1h":  { interval: "1h",    outputsize: 250, label: "ساعة"     },
  "4h":  { interval: "4h",    outputsize: 250, label: "4 ساعات"  },
  "1d":  { interval: "1day",  outputsize: 250, label: "يومي"     },
};

// ─── Auto-Signal Config ───────────────────────────────────────────────
interface AutoConfig {
  enabled: boolean;
  minConsensus: number;       // minimum % strategies agreement (e.g. 75)
  minAIConfidence: number;    // minimum avg AI confidence (e.g. 70)
  pairs: string[];            // pairs to scan
  timeframes: string[];       // timeframes to scan
  intervalMinutes: number;    // scan every X minutes
  useAI: boolean;             // true: AI plurality decides; false: technical-only signals
  binary: boolean;            // binary-options mode: CALL/PUT + expiry, no SL/TP, no spread gate
  binaryExpiry: number;       // expiry in candles (3/5/7/10); 0 = auto (decided by the analysis)
}

const defaultAutoConfig: AutoConfig = {
  enabled: false,
  minConsensus: 75,
  minAIConfidence: 70,
  pairs: Object.keys(PAIRS),
  timeframes: ["15m", "1h"],
  intervalMinutes: 30,
  useAI: true,
  binary: false,
  binaryExpiry: 0,
};
/** Binary trade still running per pair:tf (a new one opens only after it expires). */
const binaryBusyUntil = new Map<string, number>();

/** Binary payout assumed for the journal's R and break-even (override: HAYO_BINARY_PAYOUT=0.8). */
const BINARY_PAYOUT = Number(process.env.HAYO_BINARY_PAYOUT ?? 0.85);
const TF_MINUTES: Record<string, number> = { "1m": 1, "5m": 5, "15m": 15, "30m": 30, "1h": 60, "4h": 240, "1d": 1440 };

let autoConfig: AutoConfig = { ...defaultAutoConfig };
let autoScanTimer: NodeJS.Timeout | null = null;

const SIGNAL_COOLDOWN_MS = 4 * 60 * 60 * 1000;

// ─── Session State ────────────────────────────────────────────────────
// Declared inside startTelegramBot so each bot instance has independent state
interface Session { pair?: string; tf?: string; settingsContext?: string }

// ─── Keyboards ────────────────────────────────────────────────────────
function pairsKeyboard(): TelegramBot.InlineKeyboardMarkup {
  return {
    inline_keyboard: [
      [{ text: "━━ 💱 العملات الرئيسية ━━", callback_data: "noop" }],
      [
        { text: "🇪🇺🇺🇸 EUR/USD", callback_data: "pair:EURUSD" },
        { text: "🇺🇸🇯🇵 USD/JPY", callback_data: "pair:USDJPY" },
        { text: "🇬🇧🇺🇸 GBP/USD", callback_data: "pair:GBPUSD" },
      ],
      [
        { text: "🇬🇧🇯🇵 GBP/JPY", callback_data: "pair:GBPJPY" },
        { text: "🇺🇸🇨🇭 USD/CHF", callback_data: "pair:USDCHF" },
        { text: "🇦🇺🇺🇸 AUD/USD", callback_data: "pair:AUDUSD" },
      ],
      [
        { text: "🇳🇿🇺🇸 NZD/USD", callback_data: "pair:NZDUSD" },
        { text: "🇺🇸🇨🇦 USD/CAD", callback_data: "pair:USDCAD" },
      ],
      [{ text: "━━ 🔀 الأزواج المتقاطعة ━━", callback_data: "noop" }],
      [
        { text: "🇪🇺🇬🇧 EUR/GBP", callback_data: "pair:EURGBP" },
        { text: "🇪🇺🇯🇵 EUR/JPY", callback_data: "pair:EURJPY" },
        { text: "🇪🇺🇨🇭 EUR/CHF", callback_data: "pair:EURCHF" },
      ],
      [
        { text: "🇦🇺🇨🇦 AUD/CAD", callback_data: "pair:AUDCAD" },
      ],
      [{ text: "━━ 🥇 المعادن والسلع ━━", callback_data: "noop" }],
      [
        { text: "🥇 ذهب XAU", callback_data: "pair:XAUUSD" },
        { text: "🥈 فضة XAG", callback_data: "pair:XAGUSD" },
        { text: "🛢️ نفط Oil", callback_data: "pair:USOIL" },
      ],
      [{ text: "━━ 📊 كريبتو ومؤشرات ━━", callback_data: "noop" }],
      [
        { text: "₿ BTC/USD", callback_data: "pair:BTCUSD" },
        { text: "⟠ ETH/USD", callback_data: "pair:ETHUSD" },
        { text: "🏛️ US30/DJI", callback_data: "pair:US30" },
      ],
      [
        { text: `📡 إشارات تلقائية ${autoConfig.enabled ? "✅" : "❌"}`, callback_data: "auto:menu" },
        { text: `🎯 التطابق ${convergenceConfig.enabled ? "✅" : "❌"}`, callback_data: "conv:menu" },
      ],
    ],
  };
}

function timeframesKeyboard(): TelegramBot.InlineKeyboardMarkup {
  return {
    inline_keyboard: [
      [
        { text: "1 دقيقة",  callback_data: "tf:1m" },
        { text: "5 دقائق",  callback_data: "tf:5m" },
        { text: "15 دقيقة", callback_data: "tf:15m" },
      ],
      [
        { text: "30 دقيقة", callback_data: "tf:30m" },
        { text: "ساعة كاملة", callback_data: "tf:1h" },
      ],
      [
        { text: "4 ساعات", callback_data: "tf:4h" },
        { text: "يومي", callback_data: "tf:1d" },
      ],
      [{ text: "◀️ تغيير الزوج", callback_data: "back:pairs" }],
    ],
  };
}

function analysisTypeKeyboard(): TelegramBot.InlineKeyboardMarkup {
  return {
    inline_keyboard: [
      [{ text: "⚡ تقني فوري (بدون AI)", callback_data: "analyze:quick" }],
      [{ text: "🤖 تحليل كامل بالذكاء الاصطناعي", callback_data: "analyze:full" }],
      [
        { text: "◀️ تغيير الإطار", callback_data: "back:timeframes" },
        { text: "🔄 تغيير الزوج",  callback_data: "back:pairs" },
      ],
    ],
  };
}

function afterResultKeyboard(): TelegramBot.InlineKeyboardMarkup {
  return {
    inline_keyboard: [
      [
        { text: "⚡ تقني مجدداً",  callback_data: "analyze:quick" },
        { text: "🤖 AI مجدداً",    callback_data: "analyze:full" },
      ],
      [
        { text: "🔄 تغيير الإطار", callback_data: "back:timeframes" },
        { text: "🏠 زوج جديد",    callback_data: "back:pairs" },
      ],
    ],
  };
}

// ─── Auto-Signal Settings Keyboards ──────────────────────────────────
function autoMenuKeyboard(): TelegramBot.InlineKeyboardMarkup {
  const c = autoConfig;
  const pf: Record<string, string> = {
    EURUSD:"🇪🇺🇺🇸", USDJPY:"🇺🇸🇯🇵", GBPUSD:"🇬🇧🇺🇸", GBPJPY:"🇬🇧🇯🇵",
    USDCHF:"🇺🇸🇨🇭", AUDUSD:"🇦🇺🇺🇸", NZDUSD:"🇳🇿🇺🇸", USDCAD:"🇺🇸🇨🇦",
    EURGBP:"🇪🇺🇬🇧", EURJPY:"🇪🇺🇯🇵", EURCHF:"🇪🇺🇨🇭", AUDCAD:"🇦🇺🇨🇦",
    XAUUSD:"🥇", XAGUSD:"🥈", BTCUSD:"₿", ETHUSD:"⟠", USOIL:"🛢️", US30:"🏛️",
  };
  const pairLabel: Record<string, string> = {
    EURUSD:"EUR/USD", USDJPY:"USD/JPY", GBPUSD:"GBP/USD", GBPJPY:"GBP/JPY",
    USDCHF:"USD/CHF", AUDUSD:"AUD/USD", NZDUSD:"NZD/USD", USDCAD:"USD/CAD",
    EURGBP:"EUR/GBP", EURJPY:"EUR/JPY", EURCHF:"EUR/CHF", AUDCAD:"AUD/CAD",
    XAUUSD:"XAU/USD", XAGUSD:"XAG/USD", BTCUSD:"BTC/USD", ETHUSD:"ETH/USD",
    USOIL:"Oil", US30:"US30",
  };
  const pb = (p: string) => ({ text: `${c.pairs.includes(p)?"✅ ":""}${pf[p]||""}${pairLabel[p]||p}`, callback_data: `auto:pair:${p}` });
  const allPairsCount = c.pairs.length;
  const totalPairs = Object.keys(PAIRS).length;

  return {
    inline_keyboard: [
      [{ text: `${c.enabled ? "🔴 إيقاف الإشارات التلقائية" : "🟢 تفعيل الإشارات التلقائية"}`, callback_data: "auto:toggle" }],
      [{ text: "▶️ فحص فوري الآن (SCAN)", callback_data: "auto:now" }],
      [{ text: "━━ نوع التداول ━━", callback_data: "auto:noop" }],
      [
        { text: `${!c.binary ? "✅ " : ""}📈 فوركس (وقف/هدف)`, callback_data: "auto:mode:forex" },
        { text: `${c.binary ? "✅ " : ""}🎰 خيارات ثنائية`, callback_data: "auto:mode:binary" },
      ],
      ...(c.binary ? [
        [{ text: `${c.binaryExpiry===0?"✅ ":""}⌛ مدة تلقائية (يحددها التحليل)`, callback_data: "auto:exp:0" }],
        [
          { text: `${c.binaryExpiry===3?"✅ ":""}3`, callback_data: "auto:exp:3" },
          { text: `${c.binaryExpiry===5?"✅ ":""}5`, callback_data: "auto:exp:5" },
          { text: `${c.binaryExpiry===7?"✅ ":""}7`, callback_data: "auto:exp:7" },
          { text: `${c.binaryExpiry===10?"✅ ":""}10 شموع`, callback_data: "auto:exp:10" },
        ],
      ] : []),
      [{ text: "━━ نوع التحليل ━━", callback_data: "auto:noop" }],
      [
        { text: `${c.useAI ? "✅ " : ""}🤖 مع AI`, callback_data: "auto:ai:on" },
        { text: `${!c.useAI ? "✅ " : ""}⚡ بدون AI (فني)`, callback_data: "auto:ai:off" },
      ],
      [{ text: `━━ الحد الأدنى للتوافق الفني: ${c.minConsensus}% ━━`, callback_data: "auto:noop" }],
      [
        { text: `${c.minConsensus===65?"✅ ":""}65%`, callback_data: "auto:cons:65" },
        { text: `${c.minConsensus===75?"✅ ":""}75%`, callback_data: "auto:cons:75" },
        { text: `${c.minConsensus===85?"✅ ":""}85%`, callback_data: "auto:cons:85" },
      ],
      [{ text: `━━ ثقة AI الأدنى: ${c.minAIConfidence}% ━━`, callback_data: "auto:noop" }],
      [
        { text: `${c.minAIConfidence===60?"✅ ":""}60%`, callback_data: "auto:aiconf:60" },
        { text: `${c.minAIConfidence===70?"✅ ":""}70%`, callback_data: "auto:aiconf:70" },
        { text: `${c.minAIConfidence===80?"✅ ":""}80%`, callback_data: "auto:aiconf:80" },
      ],
      [{ text: `━━ الأزواج المراقَبة (${allPairsCount}/${totalPairs}) ━━`, callback_data: "auto:noop" }],
      [{ text: `${allPairsCount===totalPairs?"✅ ":""}تحديد/إلغاء الكل`, callback_data: "auto:pair:ALL" }],
      [pb("EURUSD"), pb("USDJPY"), pb("GBPUSD")],
      [pb("GBPJPY"), pb("USDCHF"), pb("AUDUSD")],
      [pb("NZDUSD"), pb("USDCAD"), pb("EURGBP")],
      [pb("EURJPY"), pb("EURCHF"), pb("AUDCAD")],
      [pb("XAUUSD"), pb("XAGUSD"), pb("BTCUSD")],
      [pb("ETHUSD"), pb("USOIL"), pb("US30")],
      [{ text: `━━ الإطارات الزمنية (${c.timeframes.length}/${Object.keys(TIMEFRAMES).length}) ━━`, callback_data: "auto:noop" }],
      [{ text: `${c.timeframes.length === Object.keys(TIMEFRAMES).length ? "✅ " : ""}تحديد/إلغاء كل الفريمات`, callback_data: "auto:tf:ALL" }],
      [
        { text: `${c.timeframes.includes("1m") ?"✅ ":""}1م`,   callback_data: "auto:tf:1m" },
        { text: `${c.timeframes.includes("5m") ?"✅ ":""}5م`,   callback_data: "auto:tf:5m" },
        { text: `${c.timeframes.includes("15m")?"✅ ":""}15م`,  callback_data: "auto:tf:15m" },
      ],
      [
        { text: `${c.timeframes.includes("30m")?"✅ ":""}30م`,  callback_data: "auto:tf:30m" },
        { text: `${c.timeframes.includes("1h") ?"✅ ":""}1س`,   callback_data: "auto:tf:1h" },
        { text: `${c.timeframes.includes("4h") ?"✅ ":""}4س`,   callback_data: "auto:tf:4h" },
        { text: `${c.timeframes.includes("1d") ?"✅ ":""}يومي`, callback_data: "auto:tf:1d" },
      ],
      [{ text: "━━ فترة الفحص التلقائي ━━", callback_data: "auto:noop" }],
      [
        { text: `${c.intervalMinutes===1 ?"✅ ":""}1د`,   callback_data: "auto:interval:1" },
        { text: `${c.intervalMinutes===5 ?"✅ ":""}5د`,   callback_data: "auto:interval:5" },
        { text: `${c.intervalMinutes===15?"✅ ":""}15د`,  callback_data: "auto:interval:15" },
        { text: `${c.intervalMinutes===30?"✅ ":""}30د`,  callback_data: "auto:interval:30" },
      ],
      [{ text: "◀️ رجوع للقائمة الرئيسية", callback_data: "back:pairs" }],
    ],
  };
}

// ─── Indicator Helpers ────────────────────────────────────────────────
function smaN(arr: number[], n: number) {
  if (arr.length < n) return arr[arr.length - 1] ?? 0;
  return arr.slice(-n).reduce((a, b) => a + b, 0) / n;
}
function emaN(arr: number[], n: number) {
  if (!arr.length) return 0;
  const k = 2 / (n + 1);
  let e = arr[0];
  for (let i = 1; i < arr.length; i++) e = arr[i] * k + e * (1 - k);
  return e;
}

// Strategy/filter shapes now come from the shared market-analysis module (15
// strategies). Sig/Flt kept as aliases so the message builders below are unchanged.
type Sig = StrategySignal;
type Flt = FilterResult;

// ─── Market Data — TwelveData API ─────────────────────────────────────
interface CacheEntry { data: any; ts: number }
const marketCache = new Map<string, CacheEntry>();
const CACHE_TTL_MS = 3 * 60 * 1000; // 3-minute cache

/**
 * useTwelveData: manual analyses (a person is waiting) try TwelveData first —
 * a fast single attempt per key. Background scans never touch it: scanning 18
 * pairs × 3 TFs every few minutes used up the daily TwelveData credits within
 * minutes, which is why every request had been falling back to Yahoo.
 */
/**
 * Live quote AT THE MOMENT of analysis (5 s cache per symbol), attached to every
 * fetchMarket result — the indicators stay on closed candles, but the price
 * shown, the entry and the ATR levels are anchored to the live market, so the
 * message matches the chart at the second it was produced. A quote that
 * disagrees with the candles by > 3 ATR (feeds out of sync) is ignored.
 */
const liveCache = new Map<string, { price: number; source: string; at: number }>();
async function withLivePrice<T extends { price: number; ATR: number }>(symbol: string, d: T): Promise<T & { livePrice: number | null; liveSource: string | null; liveAt: number }> {
  let q = liveCache.get(symbol);
  if (!q || Date.now() - q.at > 5000) {
    try {
      const rt = await fetchRealtimePrice(symbol, { skipTwelveData: true });
      if (rt) { q = { price: rt.price, source: rt.source, at: Date.now() }; liveCache.set(symbol, q); }
    } catch { /* no live quote */ }
  }
  const ok = !!q && Date.now() - q.at < 60_000 && isFinite(q.price) && (!(d.ATR > 0) || Math.abs(q.price - d.price) <= 3 * d.ATR);
  return { ...d, livePrice: ok ? q!.price : null, liveSource: ok ? q!.source : null, liveAt: ok ? q!.at : Date.now() };
}

/** Price to trade from: the live quote when available, else the last closed candle. */
function tradePrice(d: any): number { return typeof d.livePrice === "number" && isFinite(d.livePrice) ? d.livePrice : d.price; }

/** "💰 price" line: live quote with its exact time, plus the last closed candle. */
function priceLine(d: any): string {
  const t = (ms: number) => localAndUtc(ms);
  const closeAt = d.datetime ? String(d.datetime).slice(11, 16) : "";
  return typeof d.livePrice === "number"
    ? `💰 <b>${d.fmt(d.livePrice)}</b> حي (${escHtml(d.liveSource || "")}) ⏱ <i>${t(d.liveAt)}</i>\n🕯 إغلاق آخر شمعة مكتملة <code>${d.fmt(d.price)}</code> <i>(شمعة ${closeAt})</i>`
    : `💰 <b>${d.fmt(d.price)}</b> <i>إغلاق شمعة ${closeAt} UTC — لا سعر حي متاح</i>`;
}

async function fetchMarket(pair: string, tfCfg: TfConfig, opts: { useTwelveData?: boolean } = {}) {
  const p = PAIRS[pair];
  return withLivePrice(p.tdSymbol, await fetchMarketCandles(pair, tfCfg, opts));
}

async function fetchMarketCandles(pair: string, tfCfg: TfConfig, opts: { useTwelveData?: boolean } = {}) {
  const p = PAIRS[pair];
  const cacheKey = `${pair}:${tfCfg.interval}:${opts.useTwelveData ? "td" : "fb"}`;

  const cached = marketCache.get(cacheKey);
  if (cached && Date.now() - cached.ts < CACHE_TTL_MS) {
    console.log(`[Bot] Cache hit: ${cacheKey} (${Math.round((Date.now()-cached.ts)/1000)}s old)`);
    return cached.data;
  }

  let json: any = null;
  let source = "";
  const tryTwelveData = async () => {
    let apiKey = getTwelveDataKey();
    for (let attempt = 0; apiKey && attempt < 2; attempt++) {
      const url = `https://api.twelvedata.com/time_series?symbol=${encodeURIComponent(p.tdSymbol)}&interval=${tfCfg.interval}&outputsize=${tfCfg.outputsize}&timezone=UTC&apikey=${apiKey}`;
      try {
        const res = await fetch(url, { signal: AbortSignal.timeout(12000) });
        if (res.status === 429) { rotateToNextKey(); apiKey = getTwelveDataKey(); continue; }
        if (!res.ok) return;
        const j = await res.json() as any;
        if (j.status === "error" && isRateLimitError(j)) {
          const isDailyDone = await checkAndMarkIfDailyExhausted(apiKey);
          if (!isDailyDone) rotateToNextKey();
          apiKey = getTwelveDataKey();
          continue;
        }
        if (j.status !== "error" && Array.isArray(j.values) && j.values.length) { json = j; source = "twelvedata"; }
        return;
      } catch { return; }
    }
  };

  // Provider order: [TwelveData — manual only] → OANDA → Binance (crypto) → Yahoo.
  // A frozen/flat TwelveData series is replaced by a fresh fallback when one exists.
  if (opts.useTwelveData) await tryTwelveData();
  if (!json || !assessData(p.tdSymbol, json.values, tfCfg.interval).usable) {
    try {
      const fb = await fetchOhlcFallback(p.tdSymbol, tfCfg.interval, tfCfg.outputsize);
      if (fb && (!json || fb.quality.usable)) { json = fb; source = fb.meta.source; }
    } catch { /* none */ }
  }

  if (!json || json.status === "error" || !json.values || !Array.isArray(json.values)) {
    throw new Error((json && json.message) || "لا توجد بيانات سوق (TwelveData/OANDA/Yahoo)");
  }

  // Closed candles only — same rule as the web engine, so both agree.
  const closedValues = dropFormingCandle(json.values, tfCfg.interval);
  const quality = assessData(p.tdSymbol, closedValues, tfCfg.interval);
  const flatShare = quality.flatShare;
  const rawCandles = [...closedValues].reverse();
  if (rawCandles.length < 20) throw new Error("بيانات غير كافية من مزود البيانات");

  const closes = rawCandles.map((c: any) => parseFloat(c.close));
  const highs  = rawCandles.map((c: any) => parseFloat(c.high));
  const lows   = rawCandles.map((c: any) => parseFloat(c.low));
  const opens  = rawCandles.map((c: any) => parseFloat(c.open));
  const volumes = rawCandles.map((c: any) => parseFloat(c.volume ?? "0") || 0);

  const price  = closes[closes.length - 1];
  const dec    = p.decimals;
  const fmt    = (n: number) => n.toFixed(dec);

  const RSI    = calcRSI(closes);
  const SMA20  = smaN(closes, 20);
  const SMA50  = smaN(closes, 50);
  const SMA200 = closes.length >= 200 ? smaN(closes, 200) : null;
  const MACD   = calcMACD(closes);
  const BB     = calcBB(closes);
  const ATR    = calcATR(highs, lows, closes);
  // Extra indicators for the full 15-strategy set (same as the web engine).
  const STOCH  = calcStochastic(closes, highs, lows);
  const WILLR  = calcWilliamsR(closes, highs, lows);
  const PIVOTS = calcPivotPoints(highs, lows, closes, rawCandles.map((c: any) => c.datetime));
  const ADX    = calcADX(highs, lows, closes);
  const strategies = calcStrategies(closes, highs, lows, SMA20, SMA50, SMA200, RSI, MACD, BB, ATR, STOCH, WILLR, ADX, PIVOTS, opens, volumes);
  const filters    = calcFilters(price, SMA20, SMA50, SMA200, RSI, ATR, closes, { highs, lows, market24x7: pair === "BTCUSD" || pair === "ETHUSD" });

  const marketResult = {
    price, fmt, RSI, SMA20, SMA50, SMA200, MACD, BB, ATR,
    STOCH, WILLR, PIVOTS, ADX,
    strategies, filters,
    datetime: rawCandles[rawCandles.length - 1].datetime,
    // Where the candles came from and whether they are usable (see flatCandleShare).
    dataSource: source || "?",
    flatShare,
    poorData: !quality.usable,
    qualityNote: quality.note,
    // Raw closed candles (epoch seconds) — used to draw the chart snapshot the
    // vision models read, so image and indicators come from identical data.
    candles: rawCandles.map((c: any, i: number) => ({
      time: Math.floor(toUtcMs(String(c.datetime)) / 1000),
      open: opens[i], high: highs[i], low: lows[i], close: closes[i], volume: volumes[i],
    })),
  };

  marketCache.set(cacheKey, { data: marketResult, ts: Date.now() });
  console.log(`[Bot] ✅ ${pair} ${tfCfg.interval} via ${source || "?"} — ${closes.length} candles, price: ${fmt(price)}`);
  return marketResult;
}

// ─── Higher-timeframe (MTF) bias — top-down context ───────────────────
const HTF_MAP: Record<string, { interval: string; label: string }> = {
  "1m": { interval: "15min", label: "15د" }, "5m": { interval: "1h", label: "1س" },
  "15m": { interval: "4h", label: "4س" }, "30m": { interval: "4h", label: "4س" }, "1h": { interval: "1day", label: "يومي" },
  "4h": { interval: "1day", label: "يومي" }, "1d": { interval: "1week", label: "أسبوعي" },
};
async function computeHtfBias(pair: string, tf: string): Promise<string> {
  const h = HTF_MAP[tf];
  if (!h) return "";
  try {
    const d = await fetchMarket(pair, { interval: h.interval, outputsize: 60, label: h.label });
    const bull = d.price > d.SMA20 && d.SMA20 >= d.SMA50;
    const bear = d.price < d.SMA20 && d.SMA20 <= d.SMA50;
    const trend = bull ? "📈 صاعد" : bear ? "📉 هابط" : "↔️ عرضي";
    return `الإطار الأعلى (${h.label}): <b>${trend}</b>${bull ? " — يفضّل الشراء/المسايرة" : bear ? " — يفضّل البيع/المسايرة" : " — حذر أكبر"}`;
  } catch { return ""; }
}

// ─── Consensus Calculator ─────────────────────────────────────────────
// Technical agreement: share of the strategies that TOOK a side (BUY or SELL)
// that agree, and at least MIN_AGREEING of them. Previously the share was over
// all 15 strategies, neutral ones included — "75%" needed 12/15 on one side,
// which almost never happens, so auto-signals and convergence never fired.
const MIN_AGREEING = 4;
function calcConsensus(strategies: Sig[]): { direction: "BUY"|"SELL"|"NEUTRAL"; pct: number; buys: number; sells: number } {
  const buys  = strategies.filter(s=>s.signal==="BUY").length;
  const sells = strategies.filter(s=>s.signal==="SELL").length;
  const dom = Math.max(buys, sells), directional = buys + sells;
  const pct = directional ? Math.round(dom / directional * 100) : 0;
  if (buys === sells || dom < MIN_AGREEING) return { direction:"NEUTRAL", pct, buys, sells };
  return { direction: buys > sells ? "BUY" : "SELL", pct, buys, sells };
}

// ─── Economic News Fetcher (cached 30 min) ───────────────────────────
interface NewsEvent { currency: string; title: string; impact: string; time: string; forecast: string; previous: string; actual: string; minutesUntil: number | null }

const PAIR_CURRENCIES: Record<string, string[]> = {
  EURUSD: ["EUR", "USD"], USDJPY: ["USD", "JPY"], GBPUSD: ["GBP", "USD"], GBPJPY: ["GBP", "JPY"],
  USDCHF: ["USD", "CHF"], AUDUSD: ["AUD", "USD"], NZDUSD: ["NZD", "USD"], USDCAD: ["USD", "CAD"],
  EURGBP: ["EUR", "GBP"], EURJPY: ["EUR", "JPY"], EURCHF: ["EUR", "CHF"], AUDCAD: ["AUD", "CAD"],
  // Metals, crypto, oil and the Dow are USD-priced: USD releases move them.
  XAUUSD: ["USD"], XAGUSD: ["USD"], BTCUSD: ["USD"], ETHUSD: ["USD"], USOIL: ["USD", "CAD"], US30: ["USD"],
};

// Raw news cache (single fetch, filter per-pair)
let rawNewsCache: { items: any[]; ts: number } | null = null;
const RAW_NEWS_TTL = 30 * 60 * 1000; // 30 minutes

async function fetchEconomicNews(pair: string): Promise<NewsEvent[]> {
  const related = PAIR_CURRENCIES[pair] ?? [];
  try {
    // Use cached raw news if fresh
    if (!rawNewsCache || Date.now() - rawNewsCache.ts > RAW_NEWS_TTL) {
      const url = "https://nfs.faireconomy.media/ff_calendar_thisweek.json";
      const res = await fetch(url, { signal: AbortSignal.timeout(8000) });
      if (!res.ok) return [];
      rawNewsCache = { items: await res.json() as any[], ts: Date.now() };
      console.log(`[TelegramBot] Economic news fetched from API (${rawNewsCache.items.length} events)`);
    } else {
      console.log(`[TelegramBot] Economic news from cache (${Math.round((Date.now()-rawNewsCache.ts)/60000)}m old)`);
    }

    const now = new Date();
    return rawNewsCache.items
      .filter((e:any) =>
        (e.impact === "High" || e.impact === "Medium") &&
        related.includes(e.country)
      )
      .map((e:any) => {
        const whenMs = Date.parse(e.date);
        const minutesUntil = Number.isNaN(whenMs) ? null : Math.round((whenMs - now.getTime()) / 60000);
        return {
          currency: e.country, title: e.title, impact: e.impact,
          time: e.time, forecast: e.forecast||"—", previous: e.previous||"—", actual: e.actual||"لم يُعلن",
          minutesUntil,
        };
      })
      .filter((e:any) => e.minutesUntil === null ? true : Math.abs(e.minutesUntil) < 12 * 60)
      .sort((a:any,b:any) => (a.minutesUntil ?? 1e9) - (b.minutesUntil ?? 1e9))
      .slice(0, 6);
  } catch { return []; }
}

// ─── AI Runner (5 models — matches platform) ──────────────────────────
export async function runAI(pair: string, tf: string, d: Awaited<ReturnType<typeof fetchMarket>>, news: NewsEvent[] = [], chart: Buffer | null = null, htfBias = "") {
  const buySigs  = d.strategies.filter(s=>s.signal==="BUY").length;
  const sellSigs = d.strategies.filter(s=>s.signal==="SELL").length;
  const avgStr   = Math.round(
    d.strategies.filter(s=>s.signal!=="NEUTRAL").reduce((a,s)=>a+s.strength,0) /
    (d.strategies.filter(s=>s.signal!=="NEUTRAL").length || 1)
  );

  // Build news context (same as router.ts)
  const newsContext = news.length > 0
    ? `\n\n📰 الأخبار الاقتصادية ذات الصلة:\n` +
      news.map(e=>`• ${e.impact==="High"?"🔴":"🟡"} ${e.currency} | ${e.title} | توقعات: ${e.forecast} | سابق: ${e.previous} | فعلي: ${e.actual}`).join("\n") +
      "\n⚠️ مهم: راعِ هذه الأخبار عند تحديد مستوى المخاطرة."
    : "";

  const ctx = `تحليل زوج ${pair} — الإطار الزمني: ${tf}
السعر الحي لحظة التحليل: ${typeof (d as any).livePrice === "number" ? `${d.fmt((d as any).livePrice)} (${(d as any).liveSource}, ${new Date((d as any).liveAt).toISOString().slice(11, 19)} UTC)` : "غير متاح"}
إغلاق آخر شمعة: ${d.fmt(d.price)}
مصدر البيانات: ${(d as any).dataSource} — آخر شمعة مغلقة ${d.datetime} UTC${(d as any).poorData ? ` — ⚠️ بيانات غير صالحة: ${(d as any).qualityNote}، المؤشرات لا تمثل السوق الحي → الجواب HOLD` : ""}

📊 المؤشرات التقنية:
• RSI(14): ${d.RSI.toFixed(1)} ${d.RSI<30?"(ذروة بيع ⚠️)":d.RSI>70?"(ذروة شراء ⚠️)":"(محايد)"}
• MACD: ${d.fmt(d.MACD.macd)} | Signal: ${d.fmt(d.MACD.signal)} | ${d.MACD.macd>d.MACD.signal?"📈 صاعد":"📉 هابط"}
• SMA20: ${d.fmt(d.SMA20)} ${d.price>d.SMA20?"✅ فوق":"❌ تحت"} | SMA50: ${d.fmt(d.SMA50)} ${d.price>d.SMA50?"✅ فوق":"❌ تحت"}${d.SMA200?` | SMA200: ${d.fmt(d.SMA200)} ${d.price>d.SMA200?"✅ فوق":"❌ تحت"}`:" | SMA200: بيانات غير كافية"}
• BB: أعلى ${d.fmt(d.BB.upper)} | وسط ${d.fmt(d.BB.middle)} | أسفل ${d.fmt(d.BB.lower)}
• ATR(14): ${d.fmt(d.ATR)}
• Stochastic(14,3): %K=${d.STOCH.k.toFixed(1)} %D=${d.STOCH.d.toFixed(1)} | Williams %R: ${d.WILLR.toFixed(1)}
• ADX(14): ${d.ADX.adx.toFixed(1)} (+DI ${d.ADX.pdi.toFixed(1)} / -DI ${d.ADX.mdi.toFixed(1)}) ${d.ADX.adx > 25 ? "اتجاه واضح" : "سوق جانبي/ضعيف"}
• Pivot ${(d.PIVOTS as any).basis === "prevDay" ? "(اليوم السابق)" : "(تقريبي — لا يوم سابق كامل في النافذة)"}: P=${d.fmt(d.PIVOTS.pivot)} | R1=${d.fmt(d.PIVOTS.r1)} R2=${d.fmt(d.PIVOTS.r2)} | S1=${d.fmt(d.PIVOTS.s1)} S2=${d.fmt(d.PIVOTS.s2)}
${htfBias ? `• ${htfBias.replace(/<[^>]+>/g, "")}\n` : ""}• تكلفة السبريد التقريبية: ${(() => { const c = spreadCostPct(pair, d.ATR); return c === null ? "غير معروفة" : `${c.toFixed(0)}% من وقف 1.5×ATR`; })()}

🕯️ آخر 5 شموع مغلقة (O/H/L/C):
${d.candles.slice(-5).map((c: any, i: number) => `  ${i + 1}. ${d.fmt(c.open)} / ${d.fmt(c.high)} / ${d.fmt(c.low)} / ${d.fmt(c.close)}`).join("\n")}

🎯 إشارات الاستراتيجيات (${buySigs} شراء / ${sellSigs} بيع / ${d.strategies.length-buySigs-sellSigs} محايد):
${d.strategies.map(s=>`• ${s.emoji} ${s.name}: ${s.signal==="BUY"?"🟢 BUY":s.signal==="SELL"?"🔴 SELL":"🟡 NEUTRAL"} (قوة: ${s.strength}%) — ${s.desc}`).join("\n")}
متوسط قوة الإشارة: ${avgStr}%

🔍 الفلاتر (${d.filters.filter(f=>f.passed).length}/${d.filters.length} اجتازت):
${d.filters.map(f=>`• ${f.emoji} ${f.name}: ${f.passed?"✅":"⚠️"} — ${f.desc}`).join("\n")}${newsContext}`;

  const sys = `أنت محلل أسواق مالية خبير متخصص في الفوركس والذهب والعملات الرقمية. ستحصل على تحليل شامل يتضمن مؤشرات تقنية + إشارات من ${d.strategies.length} استراتيجية + نتائج ${d.filters.length} فلاتر تأكيد${news.length>0?" + أخبار اقتصادية":""}.

مهمتك: دمج جميع هذه المعطيات وإعطاء توصية نهائية متكاملة مع الالتزام بالقواعد التالية:
1. توافق الاستراتيجيات (هل الأغلبية تشير لنفس الاتجاه؟)
2. الفلاتر (هل التوقيت والتقلب والاتجاه الرئيسي مناسبان؟)
3. قوة الإشارة الإجمالية
4. 🏛️ قاعدة حتمية: إذا كان السعر عند دعم متكرر → لا تُعطِ SELL. إذا كان عند مقاومة متكررة → لا تُعطِ BUY.
${news.some(e=>e.impact==="High")?"5. 📰 هناك أخبار عالية التأثير قريبة → ارفع مستوى المخاطرة وقلّل الثقة.":""}
6. 📐 المستويات: رقم واحد لكل حقل (لا نطاقات ولا نص). في الشراء: الوقف < الدخول < الهدف، وفي البيع العكس. الوقف لا يقل عن 1×ATR (ATR = ${d.fmt(d.ATR)}) والعائد:المخاطرة 1.5 على الأقل؛ إن تعذّر ذلك فأجب HOLD.
7. إذا كانت الإشارات متعارضة فالجواب الصحيح HOLD — لا تختر اتجاهاً لمجرد وجود أغلبية ضئيلة.

يجب أن ترد فقط بتنسيق JSON صحيح:
{"signal":"BUY"|"SELL"|"HOLD","confidence":0-100,"reasoning":"تحليل 3-4 جمل يذكر الاستراتيجيات والفلاتر والأخبار","entryZone":"مستوى الدخول","stopLoss":"وقف الخسارة","takeProfit":"جني الأرباح","risk":"LOW"|"MEDIUM"|"HIGH"}

لا تُرجع أي نص خارج JSON. هذا تحليل تعليمي فقط.`;

  // Chart-reading instructions (only for models that actually receive the image).
  const visionSys = sys.replace(
    `يجب أن ترد فقط بتنسيق JSON صحيح:`,
    `📸 مرفق لقطة حيّة للشارت (نفس الشموع المغلقة التي حُسبت منها المؤشرات): شموع + SMA20 (برتقالي) + SMA50 (أزرق) + SMA200 (بنفسجي) + بولينجر (رمادي منقّط) + خطوط Pivot/R1/S1 إن وُجدت، وتحتها RSI(14) ثم MACD.
اعمل بالترتيب:
أ) اقرأ الشارت بصرياً بشكل مستقل قبل الأرقام: الاتجاه وبنية القمم والقيعان، أين السعر من المتوسطات والبولينجر، مستويات دعم/مقاومة ظاهرة، نماذج سعرية أو شموع انعكاسية، حالة RSI وMACD.
ب) قارن قراءتك البصرية بمخرجات المؤشرات والاستراتيجيات والفلاتر أدناه: أين تتفق وأين تتناقض؟
ج) أصدر القرار. إذا ناقض الشارتُ المؤشرات بوضوح فالقرار HOLD.

يجب أن ترد فقط بتنسيق JSON صحيح:`,
  ).replace(
    `"risk":"LOW"|"MEDIUM"|"HIGH"}`,
    `"risk":"LOW"|"MEDIUM"|"HIGH","chartReading":"ما تراه في الشارت في جملتين","chartAgrees":true|false}`,
  );

  // Binary-options mode: each model also proposes the expiry (in candles).
  let sysUsed = sys, visionUsed = visionSys;
  if ((d as any).binary) {
    const addField = (t: string) => t.replace(`"risk":"LOW"|"MEDIUM"|"HIGH"`, `"risk":"LOW"|"MEDIUM"|"HIGH","expiryCandles":2-30`);
    const rule = `\n8. 🎰 هذه إشارة خيارات ثنائية على إطار ${tf}: حدّد "expiryCandles" = عدد الشموع (2-30) التي يُرجَّح أن يبقى خلالها السعر في اتجاه قرارك حتى الانتهاء، بناءً على قوة الزخم وبُعد أقرب دعم/مقاومة في الاتجاه المعاكس. لا تُطل المدة إذا كان مستوى معاكس قريباً.`;
    sysUsed = addField(sys).replace(`7. إذا كانت الإشارات متعارضة`, `${rule.trim()}\n7. إذا كانت الإشارات متعارضة`);
    visionUsed = addField(visionSys).replace(`7. إذا كانت الإشارات متعارضة`, `${rule.trim()}\n7. إذا كانت الإشارات متعارضة`);
  }

  // ── 5 providers — same as platform ─────────────────────────────────
  const providers: AIProvider[] = ["claude","gpt4","gemini","geminiPro","deepseek"];
  const settled = await Promise.allSettled(
    providers.map(async p => {
      const name = PROVIDER_CONFIGS[p].name;
      const icon = PROVIDER_CONFIGS[p].icon;
      if (!isProviderAvailable(p)) {
        return { provider:p, name, icon, signal:"ERROR", confidence:0, reasoning:"المزود غير متاح", entry:"—", sl:"—", tp:"—", risk:"—", sawChart:false, chartReading:"", chartAgrees:null };
      }
      try {
        // Vision models get the chart + chart-reading instructions. If the image
        // could not be delivered, callProviderVision falls back to text-only and
        // sawImage=false — its "chartReading" is then discarded below.
        const res = await callProviderVision(p, chart ? visionUsed : sysUsed, ctx, chart);
        const clean = res.content.replace(/```json\n?|```\n?/g,"").trim();
        const j = JSON.parse(clean.slice(clean.indexOf("{"), clean.lastIndexOf("}")+1));
        const sig = ["BUY","SELL","HOLD"].includes(j.signal) ? j.signal : "HOLD";
        return { provider:p, name, icon,
          signal:sig, confidence:Math.min(100,Math.max(0,Number(j.confidence)||50)),
          reasoning:j.reasoning||"—", entry:j.entryZone||"—", sl:j.stopLoss||"—", tp:j.takeProfit||"—", risk:j.risk||"MEDIUM",
          sawChart: res.sawImage,
          chartReading: res.sawImage ? String(j.chartReading || "") : "",
          chartAgrees: res.sawImage && typeof j.chartAgrees === "boolean" ? j.chartAgrees : null,
          expiryCandles: Number.isFinite(Number(j.expiryCandles)) ? Math.round(Number(j.expiryCandles)) : null };
      } catch (err: any) {
        console.error(`[TelegramBot] ${name} error:`, err.message);
        return { provider:p, name, icon, signal:"ERROR", confidence:0, reasoning:"", entry:"—", sl:"—", tp:"—", risk:"—", sawChart:false, chartReading:"", chartAgrees:null };
      }
    })
  );
  return settled.map(r => r.status==="fulfilled" ? r.value : { name:"—", icon:"⚠️", signal:"ERROR", confidence:0, reasoning:"", entry:"—", sl:"—", tp:"—", risk:"—" });
}

// ─── Message Builders ─────────────────────────────────────────────────
function sigIcon(s:"BUY"|"SELL"|"NEUTRAL") {
  return s==="BUY"?"🟢 شراء":s==="SELL"?"🔴 بيع":"🟡 محايد";
}

function buildQuickMsg(pair: string, tf: string, d: Awaited<ReturnType<typeof fetchMarket>>, news: NewsEvent[] = [], journalLine = "", header = "") {
  const p = PAIRS[pair];
  const buys  = d.strategies.filter(s=>s.signal==="BUY").length;
  const sells = d.strategies.filter(s=>s.signal==="SELL").length;
  const neutrals = d.strategies.length - buys - sells;
  const cons  = buys>sells?"🟢 شراء":sells>buys?"🔴 بيع":"🟡 محايد";
  return [
    ...(header ? [header] : []),
    `${p.flag} <b>${p.label}</b> | <code>${tf}</code>`,
    priceLine(d),
    dataLine(d),
    ``,
    `<b>━━ 📊 المؤشرات ━━</b>`,
    `RSI <code>${d.RSI.toFixed(1)}</code> ${d.RSI<30?"🔴 ذروة بيع":d.RSI>70?"🟢 ذروة شراء":"⚪ محايد"}`,
    `MACD ${d.MACD.macd>d.MACD.signal?"✅ صاعد":"❌ هابط"} | BB ${d.price<d.BB.lower?"↓ أسفل":d.price>d.BB.upper?"↑ أعلى":"↔ داخل"} النطاق`,
    `SMA20 <code>${d.fmt(d.SMA20)}</code>${d.price>d.SMA20?" ✅":" ❌"}  SMA50 <code>${d.fmt(d.SMA50)}</code>${d.price>d.SMA50?" ✅":" ❌"}`,
    d.SMA200?`SMA200 <code>${d.fmt(d.SMA200)}</code>${d.price>d.SMA200?" ✅":" ❌"}`:`SMA200 —`,
    `ATR <code>${d.fmt(d.ATR)}</code>`,
    ``,
    `<b>━━ 🎯 الاستراتيجيات (${buys}🟢 ${sells}🔴 ${neutrals}🟡) ━━</b>`,
    ...d.strategies.map(s=>`${s.emoji} <b>${s.name}</b>: ${sigIcon(s.signal)}${s.signal!=="NEUTRAL"?` <code>${s.strength}%</code>`:""}\n   <i>${s.desc}</i>`),
    ``,
    `<b>━━ 🔍 الفلاتر ━━</b>`,
    ...d.filters.map(f=>`${f.passed?"✅":"⚠️"} ${f.emoji} <b>${f.name}</b>: <i>${f.desc}</i>`),
    ``,
    `┌──────────────────────────┐`,
    `│  التوافق: ${cons.padEnd(12)}│`,
    `└──────────────────────────┘`,
    ...buildRecommendation(pair, d, [], news),
    ...(journalLine ? [journalLine] : []),
    ``,
    `<i>⚠️ للأغراض التعليمية فقط</i>`,
  ].join("\n");
}

// ─── Long-message delivery ────────────────────────────────────────────
// Telegram rejects messages over 4096 chars; a full AI analysis (15 strategies,
// 5 models with chart readings, final decision) can exceed that. Split on line
// boundaries (every line carries its own balanced HTML tags) and send in order;
// the first part may replace a "loading…" message, the keyboard goes on the last.
function chunk<T>(arr: T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
  return out;
}

function splitForTelegram(text: string, limit = 3900): string[] {
  const out: string[] = [];
  let cur = "";
  for (const raw of text.split("\n")) {
    const line = raw.length > limit ? raw.slice(0, limit) : raw;
    if (cur && cur.length + 1 + line.length > limit) { out.push(cur); cur = line; }
    else cur = cur ? `${cur}\n${line}` : line;
  }
  if (cur) out.push(cur);
  return out;
}

async function deliverLong(
  bot: TelegramBot, chatId: number, text: string,
  opts: { replyMarkup?: TelegramBot.InlineKeyboardMarkup; editMessageId?: number } = {},
): Promise<void> {
  const parts = splitForTelegram(text);
  for (let i = 0; i < parts.length; i++) {
    const extra: any = { parse_mode: "HTML" };
    if (i === parts.length - 1 && opts.replyMarkup) extra.reply_markup = opts.replyMarkup;
    if (i === 0 && opts.editMessageId) {
      await bot.editMessageText(parts[0], { chat_id: chatId, message_id: opts.editMessageId, ...extra });
    } else {
      await bot.sendMessage(chatId, parts[i], extra);
    }
  }
}

/** One line describing where the candles came from and whether they are usable. */
function dataLine(d: any): string {
  const src = d.dataSource || "?";
  return d.poorData
    ? `📡 البيانات: <code>${src}</code> ⚠️ <b>غير صالحة</b> (${escHtml(d.qualityNote ?? "")}) — لا يُعتمد عليها`
    : `📡 البيانات: <code>${src}</code> ✅`;
}

/** AI text is untrusted: escape it before embedding in Telegram HTML. */
function escHtml(t: string): string {
  return String(t).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

/** Snapshot of the live chart (same closed candles as the indicators); null if unavailable. */
async function renderPairChart(pair: string, tf: string, d: Awaited<ReturnType<typeof fetchMarket>>): Promise<Buffer | null> {
  const p = PAIRS[pair];
  const levels: { price: number; label: string; color: string }[] = [];
  const pv: any = d.PIVOTS;
  if (pv && pv.basis === "prevDay") {
    levels.push({ price: pv.r1, label: "R1", color: "#ef5350" }, { price: pv.pivot, label: "Pivot", color: "#fbc02d" }, { price: pv.s1, label: "S1", color: "#26a69a" });
  }
  return renderChartSnapshot({ title: `${p.label} · ${tf}`, candles: d.candles, decimals: p.decimals, levels });
}

async function sendChartPhoto(bot: TelegramBot, chatId: number, png: Buffer | null, caption: string): Promise<void> {
  if (!png) return;
  try {
    await bot.sendPhoto(chatId, png, { caption }, { filename: "chart.png", contentType: "image/png" });
  } catch (err: any) { console.warn("[TelegramBot] sendPhoto failed:", err.message); }
}

// ─── AI consensus = the FINAL decision ───────────────────────────────
// Every model that answered casts one vote (BUY / SELL / HOLD — "wait" is a
// vote too). The answer with the MOST votes wins (plurality); a tie at the top
// means no clear agreement → "SPLIT" (treated as wait). Each model has already
// seen ALL the indicator/strategy/filter data (and the chart, if it has vision),
// so this is where everything converges.
export function aiConsensus(aiResults: any[]): { label: "BUY" | "SELL" | "HOLD" | "SPLIT"; votes: number; answered: number; avgConf: number; buys: number; sells: number; holds: number } {
  const answered = aiResults.filter((r: any) => r.signal === "BUY" || r.signal === "SELL" || r.signal === "HOLD");
  const buys = answered.filter((r: any) => r.signal === "BUY").length;
  const sells = answered.filter((r: any) => r.signal === "SELL").length;
  const holds = answered.length - buys - sells;
  const n = answered.length;
  const top = Math.max(buys, sells, holds);
  const leaders = ([["BUY", buys], ["SELL", sells], ["HOLD", holds]] as const).filter(([, v]) => v === top);
  const label: "BUY" | "SELL" | "HOLD" | "SPLIT" = n === 0 ? "HOLD" : leaders.length > 1 ? "SPLIT" : leaders[0][0];
  const voters = label === "SPLIT" ? answered : answered.filter((r: any) => r.signal === label);
  const avgConf = voters.length ? Math.round(voters.reduce((a: number, r: any) => a + r.confidence, 0) / voters.length) : 0;
  return { label, votes: label === "SPLIT" ? 0 : voters.length, answered: n, avgConf, buys, sells, holds };
}

/** First number in an AI level string ("83910 - 83920" → 83910); NaN if none. */
function firstNumber(v: unknown): number {
  const m = String(v ?? "").replace(/,/g, "").match(/-?\d+(\.\d+)?/);
  return m ? parseFloat(m[0]) : NaN;
}

const MIN_RR = 1.5;          // minimum reward:risk for levels we publish
// Counter-trend filter on by default; HAYO_COUNTER_TREND_BLOCK=0 disables it.
const COUNTER_TREND_BLOCK = process.env.HAYO_COUNTER_TREND_BLOCK !== "0";
/** Direction of the higher-timeframe bias line built by computeHtfBias: 1 up, -1 down, 0 flat/unknown. */
function htfDirOf(text: unknown): 1 | -1 | 0 {
  const t = String(text ?? "");
  return t.includes("📈 صاعد") ? 1 : t.includes("📉 هابط") ? -1 : 0;
}
// Minimum AI models that must actually answer before an AI decision is trusted.
const MIN_AI_ANSWERS = Math.max(1, Number(process.env.HAYO_MIN_AI_ANSWERS ?? 2));
// Spread cost (% of a 1.5×ATR stop) at which a trade is blocked. Env-tunable;
// HAYO_COST_BLOCK_PCT=0 disables the gate (the cost line is still shown).
const COST_BLOCK_PCT = Number(process.env.HAYO_COST_BLOCK_PCT ?? 25);

interface Recommendation {
  dir: "BUY" | "SELL" | "HOLD";
  conf: number;
  entry: number; sl: number; tp: number; rr: number;
  levelsFrom: "AI" | "ATR" | "";
  reasons: string[];
  blockers: string[];
  costPct: number | null;
  expiry?: number;                          // binary: expiry in candles
  expiryFrom?: "AI" | "ADX" | "fixed" | "model";
}

// Deterministic FINAL recommendation — strategies + trend filter + AI majority,
// then hard safety gates (AI majority, minimum confidence, spread cost, news),
// then validated levels (correct side, R:R ≥ 1.5, else ATR-based).
export function computeRecommendation(
  pair: string,
  d: Awaited<ReturnType<typeof fetchMarket>>,
  aiResults: any[],
  news: NewsEvent[] = [],
): Recommendation {
  const buys = d.strategies.filter((s: Sig) => s.signal === "BUY");
  const sells = d.strategies.filter((s: Sig) => s.signal === "SELL");
  const trendF = d.filters.find((f: any) => f.id === "trend_filter");
  const trendUp = trendF ? trendF.allowsBuy : null;
  const ai = aiConsensus(aiResults);

  let dir: "BUY" | "SELL" | "HOLD";
  let conf: number;
  const reasons: string[] = [`الاستراتيجيات ${buys.length}🟢 / ${sells.length}🔴`];
  if (trendUp !== null) reasons.push(`الاتجاه الرئيسي ${trendUp ? "صاعد 📈" : "هابط 📉"}`);

  if (ai.answered > 0) {
    // FINAL DECISION = the answer most AI models agree on.
    dir = ai.label === "SPLIT" ? "HOLD" : ai.label;
    conf = ai.avgConf;
    reasons.push(`أصوات AI: ${ai.buys} شراء · ${ai.sells} بيع · ${ai.holds} انتظار من ${ai.answered}`);
    reasons.push(ai.label === "SPLIT"
      ? "تعادل في الأصوات — لا توافق كافٍ"
      : `القرار الأكثر توافقاً: ${ai.label === "BUY" ? "شراء" : ai.label === "SELL" ? "بيع" : "انتظار"} (${ai.votes}/${ai.answered})`);
  } else {
    // No model answered → fall back to the weighted technical vote.
    let vote = 0;
    for (const s of d.strategies as Sig[]) { if (s.signal === "BUY") vote += s.strength / 100; else if (s.signal === "SELL") vote -= s.strength / 100; }
    if (trendUp === true) vote += 1.2; else if (trendUp === false) vote -= 1.2;
    const norm = Math.max(-1, Math.min(1, vote / ((d.strategies.length + 1.2) * 0.5)));
    dir = Math.abs(norm) < 0.18 ? "HOLD" : norm > 0 ? "BUY" : "SELL";
    conf = Math.round(Math.abs(norm) * 100);
    reasons.push("لا نماذج AI متاحة — قرار فني من الاستراتيجيات");
  }

  // ── Safety gates (external facts, not opinions): turn the verdict into "wait" ──
  const blockers: string[] = [];
  const costPct = spreadCostPct(pair, d.ATR);
  const binary = (d as any).binary as { expiry: number; tfMin: number } | undefined;
  // Binary options pay a fixed amount at expiry: no stop, no spread → no cost gate.
  if (!binary && COST_BLOCK_PCT > 0 && costPct !== null && costPct >= COST_BLOCK_PCT) blockers.push(`السبريد ≈ ${costPct.toFixed(0)}% من الوقف على هذا الإطار — استخدم إطاراً أعلى`);
  const danger = news.find(e => e.impact === "High" && e.minutesUntil !== null && Math.abs(e.minutesUntil) <= 15);
  if (danger) blockers.push(`خبر عالي التأثير ${danger.currency} ${danger.title} خلال 15 دقيقة`);
  // Counter-trend filter: no trade AGAINST both the main trend (price vs SMA200)
  // and the higher-timeframe trend. One of them opposing is only a warning.
  if (dir !== "HOLD" && COUNTER_TREND_BLOCK) {
    const side = dir === "BUY" ? 1 : -1;
    const mainDir = trendUp === true ? 1 : trendUp === false ? -1 : 0;
    const htf = htfDirOf((d as any).htfBias);
    if (mainDir === -side && htf === -side) {
      blockers.push(`عكس الاتجاه: الاتجاه الرئيسي (SMA200) والإطار الأعلى كلاهما ${side > 0 ? "هابط" : "صاعد"} — لا ${side > 0 ? "شراء" : "بيع"} عكسهما`);
    } else if (mainDir === -side || htf === -side) {
      reasons.push(`⚠️ ${side > 0 ? "الشراء" : "البيع"} عكس ${mainDir === -side ? "الاتجاه الرئيسي" : "الإطار الأعلى"}`);
    }
  }

  // Quorum: "the answer most models agree on" needs at least 2 models answering.
  if (aiResults.length > 0 && ai.answered < MIN_AI_ANSWERS) {
    blockers.push(`استجاب ${ai.answered} من ${aiResults.length} نماذج AI فقط — القرار التوافقي يحتاج ${MIN_AI_ANSWERS} نماذج على الأقل (تحقق من مفاتيح/رصيد النماذج)`);
  }
  if ((d as any).poorData) blockers.push(`بيانات السوق غير صالحة (${(d as any).qualityNote} — ${(d as any).dataSource}) — لا توصية على بيانات غير حية`);
  if (blockers.length) dir = "HOLD";

  // ── Levels: AI levels only if they are sane, otherwise ATR-based ──
  let entry = NaN, sl = NaN, tp = NaN, rr = NaN, levelsFrom: "AI" | "ATR" | "" = "";
  if (dir !== "HOLD") {
    const px = tradePrice(d); // live quote at the analysis moment (else last close)
    const atr = d.ATR || px * 0.001;
    const isBuy = dir === "BUY";
    const candidates = aiResults
      .filter((r: any) => r.signal === dir)
      .sort((a: any, b: any) => b.confidence - a.confidence);
    for (const r of candidates) {
      const e = firstNumber(r.entry), s0 = firstNumber(r.sl), t0 = firstNumber(r.tp);
      const e1 = isFinite(e) ? e : px;
      if (!isFinite(s0) || !isFinite(t0)) continue;
      const risk = isBuy ? e1 - s0 : s0 - e1, reward = isBuy ? t0 - e1 : e1 - t0;
      if (risk >= 0.5 * atr && reward / risk >= MIN_RR && Math.abs(e1 - px) <= atr) {
        entry = e1; sl = s0; tp = t0; rr = reward / risk; levelsFrom = "AI"; break;
      }
    }
    if (!levelsFrom) {
      entry = px;
      sl = isBuy ? px - 1.5 * atr : px + 1.5 * atr;
      tp = isBuy ? px + 2.5 * atr : px - 2.5 * atr;
      rr = 2.5 / 1.5; levelsFrom = "ATR";
    }
  }
  // ── Binary expiry: fixed by the user, else median of the agreeing models,
  //    else from trend strength (strong trend → hold longer, range → shorter).
  let expiry: number | undefined, expiryFrom: Recommendation["expiryFrom"];
  if (binary && dir !== "HOLD") {
    const clampE = (n: number) => Math.max(2, Math.min(30, Math.round(n)));
    const votes = aiResults
      .filter((r: any) => r.signal === dir && Number.isFinite(r.expiryCandles) && r.expiryCandles >= 1)
      .map((r: any) => clampE(r.expiryCandles)).sort((a: number, b: number) => a - b);
    if (binary.expiry > 0) { expiry = binary.expiry; expiryFrom = "fixed"; }
    else if (votes.length) { expiry = votes[Math.floor((votes.length - 1) / 2)]; expiryFrom = "AI"; }
    else { const adx = d.ADX?.adx ?? 20; expiry = adx >= 30 ? 10 : adx >= 25 ? 7 : adx >= 20 ? 5 : 3; expiryFrom = "ADX"; }
  }
  return { dir, conf, entry, sl, tp, rr, levelsFrom, reasons, blockers, costPct, expiry, expiryFrom };
}

function buildRecommendation(
  pair: string,
  d: Awaited<ReturnType<typeof fetchMarket>>,
  aiResults: any[],
  news: NewsEvent[] = [],
): string[] {
  const rec = computeRecommendation(pair, d, aiResults, news);
  const dirLabel = rec.dir === "BUY" ? "🟢 <b>شراء</b>" : rec.dir === "SELL" ? "🔴 <b>بيع</b>" : "🟡 <b>انتظار</b>";
  const out = [
    ``,
    aiResults.some((r: any) => ["BUY", "SELL", "HOLD"].includes(r.signal))
      ? `<b>━━ ✅ القرار النهائي — الأكثر توافقاً بين نماذج AI ━━</b>`
      : `<b>━━ ✅ القرار النهائي — تحليل فني (بدون AI) ━━</b>`,
    rec.dir === "HOLD" ? dirLabel : `${dirLabel} | ثقة <code>${rec.conf}%</code>`,
    `📝 <i>${rec.reasons.join("، ")}.</i>`,
  ];
  for (const b of rec.blockers) out.push(`⛔ ${b}`);
  const binary = (d as any).binary as { expiry: number; tfMin: number } | undefined;
  if (binary) {
    if (rec.dir !== "HOLD") out.push(...binaryLines(d, rec, binary.tfMin));
    else if (!rec.blockers.length) out.push(`⏸️ <i>لا صفقة واضحة الآن — انتظر تحسّن التوافق.</i>`);
    out.push(`⚠️ <i>إدارة المخاطرة: لا تخاطر بأكثر من 1–2% من الرصيد في الصفقة.</i>`);
    return out;
  }
  if (rec.costPct !== null) out.push(`💸 تكلفة السبريد ≈ <code>${rec.costPct.toFixed(0)}%</code> من وقف الخسارة${rec.costPct >= 12 ? " ⚠️" : ""}`);
  if (rec.dir !== "HOLD") {
    out.push(`🎯 دخول <code>${d.fmt(rec.entry)}</code> | 🛑 وقف <code>${d.fmt(rec.sl)}</code> | 🎯 هدف <code>${d.fmt(rec.tp)}</code>`);
    out.push(`⚖️ العائد:المخاطرة <code>1:${rec.rr.toFixed(2)}</code> — ${rec.levelsFrom === "AI" ? "مستويات AI بعد التحقق" : "مستويات محسوبة من ATR (مستويات AI لم تجتز الفحص)"}`);
  } else if (!rec.blockers.length) {
    out.push(`⏸️ <i>لا صفقة واضحة الآن — انتظر تحسّن التوافق.</i>`);
  }
  out.push(`⚠️ <i>إدارة المخاطرة: لا تخاطر بأكثر من 1–2% من رأس المال.</i>`);
  return out;
}

/** Clock time in the owner's zone (HAYO_TZ, default Asia/Damascus) as "23:13:07 (UTC+3)". */
const OWNER_TZ = process.env.HAYO_TZ || "Asia/Damascus";
function localAndUtc(ms: number): string {
  try {
    const parts = new Intl.DateTimeFormat("en-GB", { timeZone: OWNER_TZ, hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false, timeZoneName: "shortOffset" }).formatToParts(new Date(ms));
    const get = (t: string) => parts.find(x => x.type === t)?.value ?? "";
    const off = get("timeZoneName").replace("GMT", "UTC");
    return `${get("hour")}:${get("minute")}:${get("second")} (${off === "UTC" ? "UTC+0" : off})`;
  } catch {
    return `${new Date(ms).toISOString().slice(11, 19)} (UTC)`;
  }
}

// ─── Compact signal messages ──────────────────────────────────────────
// Automatic signals are sent SHORT (what to do, at what price, how strong);
// the full analysis + chart stay one tap away behind "📋 التحليل الكامل".
interface CompactSignal {
  title: string; pair: string; tf: string; dir: "BUY" | "SELL";
  entry: number; fmt: (n: number) => string; strengthPct: number; strengthNote?: string; at: number;
  binary?: { candles: number; tfMin: number };
  forex?: { sl: number };
}
function compactSignalText(o: CompactSignal): string {
  const p = PAIRS[o.pair];
  const lines = [
    `<b>${o.title}</b>`,
    `${p.flag} <b>${p.label}</b> | <code>${o.tf}</code>`,
    o.binary ? (o.dir === "BUY" ? `🟢 <b>شراء — CALL</b>` : `🔴 <b>بيع — PUT</b>`) : (o.dir === "BUY" ? `🟢 <b>شراء</b>` : `🔴 <b>بيع</b>`),
    `💵 الدخول: <code>${o.fmt(o.entry)}</code>`,
  ];
  if (o.binary) {
    lines.push(`⌛ المدة: <b>${o.binary.candles} شموع</b> (${o.binary.candles * o.binary.tfMin} دقيقة)`);
  } else if (o.forex && isFinite(o.forex.sl)) {
    const r = Math.abs(o.entry - o.forex.sl), s = o.dir === "BUY" ? 1 : -1;
    lines.push(`🛑 وقف الخسارة: <code>${o.fmt(o.forex.sl)}</code>`);
    lines.push(`🎯 الهدف 1: <code>${o.fmt(o.entry + s * r)}</code>`);
    lines.push(`🎯 الهدف 2: <code>${o.fmt(o.entry + s * 2 * r)}</code>`);
    lines.push(`🎯 الهدف 3: <code>${o.fmt(o.entry + s * 3 * r)}</code>`);
  }
  lines.push(`💪 قوة الإشارة: <b>${o.strengthPct}%</b>${o.strengthNote ? ` <i>${o.strengthNote}</i>` : ""}`);
  lines.push(`⏱ ${localAndUtc(o.at)}`);
  return lines.join("\n");
}
const detailStore = new Map<string, { text: string; chart: Buffer | null; caption: string }>();
let detailSeq = 0;
function storeDetails(text: string, chart: Buffer | null, caption: string): string {
  const id = `${Date.now().toString(36)}${(++detailSeq).toString(36)}`;
  detailStore.set(id, { text, chart, caption });
  while (detailStore.size > 40) detailStore.delete(detailStore.keys().next().value as string);
  return id;
}
/** Send the short signal with a button that reveals the full analysis. */
async function sendCompactSignal(bot: TelegramBot, chatId: number, o: CompactSignal, fullText: string, chart: Buffer | null, caption: string): Promise<void> {
  const id = storeDetails(fullText, chart, caption);
  await bot.sendMessage(chatId, compactSignalText(o), {
    parse_mode: "HTML",
    reply_markup: { inline_keyboard: [[
      { text: "📋 التحليل الكامل", callback_data: `full:${id}` },
      { text: "🔄 إعادة تحليل", callback_data: `pair:${o.pair}` },
    ]] },
  });
}

/** Binary-options execution block: direction, entry price/time, expiry, win condition. */
function binaryLines(d: any, rec: Recommendation, tfMin: number): string[] {
  const dir = rec.dir, entry = rec.entry, n = rec.expiry ?? 5;
  const at = typeof d.liveAt === "number" ? d.liveAt : Date.now();
  const mins = n * tfMin;
  const from = rec.expiryFrom === "AI" ? "حدّدها AI (وسيط النماذج الموافِقة)" : rec.expiryFrom === "ADX" ? "من قوة الاتجاه ADX" : rec.expiryFrom === "model" ? "أفق نموذج الأوزان الذي اختُبر عليه" : "مدة ثابتة من الإعدادات";
  const breakEven = Math.round(100 / (1 + BINARY_PAYOUT));
  return [
    `<b>━━ 🎰 خيار ثنائي ━━</b>`,
    dir === "BUY" ? `🟢 <b>CALL — صعود</b>` : `🔴 <b>PUT — هبوط</b>`,
    `💵 سعر الدخول <code>${d.fmt(entry)}</code> ⏱ <i>${localAndUtc(at)}</i>`,
    `⌛ المدة: <b>${n} شموع</b> = ${mins} دقيقة → تنتهي ≈ <i>${localAndUtc(at + mins * 60_000)}</i>`,
    `<i>(${from})</i>`,
    `✅ تربح إذا كان السعر عند الانتهاء ${dir === "BUY" ? "أعلى" : "أدنى"} من <code>${d.fmt(entry)}</code>`,
    `📊 <i>نقطة التعادل: فوز ≥ ${breakEven}% من الصفقات (بعائد ${Math.round(BINARY_PAYOUT * 100)}%)</i>`,
  ];
}

// ─── Live signal journal (auto) ───────────────────────────────────────
// Every BUY/SELL recommendation the bot sends is logged and later graded
// (win/loss/expired) from real prices by the journal evaluator in router.ts,
// so the bot's REAL live hit-rate is measured without selection bias.
let ownerUserIdCache: number | null | undefined;
async function ownerUserId(): Promise<number | null> {
  if (ownerUserIdCache !== undefined) return ownerUserIdCache;
  try {
    const { db } = await import("@workspace/db");
    const { users } = await import("@workspace/db/schema");
    const { eq, asc } = await import("drizzle-orm");
    const [u] = await db.select({ id: users.id }).from(users).where(eq(users.role, "admin")).orderBy(asc(users.id)).limit(1);
    const id = u?.id ?? null;
    ownerUserIdCache = id;
    return id;
  } catch {
    ownerUserIdCache = null;
    return null;
  }
}

const journalDedup = new Map<string, number>();
async function journalRecommendation(pair: string, interval: string, rec: Recommendation, source: string): Promise<void> {
  const isBinary = source === "tg-bin" || source === "tg-wgt";
  if (rec.dir === "HOLD" || !isFinite(rec.entry) || (!isBinary && !isFinite(rec.sl))) return;
  const key = `${pair}|${interval}|${rec.dir}|${source}`;
  const dedupMs = isBinary ? 60 * 1000 : 30 * 60 * 1000;
  if (Date.now() - (journalDedup.get(key) ?? 0) < dedupMs) return; // same setup re-sent
  journalDedup.set(key, Date.now());
  try {
    const { insertSignalJournal, ensureSignalJournalSchema } = await import("../hayo/db.js");
    await ensureSignalJournalSchema();
    await insertSignalJournal({
      userId: await ownerUserId(), pair, timeframe: interval, direction: rec.dir,
      entry: rec.entry, stopLoss: isBinary ? rec.entry : rec.sl, takeProfit: isBinary ? null : rec.tp, confidence: rec.conf, source,
      note: isBinary ? `binary:${rec.expiry ?? 5}` : rec.levelsFrom === "AI" ? "levels: AI (validated)" : "levels: ATR",
    });
  } catch (err: any) { console.error("[Journal] insert failed:", err.message); }
}

/** One-line live track record of the bot's own recommendations. */
async function journalStatsLine(kind: boolean | "binary" | "weights" | "forex" = "forex"): Promise<string> {
  const k = kind === true ? "binary" : kind === false ? "forex" : kind;
  try {
    const { getJournalStats } = await import("../hayo/db.js");
    const st = await getJournalStats(await ownerUserId(), k);
    if (!st) return "";
    if (k !== "forex") {
      const title = k === "weights" ? "⚖️ سجل نظام الأوزان (حي)" : "🎰 سجل الإشارات الثنائية التلقائية";
      const n = Number(st.wins ?? 0) + Number(st.losses ?? 0);
      if (n === 0) return `<i>${title}: لا صفقات منتهية بعد (${st.open ?? 0} قيد الانتظار)</i>`;
      const be = Math.round(100 / (1 + BINARY_PAYOUT));
      return `<b>${title}:</b> ${n} صفقة | فوز <code>${st.winRate}%</code> (التعادل ${be}%) | صافي <code>${Number(st.totalR) >= 0 ? "+" : ""}${Number(st.totalR).toFixed(2)}</code> رهان${n < 30 ? " <i>(عينة صغيرة)</i>" : ""}`;
    }
    const closed = Number(st.wins ?? 0) + Number(st.losses ?? 0);
    if (closed === 0) return `📒 <i>سجل الإشارات الحي: لا صفقات مغلقة بعد (${st.open ?? 0} مفتوحة)</i>`;
    return `📒 <b>سجل الإشارات الحي:</b> ${closed} مغلقة | فوز <code>${st.winRate ?? Math.round(Number(st.wins) / closed * 100)}%</code> | متوسط <code>${Number(st.avgR ?? 0) >= 0 ? "+" : ""}${Number(st.avgR ?? 0).toFixed(2)}R</code>${closed < 30 ? " <i>(عينة صغيرة)</i>" : ""}`;
  } catch { return ""; }
}

function buildAIMsg(
  pair: string, tf: string,
  d: Awaited<ReturnType<typeof fetchMarket>>,
  aiResults: any[],
  isAutoSignal = false,
  news: NewsEvent[] = [],
  htfBias = "",
  journalLine = "",
) {
  const p = PAIRS[pair];
  const buys  = d.strategies.filter(s=>s.signal==="BUY").length;
  const sells = d.strategies.filter(s=>s.signal==="SELL").length;
  const ai = aiConsensus(aiResults);
  const aiCons = ai.label==="BUY"?"🟢 شراء":ai.label==="SELL"?"🔴 بيع":ai.label==="HOLD"?"🟡 انتظار":"⚖️ منقسم";
  const avgConf = ai.avgConf;
  const highImpactNews = news.filter(e=>e.impact==="High");
  // Live news countdown: nearest high-impact event + a danger/caution gate.
  const fmtCd = (m: number|null) => {
    if (m === null) return "";
    const a = Math.abs(m), h = Math.floor(a/60), mm = a%60, dur = h>0?`${h}س${mm}د`:`${mm}د`;
    return m >= 0 ? ` ⏳بعد ${dur}` : ` ✅منذ ${dur}`;
  };
  const nextHigh = highImpactNews.filter(e=>e.minutesUntil!==null).sort((a,b)=>Math.abs(a.minutesUntil!)-Math.abs(b.minutesUntil!))[0];
  const newsGate = nextHigh
    ? (Math.abs(nextHigh.minutesUntil!) <= 15
        ? `🚫 <b>منطقة خطر</b>: ${nextHigh.currency} ${nextHigh.title}${fmtCd(nextHigh.minutesUntil)} — تجنّب الدخول`
        : Math.abs(nextHigh.minutesUntil!) <= 60
        ? `⚠️ <b>حذر</b>: ${nextHigh.currency} ${nextHigh.title}${fmtCd(nextHigh.minutesUntil)} — قلّل المخاطرة`
        : `🟢 أقرب خبر عالي التأثير: ${nextHigh.currency} ${nextHigh.title}${fmtCd(nextHigh.minutesUntil)}`)
    : "";

  return [
    isAutoSignal ? `🔔 <b>إشارة تلقائية!</b>` : "",
    `${p.flag} <b>تحليل AI كامل — ${p.label}</b> | <code>${tf}</code>`,
    priceLine(d),
    dataLine(d),
    ``,
    `<b>━━ 📊 المؤشرات ━━</b>`,
    `RSI <code>${d.RSI.toFixed(1)}</code> ${d.RSI<30?"🔴 ذروة بيع":d.RSI>70?"🟢 ذروة شراء":"⚪"} | MACD ${d.MACD.macd>d.MACD.signal?"✅ صاعد":"❌ هابط"}`,
    `SMA20 ${d.price>d.SMA20?"✅":"❌"} | SMA50 ${d.price>d.SMA50?"✅":"❌"}${d.SMA200?" | SMA200 "+(d.price>d.SMA200?"✅":"❌"):""}`,
    `BB ${d.price<d.BB.lower?"↓ أسفل النطاق":d.price>d.BB.upper?"↑ أعلى النطاق":"↔ داخل النطاق"} | ATR <code>${d.fmt(d.ATR)}</code>`,
    ``,
    `<b>━━ 🎯 الاستراتيجيات (${buys}🟢 ${sells}🔴 ${d.strategies.length-buys-sells}🟡) ━━</b>`,
    ...d.strategies.map(s=>`${s.emoji} ${s.name}: ${sigIcon(s.signal)}${s.signal!=="NEUTRAL"?` <code>${s.strength}%</code>`:""}`),
    ``,
    `<b>━━ 🔍 الفلاتر ━━</b>`,
    ...d.filters.map(f=>`${f.passed?"✅":"⚠️"} ${f.emoji} ${f.name}: <i>${f.desc.split("—")[0].trim()}</i>`),
    ...(htfBias ? [``, `<b>━━ 🧭 الإطار الأعلى (MTF) ━━</b>`, `🧭 ${htfBias}`] : []),
    // News — live countdown + gate
    ...(highImpactNews.length>0 ? [
      ``,
      `<b>━━ 📰 أخبار عالية التأثير (حي) ━━</b>`,
      ...highImpactNews.map(e=>`🔴 ${e.currency} — ${e.title}${fmtCd(e.minutesUntil)}`),
      newsGate ? `🕒 ${newsGate}` : "",
    ] : news.length>0 ? [
      ``,
      `📰 أخبار متوسطة: ${news.map(e=>e.currency+"—"+e.title.slice(0,22)+fmtCd(e.minutesUntil)).join(" | ")}`,
    ] : []),
    ``,
    `<b>━━ 🤖 الذكاء الاصطناعي (${aiResults.length} نماذج — ${aiResults.filter((r:any)=>r.sawChart).length} قرأت الشارت 👁️) ━━</b>`,
    ...aiResults.map((r:any)=>r.signal==="ERROR"
      ? `${r.icon} <b>${r.name}</b>: ⚠️ غير متاح`
      : [
          `${r.icon} <b>${r.name}</b>${r.sawChart?" 👁️":""}: ${r.signal==="BUY"?"🟢 شراء":r.signal==="SELL"?"🔴 بيع":"🟡 انتظار"} <code>${r.confidence}%</code> | خطر: ${r.risk==="LOW"?"🟢 منخفض":r.risk==="HIGH"?"🔴 مرتفع":"🟡 متوسط"}`,
          ...(r.sawChart && r.chartReading ? [`   👁️ ${r.chartAgrees===false?"⚠️ الشارت يناقض المؤشرات":r.chartAgrees===true?"✅ الشارت يؤكد المؤشرات":"الشارت"}: <i>${escHtml(r.chartReading.slice(0,160))}${r.chartReading.length>160?"…":""}</i>`] : []),
          `   💬 <i>${escHtml(r.reasoning.slice(0,120))}${r.reasoning.length>120?"…":""}</i>`,
          `   🎯 دخول <code>${escHtml(r.entry)}</code> | SL <code>${escHtml(r.sl)}</code> | TP <code>${escHtml(r.tp)}</code>`,
        ].join("\n")
    ),
    ``,
    `┌────────────────────────────────┐`,
    `│  AI توافق: ${aiCons.padEnd(10)} ${ai.votes}/${ai.answered} | ثقة: ${avgConf}%  │`,
    `└────────────────────────────────┘`,
    ...buildRecommendation(pair, d, aiResults, news),
    journalLine,
    ``,
    `<i>⚠️ للأغراض التعليمية فقط — ليس توصية مالية</i>`,
  ].filter(l=>l!=="").join("\n");
}

// ─── Auto-Signal Scanner ─────────────────────────────────────────────
// Scans the selected pairs × timeframes (one of each, or all = SCAN). A pair/TF
// becomes a signal when:
//   1) technical agreement ≥ minConsensus (share of strategies that took a side),
//   2) with AI: the AI plurality decision equals that direction and the winning
//      models' average confidence ≥ minAIConfidence;
//      without AI: the technical final decision equals that direction,
//   3) the safety gates pass (spread cost, high-impact news).
// Each sent signal starts a 4h cooldown for that pair/TF (only when SENT).
let autoScanRunning = false;
let autoManualRunning = false;

interface ScanSummary { checked: number; sent: number; busy?: boolean; lines: string[] }

async function runAutoScan(bot: TelegramBot, ownerChatId: number, lastSignalTimeLocal: Map<string, number>, manual = false): Promise<ScanSummary> {
  const summary: ScanSummary = { checked: 0, sent: 0, lines: [] };
  if (!autoConfig.enabled && !manual) return summary;
  if (manual ? autoManualRunning : autoScanRunning) { summary.busy = true; return summary; }
  if (manual) autoManualRunning = true; else autoScanRunning = true;
  try {
    const { pairs, timeframes, minConsensus, minAIConfidence, useAI } = autoConfig;
    console.log(`[AutoScan] Scanning ${pairs.length} pairs × ${timeframes.length} TFs (${useAI ? "AI" : "technical"})`);
    for (const pair of pairs) {
      for (const tf of timeframes) {
        if (!TIMEFRAMES[tf] || !PAIRS[pair]) continue;
        const key = `${pair}:${tf}`;
        const label = `${PAIRS[pair].label} ${tf}`;
        // Binary: a new trade may open once the previous one expired.
        const tfMin = TF_MINUTES[tf] ?? 1;
        const busy = autoConfig.binary
          ? Date.now() < (binaryBusyUntil.get(key) ?? 0)
          : Date.now() - (lastSignalTimeLocal.get(key) || 0) < SIGNAL_COOLDOWN_MS;
        if (busy) {
          summary.lines.push(`⏸️ ${label}: ${autoConfig.binary ? "الصفقة الثنائية السابقة لم تنتهِ بعد" : "أُرسلت إشارة خلال آخر 4 ساعات"}`);
          continue;
        }
        try {
          await new Promise(r => setTimeout(r, 1500)); // rate limit between requests
          if (autoConfig.binary) {
            // Binary options run on the validated weighting model (1m / 5m).
            const modelId = BINARY_MODEL_BY_TF[tf];
            if (!modelId || !WEIGHT_MODELS[modelId]) {
              summary.lines.push(`➖ ${label}: الخيارات الثنائية تعمل بنظام الأوزان على فريم 1م و5م فقط`);
              continue;
            }
            if (!WEIGHTED_ASSETS.has(pair)) {
              summary.lines.push(`➖ ${label}: ⚖️ نموذج الأوزان مدرَّب على العملات والذهب فقط`);
              continue;
            }
            const datas: any[] = [];
            for (const k of WEIGHT_MODELS[modelId].tfs) { datas.push(await fetchMarket(pair, TIMEFRAMES[k])); await new Promise(r => setTimeout(r, 500)); }
            summary.checked++;
            const r = await weightedSignal(bot, ownerChatId, pair, modelId, datas, WEIGHT_MODELS[modelId].tfs,
              { useAI, summary, title: "🎰 خيار ثنائي — نظام الأوزان", expiryOverride: autoConfig.binaryExpiry || undefined });
            if (r.sent) binaryBusyUntil.set(key, Date.now() + r.expiryMs);
            continue;
          }
          const d = await fetchMarket(pair, TIMEFRAMES[tf]);
          summary.checked++;
          if ((d as any).poorData) {
            summary.lines.push(`⚠️ ${label}: بيانات غير صالحة من ${(d as any).dataSource} (${(d as any).qualityNote}) — تم التخطي`);
            continue;
          }
          const cons = calcConsensus(d.strategies);
          if (cons.direction === "NEUTRAL" || cons.pct < minConsensus) {
            summary.lines.push(`➖ ${label}: توافق فني غير كافٍ (${cons.buys}🟢 ${cons.sells}🔴)`);
            continue;
          }

          const [news, chart, htfBias] = await Promise.all([fetchEconomicNews(pair), renderPairChart(pair, tf, d), computeHtfBias(pair, tf)]);
          (d as any).htfBias = htfBias;
          let rec: Recommendation;
          let msg: string;
          if (useAI) {
            const aiResults = await runAI(pair, tf, d, news, chart, htfBias);
            rec = computeRecommendation(pair, d, aiResults, news);
            const ai = aiConsensus(aiResults);
            if (rec.dir !== cons.direction || ai.avgConf < minAIConfidence) {
              summary.lines.push(`🤖 ${label}: فني ${cons.direction === "BUY" ? "شراء" : "بيع"} لكن قرار AI ${rec.dir === "BUY" ? "شراء" : rec.dir === "SELL" ? "بيع" : "انتظار"} (ثقة ${ai.avgConf}%)${rec.blockers.length ? " — " + rec.blockers[0] : ""}`);
              continue;
            }
            await journalRecommendation(pair, TIMEFRAMES[tf].interval, rec, autoConfig.binary ? "tg-bin" : "tg-auto");
            msg = buildAIMsg(pair, tf, d, aiResults, true, news, htfBias, await journalStatsLine(autoConfig.binary));
          } else {
            rec = computeRecommendation(pair, d, [], news);
            if (rec.dir !== cons.direction) {
              summary.lines.push(`⛔ ${label}: ${rec.blockers[0] || "القرار الفني النهائي انتظار"}`);
              continue;
            }
            await journalRecommendation(pair, TIMEFRAMES[tf].interval, rec, autoConfig.binary ? "tg-bin" : "tg-auto-tech");
            msg = buildQuickMsg(pair, tf, d, news, await journalStatsLine(autoConfig.binary), autoConfig.binary ? `🎰 <b>إشارة خيار ثنائي — تحليل فني (بدون AI)</b>` : `🔔 <b>إشارة تلقائية — تحليل فني (بدون AI)</b>`);
          }

          if (autoConfig.binary) binaryBusyUntil.set(key, Date.now() + (rec.expiry ?? 5) * tfMin * 60_000);
          else lastSignalTimeLocal.set(key, Date.now());
          summary.sent++;
          summary.lines.push(`🚨 ${label}: ${rec.dir === "BUY" ? "🟢 شراء" : "🔴 بيع"} — أُرسلت إشارة`);
          console.log(`[AutoScan] 🚨 Signal: ${key} ${rec.dir} (tech ${cons.pct}%)`);
          await sendCompactSignal(bot, ownerChatId, {
            title: `📈 إشارة تلقائية${useAI ? " — AI" : " — فني"}`, pair, tf, dir: rec.dir as "BUY" | "SELL",
            entry: rec.entry, fmt: d.fmt, strengthPct: rec.conf, at: typeof (d as any).liveAt === "number" ? (d as any).liveAt : Date.now(),
            forex: { sl: rec.sl },
          }, msg, chart, `📸 ${PAIRS[pair].label} | ${tf} — الشارت الحي${useAI ? " الذي قرأته نماذج AI" : ""}`);
        } catch (err: any) {
          summary.lines.push(`⚠️ ${label}: خطأ في البيانات`);
          console.error(`[AutoScan] ${key} error:`, err.message);
        }
      }
    }
  } finally {
    if (manual) autoManualRunning = false; else autoScanRunning = false;
  }
  return summary;
}

function restartAutoScanner(bot: TelegramBot, ownerChatId: number, lastSignalTimeLocal: Map<string, number>) {
  if (autoScanTimer) {
    clearInterval(autoScanTimer);
    autoScanTimer = null;
  }
  if (!autoConfig.enabled) return;
  const ms = autoConfig.intervalMinutes * 60 * 1000;
  console.log(`[AutoScan] Started — interval ${autoConfig.intervalMinutes}min, pairs: ${autoConfig.pairs.join(",")}, TFs: ${autoConfig.timeframes.join(",")}`);
  // Run once immediately
  setTimeout(() => runAutoScan(bot, ownerChatId, lastSignalTimeLocal), 2000);
  autoScanTimer = setInterval(() => runAutoScan(bot, ownerChatId, lastSignalTimeLocal), ms);
}

// ─── Convergence Config ──────────────────────────────────────────────
export type ConvergencePreset = "fast" | "scalp" | "mid" | "long";
interface ConvergenceConfig {
  enabled: boolean;
  intervalMinutes: number;
  preset: ConvergencePreset;   // which 3 timeframes must agree
  pairs: string[];             // pairs to scan (one, several, or all = SCAN)
  useAI: boolean;              // AI plurality must confirm the match
}
let convergenceConfig: ConvergenceConfig = { enabled: true, intervalMinutes: 5, preset: "fast", pairs: Object.keys(PAIRS), useAI: true };
// ─── Settings persistence (DB) ────────────────────────────────────────
// Auto-signal and convergence settings are saved on every change and restored
// on startup, so a redeploy/restart keeps what the owner configured.
// Saves run strictly one after another and read the CURRENT config when they
// execute, so rapid button presses can't land out of order on the DB pool and
// leave an older snapshot as the final value.
let persistChain: Promise<void> = Promise.resolve();
function persistSetting(key: string, current: () => unknown): void {
  persistChain = persistChain
    .then(async () => { const m = await import("../hayo/db.js"); await m.saveBotSetting(key, current()); })
    .catch(() => {});
}
function persistAutoConfig(): void { persistSetting("autoConfig", () => autoConfig); }
function persistConvergenceConfig(): void { persistSetting("convergenceConfig", () => convergenceConfig); }
async function loadPersistedBotSettings(): Promise<void> {
  try {
    const { loadBotSetting } = await import("../hayo/db.js");
    const a = await loadBotSetting<Partial<AutoConfig>>("autoConfig");
    if (a && typeof a === "object") {
      autoConfig = {
        ...defaultAutoConfig, ...a,
        pairs: Array.isArray(a.pairs) ? a.pairs.filter(p => PAIRS[p]) : defaultAutoConfig.pairs,
        timeframes: Array.isArray(a.timeframes) ? a.timeframes.filter(t => TIMEFRAMES[t]) : defaultAutoConfig.timeframes,
      };
    }
    const c = await loadBotSetting<Partial<ConvergenceConfig>>("convergenceConfig");
    if (c && typeof c === "object") {
      convergenceConfig = {
        ...convergenceConfig, ...c,
        preset: c.preset && CONVERGENCE_PRESETS[c.preset] ? c.preset : convergenceConfig.preset,
        pairs: Array.isArray(c.pairs) ? c.pairs.filter(p => PAIRS[p]) : convergenceConfig.pairs,
      };
    }
    console.log(`[Settings] restored — auto: ${autoConfig.enabled ? "on" : "off"} (${autoConfig.pairs.length} pairs × ${autoConfig.timeframes.length} TFs, ${autoConfig.useAI ? "AI" : "tech"}), convergence: ${convergenceConfig.enabled ? "on" : "off"} (${convergenceConfig.preset}, ${convergenceConfig.pairs.length} pairs, ${convergenceConfig.useAI ? "AI" : "tech"})`);
  } catch (err: any) {
    console.error("[Settings] restore failed — using defaults:", err.message);
  }
}

/** The three timeframes that must agree, lowest → highest. Analysis/AI/chart use the highest. */
const CONVERGENCE_PRESETS: Record<ConvergencePreset, { keys: [string, string, string]; label: string }> = {
  fast: { keys: ["1m", "5m", "15m"], label: "سريع: 1م + 5م + 15م ⚖️ أوزان" },
  scalp: { keys: ["5m", "15m", "1h"], label: "سكالب: 5م + 15م + 1س ⚖️ أوزان" },
  mid:  { keys: ["15m", "1h", "4h"], label: "متوسط: 15م + 1س + 4س" },
  long: { keys: ["1h", "4h", "1d"],  label: "طويل: 1س + 4س + يومي" },
};
/** Presets decided by the learned weighting model (hayo/weights-model.ts). */
const CONVERGENCE_MODEL: Partial<Record<ConvergencePreset, string>> = { fast: "fast", scalp: "scalp" };
/** Auto-signal binary mode: which weighting model serves each low timeframe. */
const BINARY_MODEL_BY_TF: Record<string, string> = { "1m": "fast", "5m": "scalp" };
const WEIGHTED_ASSETS = new Set(["EURUSD", "USDJPY", "GBPUSD", "GBPJPY", "USDCHF", "AUDUSD", "NZDUSD", "USDCAD", "EURGBP", "EURJPY", "EURCHF", "AUDCAD", "XAUUSD", "XAGUSD"]);
let convergenceTimer: NodeJS.Timeout | null = null;
const convergenceCooldown = new Map<string, number>();
const CONVERGENCE_COOLDOWN_MS = 60 * 60 * 1000;

export interface ConvergenceSignal {
  pair: string;
  flag: string;
  direction: "BUY" | "SELL";
  avgPct: number;
  aiConfidence: number;
  aiModels: number;
  totalModels: number;
  price: string;
  timestamp: string;
  tfDetails: { tf: string; direction: string; pct: number; buys: number; sells: number }[];
  aiDetails: { name: string; icon: string; signal: string; confidence: number; entry: string; sl: string; tp: string; reasoning: string }[];
  newsWarnings: string[];
}

const convergenceSignals: ConvergenceSignal[] = [];
const MAX_CONVERGENCE_SIGNALS = 50;

export function getConvergenceConfig() { return { ...convergenceConfig }; }
let _botRef: TelegramBot | null = null;
let _ownerRef: number = 0;
export function setConvergenceConfig(patch: Partial<ConvergenceConfig>) {
  if (patch.enabled !== undefined) convergenceConfig.enabled = patch.enabled;
  if (patch.intervalMinutes !== undefined) convergenceConfig.intervalMinutes = patch.intervalMinutes;
  if (patch.preset !== undefined && CONVERGENCE_PRESETS[patch.preset]) convergenceConfig.preset = patch.preset;
  if (patch.useAI !== undefined) convergenceConfig.useAI = patch.useAI;
  if (patch.pairs !== undefined) convergenceConfig.pairs = patch.pairs.filter(p => PAIRS[p]);
  persistConvergenceConfig();
  if (_botRef && _ownerRef) restartConvergenceScanner(_botRef, _ownerRef);
}
export function getConvergenceSignals() { return [...convergenceSignals]; }
export function triggerConvergenceScan() { return _triggerConvergenceScanRef; }
export async function sendTestConvergenceSignal() {
  if (!_botRef || !_ownerRef) return "Bot not initialized";
  const testSignal: ConvergenceSignal = {
    pair: "XAUUSD", flag: "🥇", direction: "BUY",
    avgPct: 82, aiConfidence: 78, aiModels: 2, totalModels: 3,
    price: "3,245.50", timestamp: new Date().toISOString(),
    tfDetails: [
      { tf: "1m", direction: "BUY", pct: 78, buys: 6, sells: 2 },
      { tf: "5m", direction: "BUY", pct: 85, buys: 7, sells: 1 },
      { tf: "15m", direction: "BUY", pct: 83, buys: 7, sells: 1 },
    ],
    aiDetails: [
      { name: "GPT-4o", icon: "🧠", signal: "BUY", confidence: 82, entry: "3,244.00", sl: "3,238.00", tp: "3,260.00", reasoning: "اختراق مقاومة + RSI صاعد + MACD إيجابي" },
      { name: "Claude", icon: "🤖", signal: "BUY", confidence: 75, entry: "3,245.00", sl: "3,239.00", tp: "3,258.00", reasoning: "زخم صعودي قوي مدعوم بالمتوسطات" },
      { name: "Gemini", icon: "💎", signal: "SELL", confidence: 45, entry: "", sl: "", tp: "", reasoning: "إشارة غير مؤكدة" },
    ],
    newsWarnings: [],
  };
  convergenceSignals.unshift(testSignal);
  if (convergenceSignals.length > MAX_CONVERGENCE_SIGNALS) convergenceSignals.length = MAX_CONVERGENCE_SIGNALS;

  const tfDetails = testSignal.tfDetails.map(t =>
    `<code>${t.tf.padEnd(4)}</code> ${t.direction === "BUY" ? "🟢" : "🔴"} ${t.direction} <code>${t.pct}%</code> (${t.buys}🟢 ${t.sells}🔴)`
  ).join("\n");
  const aiDetails = testSignal.aiDetails.map((r: any) => {
    if (r.signal === "ERROR") return `${r.icon} <b>${r.name}</b>: ⚠️ غير متاح`;
    return [
      `${r.icon} <b>${r.name}</b>: ${r.signal === "BUY" ? "🟢 شراء" : r.signal === "SELL" ? "🔴 بيع" : "🟡 انتظار"} <code>${r.confidence}%</code>`,
      `   🎯 دخول <code>${escHtml(r.entry)}</code> | SL <code>${escHtml(r.sl)}</code> | TP <code>${escHtml(r.tp)}</code>`,
      `   💬 <i>${r.reasoning}</i>`,
    ].join("\n");
  }).join("\n");

  const msg = [
    `🎯🎯🎯 <b>تطابق كامل!</b> 🎯🎯🎯`,
    ``,
    `🥇 <b>XAUUSD — الذهب</b> — 🟢 شراء قوية`,
    `💰 السعر: <b>3,245.50</b>`,
    ``,
    `<b>━━ 📊 تطابق 3 فريمات ━━</b>`,
    tfDetails,
    `📊 متوسط التوافق: <b>82%</b>`,
    ``,
    `<b>━━ 🤖 تأكيد AI (2/3 نموذج) ━━</b>`,
    aiDetails,
    ``,
    `┌──────────────────────────────────┐`,
    `│  🎯 التطابق: 🟢 شراء  ثقة AI: 78%  │`,
    `│  3/3 فريمات متطابقة             │`,
    `└──────────────────────────────────┘`,
    ``,
    `<i>⚠️ إشارة اختبار — للتحقق من عمل النظام</i>`,
  ].join("\n");

  await _botRef.sendMessage(_ownerRef, msg, { parse_mode: "HTML" });
  console.log("[Test] ✅ Test convergence signal sent to Telegram");
  return "sent";
}

let _triggerConvergenceScanRef: (() => Promise<void>) | null = null;

const convergenceTfs = (): { key: string; cfg: TfConfig }[] =>
  CONVERGENCE_PRESETS[convergenceConfig.preset].keys.map(key => ({ key, cfg: TIMEFRAMES[key] }));

// A full scan (all pairs × 3 TFs, throttled for API limits) can outlast the
// interval; without this guard setInterval stacked concurrent scans.
// Manual scans have their own lock: pressing "scan now" must not wait for a
// long background scan of all pairs (≈ 7 min) to finish.
let convergenceScanRunning = false;
let convergenceManualRunning = false;

async function runConvergenceScan(bot: TelegramBot, ownerChatId: number, manual = false): Promise<ScanSummary> {
  const summary: ScanSummary = { checked: 0, sent: 0, lines: [] };
  if (!convergenceConfig.enabled && !manual) return summary;
  if (manual ? convergenceManualRunning : convergenceScanRunning) { console.log("[Convergence] previous scan still running — skipping"); summary.busy = true; return summary; }
  if (manual) convergenceManualRunning = true; else convergenceScanRunning = true;
  try { await runConvergenceScanInner(bot, ownerChatId, manual, summary); }
  finally { if (manual) convergenceManualRunning = false; else convergenceScanRunning = false; }
  return summary;
}

/**
 * For each selected pair: all 3 timeframes of the preset must point the same
 * way (technical agreement on each). Then the final decision on the highest TF
 * (AI plurality with AI on, technical decision with AI off, plus safety gates)
 * must agree before a signal is sent. A manual scan ignores the 1h cooldown.
 */
async function runConvergenceScanInner(bot: TelegramBot, ownerChatId: number, manual: boolean, summary: ScanSummary) {
  const pairsToScan = convergenceConfig.pairs.filter(p => PAIRS[p]);
  const useAI = convergenceConfig.useAI;
  console.log(`[Convergence] Scanning ${pairsToScan.length} pairs × ${CONVERGENCE_PRESETS[convergenceConfig.preset].label} (${useAI ? "AI" : "technical"})`);
  try {

  for (const pair of pairsToScan) {
    const coolKey = `conv:${pair}`;
    const lastSent = convergenceCooldown.get(coolKey) || 0;
    if (!manual && Date.now() - lastSent < CONVERGENCE_COOLDOWN_MS) continue;
    const plabel = PAIRS[pair].label;

    try {
      const results: { tf: string; direction: "BUY"|"SELL"|"NEUTRAL"; pct: number; data: any }[] = [];

      const tfs = convergenceTfs();
      const topTf = tfs[tfs.length - 1];
      for (const { key, cfg } of tfs) {
        await new Promise(r => setTimeout(r, 2000)); // gentle pacing (Yahoo/OANDA first; TwelveData only as fallback)
        const d = await fetchMarket(pair, cfg);
        if ((d as any).poorData) throw new Error(`POOR_DATA ${cfg.interval} (${(d as any).dataSource})`);
        const cons = calcConsensus(d.strategies);
        results.push({ tf: key, direction: cons.direction, pct: cons.pct, data: d });
      }

      summary.checked++;
      const dirs = results.map(r => r.direction);
      const icons = results.map(r => `${r.tf}${r.direction === "BUY" ? "🟢" : r.direction === "SELL" ? "🔴" : "🟡"}`).join(" ");
      const modelId = CONVERGENCE_MODEL[convergenceConfig.preset];
      if (modelId && WEIGHT_MODELS[modelId]) {
        await weightedConvergence(bot, ownerChatId, pair, modelId, results, tfs, icons, useAI, summary, coolKey);
        continue;
      }
      const allBuy  = dirs.every(d => d === "BUY");
      const allSell = dirs.every(d => d === "SELL");
      if (!allBuy && !allSell) {
        summary.lines.push(`➖ ${plabel}: لا تطابق (${icons})`);
        continue;
      }

      const convergenceDir: "BUY" | "SELL" = allBuy ? "BUY" : "SELL";
      const avgPct = Math.round(results.reduce((a, r) => a + r.pct, 0) / results.length);
      console.log(`[Convergence] 🎯 ${pair} MATCH ${convergenceDir} on ${tfs.map(t => t.key).join("/")} — deciding (${useAI ? "AI" : "technical"})...`);

      const topData = results[2].data;
      const [news, chart, htfBias] = await Promise.all([fetchEconomicNews(pair), renderPairChart(pair, topTf.key, topData), computeHtfBias(pair, topTf.key)]);
      (topData as any).htfBias = htfBias;
      const aiResults: any[] = useAI
        ? await runAI(pair, `${topTf.key} (تطابق ${tfs.map(t => t.key).join(" + ")})`, topData, news, chart, htfBias)
        : [];
      const ai = aiConsensus(aiResults);
      const validAI = aiResults.filter((r: any) => r.signal === convergenceDir);
      const avgConf = ai.avgConf;

      // The final decision (AI plurality, or technical without AI) + safety
      // gates must agree with the 3-timeframe match.
      const rec = computeRecommendation(pair, topData, aiResults, news);
      if (rec.dir !== convergenceDir) {
        summary.lines.push(`🎯 ${plabel}: تطابق ${convergenceDir === "BUY" ? "شراء" : "بيع"} (${icons}) لكن القرار النهائي ${rec.dir === "HOLD" ? "انتظار" : rec.dir === "BUY" ? "شراء" : "بيع"}${rec.blockers.length ? " — " + rec.blockers[0] : ""}`);
        continue;
      }
      summary.sent++;
      summary.lines.push(`🚨 ${plabel}: تطابق ${convergenceDir === "BUY" ? "🟢 شراء" : "🔴 بيع"} (${icons}) — أُرسلت إشارة`);

      convergenceCooldown.set(coolKey, Date.now());
      await journalRecommendation(pair, topTf.cfg.interval, rec, useAI ? "tg-conv" : "tg-conv-tech");
      const journalLine = await journalStatsLine();

      const p = PAIRS[pair];
      const d15 = results[2].data;
      const filtersInfo = d15.filters.map((f: any) => `${f.passed?"✅":"⚠️"} ${f.emoji} ${f.name}`).join("\n");

      const tfDetailsArr = results.map(r => {
        const buys = r.data.strategies.filter((s: Sig) => s.signal === "BUY").length;
        const sells = r.data.strategies.filter((s: Sig) => s.signal === "SELL").length;
        return { tf: r.tf, direction: r.direction, pct: r.pct, buys, sells };
      });
      const tfDetails = tfDetailsArr.map(t =>
        `<code>${t.tf.padEnd(4)}</code> ${t.direction === "BUY" ? "🟢" : "🔴"} ${t.direction} <code>${t.pct}%</code> (${t.buys}🟢 ${t.sells}🔴)`
      ).join("\n");

      const aiDetailsArr = aiResults.map((r: any) => ({
        name: r.name || r.provider, icon: r.icon || "",
        signal: r.signal || "ERROR", confidence: r.confidence || 0,
        entry: r.entry || "", sl: r.sl || "", tp: r.tp || "",
        reasoning: r.reasoning || "",
      }));
      const aiDetails = aiResults.map((r: any) => {
        if (r.signal === "ERROR") return `${r.icon} <b>${r.name}</b>: ⚠️ غير متاح`;
        return [
          `${r.icon} <b>${r.name}</b>: ${r.signal === "BUY" ? "🟢 شراء" : r.signal === "SELL" ? "🔴 بيع" : "🟡 انتظار"} <code>${r.confidence}%</code>`,
          `   🎯 دخول <code>${escHtml(r.entry)}</code> | SL <code>${escHtml(r.sl)}</code> | TP <code>${escHtml(r.tp)}</code>`,
          ...(r.sawChart && r.chartReading ? [`   👁️ <i>${escHtml(r.chartReading.slice(0, 120))}</i>`] : []),
          `   💬 <i>${escHtml(r.reasoning.slice(0, 100))}${r.reasoning.length > 100 ? "…" : ""}</i>`,
        ].join("\n");
      }).join("\n");

      const highImpactNews = news.filter(e => e.impact === "High");

      const convSignal: ConvergenceSignal = {
        pair, flag: p.flag, direction: convergenceDir as "BUY"|"SELL",
        avgPct, aiConfidence: avgConf, aiModels: validAI.length, totalModels: aiResults.length,
        price: d15.fmt(d15.price), timestamp: new Date().toISOString(),
        tfDetails: tfDetailsArr, aiDetails: aiDetailsArr,
        newsWarnings: highImpactNews.map(e => `${e.currency} — ${e.title}`),
      };
      convergenceSignals.unshift(convSignal);
      if (convergenceSignals.length > MAX_CONVERGENCE_SIGNALS) convergenceSignals.length = MAX_CONVERGENCE_SIGNALS;

      const msg = [
        `🎯🎯🎯 <b>تطابق كامل!</b> 🎯🎯🎯`,
        ``,
        `${p.flag} <b>${p.label}</b> — ${convergenceDir === "BUY" ? "🟢 شراء قوية" : "🔴 بيع قوي"}`,
        priceLine(d15),
        ``,
        `<b>━━ 📊 تطابق 3 فريمات ━━</b>`,
        tfDetails,
        `📊 متوسط التوافق: <b>${avgPct}%</b>`,
        ``,
        `<b>━━ 📈 المؤشرات (${topTf.key}) ━━</b>`,
        `RSI <code>${d15.RSI.toFixed(1)}</code> ${d15.RSI < 30 ? "🔴 ذروة بيع" : d15.RSI > 70 ? "🟢 ذروة شراء" : "⚪"} | MACD ${d15.MACD.macd > d15.MACD.signal ? "✅ صاعد" : "❌ هابط"}`,
        `SMA20 ${d15.price > d15.SMA20 ? "✅" : "❌"} | SMA50 ${d15.price > d15.SMA50 ? "✅" : "❌"}${d15.SMA200 ? " | SMA200 " + (d15.price > d15.SMA200 ? "✅" : "❌") : ""}`,
        `BB ${d15.price < d15.BB.lower ? "↓ أسفل" : d15.price > d15.BB.upper ? "↑ أعلى" : "↔ داخل"} | ATR <code>${d15.fmt(d15.ATR)}</code>`,
        ``,
        `<b>━━ 🎯 الاستراتيجيات (${topTf.key}) ━━</b>`,
        ...d15.strategies.map((s: Sig) => `${s.emoji} ${s.name}: ${s.signal === "BUY" ? "🟢" : s.signal === "SELL" ? "🔴" : "🟡"} ${s.signal !== "NEUTRAL" ? `<code>${s.strength}%</code>` : ""}`),
        ``,
        `<b>━━ 🔍 الفلاتر ━━</b>`,
        filtersInfo,
        ...(highImpactNews.length > 0 ? [
          ``,
          `<b>━━ 📰 تحذير أخبار ━━</b>`,
          ...highImpactNews.map(e => `🔴 ${e.currency} — ${e.title}`),
          `<i>⚠️ احذر من التداول!</i>`,
        ] : []),
        ``,
        ...(useAI ? [
          `<b>━━ 🤖 نماذج AI (${ai.buys}🟢 ${ai.sells}🔴 ${ai.holds}🟡 من ${ai.answered}) ━━</b>`,
          aiDetails,
          ``,
        ] : []),
        `┌──────────────────────────────────┐`,
        `│  🎯 التطابق: ${convergenceDir === "BUY" ? "🟢 شراء" : "🔴 بيع"}${useAI ? `  ثقة AI: ${avgConf}%` : "  (فني)"}  │`,
        `│  3/3 فريمات متطابقة             │`,
        `└──────────────────────────────────┘`,
        ...buildRecommendation(pair, d15, aiResults, news),
        journalLine,
        ``,
        `<i>⚠️ للأغراض التعليمية فقط — ليس توصية مالية</i>`,
      ].join("\n");

      await sendCompactSignal(bot, ownerChatId, {
        title: `🎯 تطابق 3 فريمات${useAI ? " + AI" : ""}`, pair, tf: tfs.map(t => t.key).join("/"), dir: convergenceDir,
        entry: rec.entry, fmt: d15.fmt, strengthPct: rec.conf, at: typeof d15.liveAt === "number" ? d15.liveAt : Date.now(),
        forex: { sl: rec.sl },
      }, msg, chart, `📸 ${p.label} | ${topTf.key} — الشارت الحي${useAI ? " الذي قرأته نماذج AI" : ""}`);

    } catch (err: any) {
      summary.lines.push(String(err?.message || "").startsWith("POOR_DATA")
        ? `⚠️ ${plabel}: بيانات منخفضة الجودة على ${String(err.message).split(" ")[1]} — تم التخطي`
        : `⚠️ ${plabel}: خطأ في البيانات`);
      console.error(`[Convergence] ${pair} error:`, err.message);
    }
  }
  } catch (outerErr: any) {
    console.error(`[Convergence] Fatal scan error:`, outerErr.message || outerErr);
  }
}

/**
 * Weighted signal: the learned model reads trend / momentum / extension / POC
 * measures on 3 timeframes and outputs P(up after H bars). Signal only at
 * grade B (p≥0.56 / ≤0.44) or A (≥0.58 / ≤0.42) — the levels that were
 * profitable out-of-sample. AI (if on) can only VETO with a majority for the
 * opposite side; news/data gates still apply. Shared by the convergence
 * scanner and the auto-signals binary mode.
 */
async function weightedSignal(
  bot: TelegramBot, ownerChatId: number, pair: string, modelId: string,
  datas: any[], tfKeys: string[],
  opts: { useAI: boolean; summary: ScanSummary; title: string; expiryOverride?: number; icons?: string },
): Promise<{ sent: boolean; expiryMs: number }> {
  const none = { sent: false, expiryMs: 0 };
  const p = PAIRS[pair];
  const label = `${p.label} ${tfKeys[0]}`;
  const summary = opts.summary;
  // Trained on FX + gold only — crypto, oil and indices behave differently.
  if (!WEIGHTED_ASSETS.has(pair)) {
    summary.lines.push(`➖ ${label}: ⚖️ نموذج الأوزان مدرَّب على العملات والذهب فقط — تم التخطي`);
    return none;
  }
  if (datas.some(d => d.poorData)) { summary.lines.push(`⚠️ ${label}: بيانات غير صالحة — تم التخطي`); return none; }
  const v = weightedVerdict(modelId, datas.map(d => d.candles));
  if (!v) { summary.lines.push(`⚠️ ${label}: شموع غير كافية لنموذج الأوزان`); return none; }
  const pTxt = `${(v.p * 100).toFixed(1)}%`;
  if (v.dir === "HOLD") {
    summary.lines.push(`➖ ${label}: ⚖️ احتمال الصعود ${pTxt} — لا أفضلية كافية${opts.icons ? ` (${opts.icons})` : ""}`);
    return none;
  }
  const lowData = datas[0];
  const topKey = tfKeys[tfKeys.length - 1];
  const [news, chart, htfBias] = await Promise.all([fetchEconomicNews(pair), renderPairChart(pair, tfKeys[0], lowData), computeHtfBias(pair, topKey)]);

  const danger = news.find(e => e.impact === "High" && e.minutesUntil !== null && Math.abs(e.minutesUntil) <= 15);
  if (danger) { summary.lines.push(`⛔ ${label}: ⚖️ ${v.dir === "BUY" ? "شراء" : "بيع"} لكن خبر عالي التأثير ${danger.currency} خلال 15 دقيقة`); return none; }

  let aiResults: any[] = [];
  let ai = aiConsensus([]);
  if (opts.useAI) {
    aiResults = await runAI(pair, `${tfKeys[0]} (أوزان ${tfKeys.join(" + ")})`, lowData, news, chart, htfBias);
    ai = aiConsensus(aiResults);
    const opposite = v.dir === "BUY" ? "SELL" : "BUY";
    if (ai.answered >= MIN_AI_ANSWERS && ai.label === opposite) {
      summary.lines.push(`🤖 ${label}: ⚖️ ${v.dir === "BUY" ? "شراء" : "بيع"} (${pTxt}) لكن أغلبية AI ${opposite === "BUY" ? "شراء" : "بيع"} — تم الإلغاء`);
      return none;
    }
  }

  const tfMin = TF_MINUTES[tfKeys[0]] ?? 1;
  const candles = opts.expiryOverride && opts.expiryOverride > 0 ? opts.expiryOverride : v.horizon;
  summary.sent++;
  summary.lines.push(`🚨 ${label}: ⚖️ ${v.dir === "BUY" ? "🟢 شراء" : "🔴 بيع"} ${pTxt} (درجة ${v.grade}) — أُرسلت إشارة`);

  const entry = tradePrice(lowData);
  const at = typeof lowData.liveAt === "number" ? lowData.liveAt : Date.now();
  const rec: Recommendation = {
    dir: v.dir, conf: v.edgePct, entry, sl: NaN, tp: NaN, rr: NaN, levelsFrom: "",
    reasons: [], blockers: [], costPct: null, expiry: candles, expiryFrom: candles === v.horizon ? "model" : "fixed",
  };
  await journalRecommendation(pair, TIMEFRAMES[tfKeys[0]].interval, rec, "tg-wgt");
  const journalLine = await journalStatsLine("weights");

  const dirProb = Math.round((v.dir === "BUY" ? v.p : 1 - v.p) * 1000) / 10;
  const pct = (x: number) => `${x >= 0 ? "+" : ""}${x.toFixed(2)}`;
  const drivers = v.top.map(t => `• <code>${t.tf}</code> ${t.reading} <i>(${t.label})</i> <code>${pct(t.contribution)}</code>`).join("\n");
  const tfLines = datas.map((d, i) => {
    const c = calcConsensus(d.strategies);
    return `<code>${tfKeys[i].padEnd(4)}</code> ${c.direction === "BUY" ? "🟢" : c.direction === "SELL" ? "🔴" : "🟡"} استراتيجيات ${c.direction === "NEUTRAL" ? "محايدة" : `${c.pct}%`}`;
  }).join("\n");
  const aiLine = opts.useAI
    ? (ai.answered ? `🤖 AI (${ai.answered} نماذج): ${ai.buys}🟢 ${ai.sells}🔴 ${ai.holds}🟡 — ${ai.answered >= MIN_AI_ANSWERS ? "لا اعتراض" : "استشاري فقط (أقل من نموذجين)"}` : "🤖 AI: لم يستجب أي نموذج — القرار لنموذج الأوزان")
    : "";
  const full = [
    `⚖️ <b>${opts.title} — التحليل الكامل</b>`,
    `${p.flag} <b>${p.label}</b> — ${v.dir === "BUY" ? "🟢 شراء (CALL)" : "🔴 بيع (PUT)"} | درجة <b>${v.grade}</b>`,
    priceLine(lowData),
    dataLine(lowData),
    ``,
    `<b>━━ ⚖️ قرار النموذج ━━</b>`,
    `احتمال الصعود بعد ${v.horizon} شموع (${tfKeys[0]}): <b>${pTxt}</b>`,
    v.expectedWinRate !== null ? `📈 دقة هذه الدرجة في اختبار 2019 (بيانات لم يرها النموذج): <b>${v.expectedWinRate}%</b>` : "",
    `<b>أقوى العوامل:</b>`,
    drivers,
    ``,
    `<b>━━ 📊 الفريمات ━━</b>`,
    tfLines,
    htfBias ? `🧭 ${htfBias}` : "",
    aiLine,
    ``,
    ...binaryLines(lowData, rec, tfMin),
    journalLine,
    `<i>⚠️ للأغراض التعليمية فقط — ليس توصية مالية</i>`,
  ].filter(l => l !== "").join("\n");

  await sendCompactSignal(bot, ownerChatId, {
    title: opts.title, pair, tf: tfKeys[0], dir: v.dir, entry, fmt: lowData.fmt, at,
    strengthPct: dirProb, strengthNote: `(درجة ${v.grade}${v.expectedWinRate !== null ? ` — دقة الاختبار ${v.expectedWinRate}%` : ""})`,
    binary: { candles, tfMin },
  }, full, chart, `📸 ${p.label} | ${tfKeys[0]} — الشارت الحي`);
  console.log(`[Weights] ⚖️ ${pair} ${tfKeys[0]} ${v.dir} p=${v.p.toFixed(3)} grade ${v.grade} (${modelId})`);
  return { sent: true, expiryMs: candles * tfMin * 60_000 };
}

async function weightedConvergence(
  bot: TelegramBot, ownerChatId: number, pair: string, modelId: string,
  results: { tf: string; direction: "BUY" | "SELL" | "NEUTRAL"; pct: number; data: any }[],
  tfs: { key: string; cfg: TfConfig }[], icons: string, useAI: boolean, summary: ScanSummary, coolKey: string,
): Promise<void> {
  const r = await weightedSignal(bot, ownerChatId, pair, modelId, results.map(x => x.data), tfs.map(t => t.key),
    { useAI, summary, title: "⚖️ تطابق — نظام الأوزان", icons });
  if (r.sent) convergenceCooldown.set(coolKey, Date.now() - CONVERGENCE_COOLDOWN_MS + r.expiryMs);
}

function restartConvergenceScanner(bot: TelegramBot, ownerChatId: number) {
  if (convergenceTimer) { clearInterval(convergenceTimer); convergenceTimer = null; }
  _triggerConvergenceScanRef = async () => { await runConvergenceScan(bot, ownerChatId, true); };
  if (!convergenceConfig.enabled) return;
  const ms = convergenceConfig.intervalMinutes * 60 * 1000;
  console.log(`[Convergence] Started — interval ${convergenceConfig.intervalMinutes}min, all ${Object.keys(PAIRS).length} pairs`);
  setTimeout(() => runConvergenceScan(bot, ownerChatId).catch(e => console.error("[Convergence] scan error:", e.message)), 3000);
  convergenceTimer = setInterval(() => runConvergenceScan(bot, ownerChatId).catch(e => console.error("[Convergence] scan error:", e.message)), ms);
}

// ─── Bot Initialization ───────────────────────────────────────────────
/**
 * Start the bot.
 * - webhookUrl supplied  → webhook mode (production): no polling, registers webhook with Telegram
 * - webhookUrl undefined → polling mode (dev / FORCE_BOT=true)
 * Returns the bot instance so callers can attach Express webhook route.
 */
export function startTelegramBot(webhookUrl?: string, tokenOverride?: string, botRole: "trading" | "bridge" = "bridge"): TelegramBot | undefined {
  const token = tokenOverride || BOT_TOKEN;
  if (!token)    { console.log("[TelegramBot] Bot token not set — disabled"); return; }
  if (!OWNER_ID) { console.log("[TelegramBot] TELEGRAM_OWNER_CHAT_ID not set — disabled"); return; }

  const useWebhook = !!webhookUrl;
  const botLabel = botRole === "trading" ? "[Bot1-Trading]" : "[Bot2-Bridge]";

  const bot = new TelegramBot(token, {
    polling: !useWebhook ? { interval: 3000, autoStart: true, params: { timeout: 10 } } : false,
  });

  if (!useWebhook) {
    fetch(`https://api.telegram.org/bot${token}/deleteWebhook?drop_pending_updates=true`, { method: "POST" })
      .then(r => r.json())
      .then((d: any) => console.log(`${botLabel} deleteWebhook:`, d.description || "ok"))
      .catch(() => {});
  }
  // Override polling error handler to include bot role in log
  (bot as any).on("polling_error", (err: any) => {
    const msg = err?.message || String(err);
    if (msg.includes("409 Conflict")) {
      console.warn(`${botLabel} 409 Conflict — another instance may be running with this token`);
    } else if (!msg.includes("EFATAL")) {
      console.warn(`${botLabel} Polling error:`, msg.slice(0, 120));
    }
  });
  const ownerChatId = parseInt(OWNER_ID, 10);
  const isOwner = (chatId: number) => chatId === ownerChatId;

  // Per-instance session state (each bot has its own, no cross-bot contamination)
  const sessions = new Map<number, Session>();
  function getSession(chatId: number): Session {
    if (!sessions.has(chatId)) sessions.set(chatId, {});
    return sessions.get(chatId)!;
  }
  const lastSignalTimeLocal = new Map<string, number>();

  // ── Safe send helper — falls back to plain text if Markdown parse fails ──
  function stripMd(text: string): string {
    // Remove Markdown formatting characters that Telegram can't parse
    return text.replace(/[*_`\[\]]/g, "");
  }

  async function safeSend(
    chatId: number,
    text: string,
    opts: TelegramBot.SendMessageOptions = {}
  ): Promise<void> {
    const truncated = text.substring(0, 4096);
    try {
      await bot.sendMessage(chatId, truncated, { parse_mode: "Markdown", ...opts });
    } catch (e: any) {
      if (e?.message?.includes("can't parse entities") || e?.response?.body?.description?.includes("can't parse entities")) {
        // Retry as plain text, stripping markdown symbols
        const plain = stripMd(truncated);
        await bot.sendMessage(chatId, plain, { ...opts, parse_mode: undefined });
      } else {
        throw e;
      }
    }
  }

  // ── Send menus ──────────────────────────────────────────────────
  async function sendPairsMenu(chatId: number, editing?: number) {
    const status = autoConfig.enabled
      ? `🤖 الإشارات التلقائية: <b>✅ مفعّلة</b>\n📋 ${autoConfig.pairs.join(", ")} | كل ${autoConfig.intervalMinutes} دقيقة\n`
      : `🤖 الإشارات التلقائية: <b>❌ معطّلة</b>\n`;
    const text = `🏦 <b>HAYO Trading Bot</b>\n\n${status}\nاختر الزوج الذي تريد تحليله:`;
    if (editing) {
      await bot.editMessageText(text, { chat_id:chatId, message_id:editing, parse_mode:"HTML", reply_markup:pairsKeyboard() });
    } else {
      await bot.sendMessage(chatId, text, { parse_mode:"HTML", reply_markup:pairsKeyboard() });
    }
  }

  async function sendTfMenu(chatId: number, editing?: number) {
    const session = getSession(chatId);
    const p = PAIRS[session.pair!];
    const text = `${p.flag} <b>${p.label}</b> — اختر الإطار الزمني:`;
    if (editing) {
      await bot.editMessageText(text, { chat_id:chatId, message_id:editing, parse_mode:"HTML", reply_markup:timeframesKeyboard() });
    } else {
      await bot.sendMessage(chatId, text, { parse_mode:"HTML", reply_markup:timeframesKeyboard() });
    }
  }

  async function sendAnalysisMenu(chatId: number, editing?: number) {
    const session = getSession(chatId);
    const p = PAIRS[session.pair!];
    const text = `${p.flag} <b>${p.label}</b> | <code>${session.tf}</code>\n\nاختر نوع التحليل:`;
    if (editing) {
      await bot.editMessageText(text, { chat_id:chatId, message_id:editing, parse_mode:"HTML", reply_markup:analysisTypeKeyboard() });
    } else {
      await bot.sendMessage(chatId, text, { parse_mode:"HTML", reply_markup:analysisTypeKeyboard() });
    }
  }

  async function sendAutoMenu(chatId: number, editing?: number) {
    persistAutoConfig(); // called after every settings change
    const text = [
      `⚙️ <b>إعدادات الإشارات التلقائية</b>`,
      ``,
      `الحالة: ${autoConfig.enabled ? "✅ <b>مفعّلة</b>" : "❌ <b>معطّلة</b>"}`,
      `التداول: ${autoConfig.binary ? `🎰 <b>خيارات ثنائية</b> — CALL/PUT، المدة: ${autoConfig.binaryExpiry ? `${autoConfig.binaryExpiry} شموع` : "تلقائية (يحددها التحليل)"}، بلا بوابة سبريد` : "📈 <b>فوركس</b> — دخول/وقف/هدف"}`,
      `النوع: ${autoConfig.useAI ? "🤖 <b>مع AI</b> — القرار = الأكثر توافقاً بين النماذج" : "⚡ <b>بدون AI</b> — قرار فني من الاستراتيجيات والفلاتر"}`,
      `الأزواج: <code>${autoConfig.pairs.length === Object.keys(PAIRS).length ? "جميع الأزواج (SCAN)" : autoConfig.pairs.join(", ")||"لا يوجد"}</code>`,
      `الإطارات: <code>${autoConfig.timeframes.join(", ")||"لا يوجد"}</code>`,
      `فترة الفحص: كل <code>${autoConfig.intervalMinutes}</code> دقيقة`,
      `الحد الأدنى للتوافق: <code>${autoConfig.minConsensus}%</code>`,
      ...(autoConfig.useAI ? [`ثقة AI الأدنى: <code>${autoConfig.minAIConfidence}%</code>`] : []),
      ``,
      `<i>عند ظهور إشارة شراء/بيع قوية تصلك رسالة تفصيلية تلقائياً.</i>`,
      `اضغط ✅ على خيار لتفعيله أو إلغائه:`,
    ].join("\n");
    if (editing) {
      await bot.editMessageText(text, { chat_id:chatId, message_id:editing, parse_mode:"HTML", reply_markup:autoMenuKeyboard() });
    } else {
      await bot.sendMessage(chatId, text, { parse_mode:"HTML", reply_markup:autoMenuKeyboard() });
    }
  }

  // ── /start ─────────────────────────────────────────────────────
  // ═══════════════════════════════════════════════════════════════
  // HAYO Bridge Bot — Full Platform Control from Telegram
  // ═══════════════════════════════════════════════════════════════

  // Main Menu Keyboard
  function mainMenuKeyboard(): TelegramBot.InlineKeyboardMarkup {
    return {
      inline_keyboard: [
        [
          { text: "💬 دردشة AI", callback_data: "bridge:chat" },
          { text: "🤖 وكيل الكود", callback_data: "bridge:agent" },
        ],
        [
          { text: "📱 منشئ تطبيقات", callback_data: "bridge:appbuilder" },
          { text: "🔬 هندسة عكسية", callback_data: "bridge:reverse" },
        ],
        [
          { text: "📄 أعمال مكتبية", callback_data: "bridge:office" },
          { text: "📊 دراسات", callback_data: "bridge:studies" },
        ],
        [
          { text: "🪄 مصنع برومبت", callback_data: "bridge:prompt" },
          { text: "🗺️ خرائط ذهنية", callback_data: "bridge:mindmap" },
        ],
        [
          { text: "⚙️ EA Factory", callback_data: "bridge:ea" },
          { text: "🎨 توليد صور", callback_data: "bridge:image" },
        ],
        [
          { text: "📈 تحليل أسواق", callback_data: "pair_menu" },
          { text: "🔍 OSINT", callback_data: "bridge:osint" },
        ],
        [
          { text: "🚀 منفّذ ذكي (صيانة)", callback_data: "bridge:executive" },
        ],
        [
          { text: `📡 إشارات تلقائية ${autoConfig.enabled ? "✅" : "❌"}`, callback_data: "auto:menu" },
          { text: `🎯 التطابق ${convergenceConfig.enabled ? "✅" : "❌"}`, callback_data: "conv:menu" },
        ],
      ],
    };
  }

  // Session extended for bridge
  interface BridgeSession {
    mode?: "chat" | "agent" | "appbuilder" | "office" | "studies" | "prompt" | "image" | "ea" | "maintenance" | "executive" | "osint" | "mindmap" | "reverse";
    subStep?: string;
    data?: Record<string, any>;
  }
  const bridgeSessions = new Map<number, BridgeSession>();
  function getBridgeSession(chatId: number): BridgeSession {
    if (!bridgeSessions.has(chatId)) bridgeSessions.set(chatId, {});
    return bridgeSessions.get(chatId)!;
  }

  bot.onText(/\/start/, async (msg) => {
    try {
      if (!isOwner(msg.chat.id)) return;
      sessions.set(msg.chat.id, {});
      bridgeSessions.set(msg.chat.id, {});
      if (botRole === "trading") {
        await bot.sendMessage(msg.chat.id,
          `📈 *HAYO Trading Bot*\n\n` +
          `بوت إشارات التداول الذكي 🤖\n\n` +
          `الأوامر المتاحة:\n` +
          `• /scan — تحليل سوق فوري\n` +
          `• /auto — إعدادات الإشارات التلقائية\n` +
          `• /signals — آخر الإشارات\n\n` +
          `اختر زوجاً للتحليل:`,
          { parse_mode: "Markdown", reply_markup: pairsKeyboard() }
        );
      } else {
        await bot.sendMessage(msg.chat.id,
          `🚀 *HAYO AI Bridge Bot*\n\n` +
          `مرحباً بك يا مالك المنصة 👑\n` +
          `تحكم بكامل منصة HAYO AI من هنا:\n\n` +
          `اختر القسم المطلوب:`,
          { parse_mode: "Markdown", reply_markup: mainMenuKeyboard() }
        );
      }
    } catch (e: any) { console.warn("[TelegramBot] /start error:", e?.message); }
  });

  bot.onText(/\/menu/, async (msg) => {
    try {
      if (!isOwner(msg.chat.id)) return;
      bridgeSessions.set(msg.chat.id, {});
      if (botRole === "trading") {
        await bot.sendMessage(msg.chat.id, "📈 *اختر زوجاً للتحليل:*", { parse_mode: "Markdown", reply_markup: pairsKeyboard() });
      } else {
        await bot.sendMessage(msg.chat.id, "🏠 *القائمة الرئيسية*\n\nاختر القسم:", { parse_mode: "Markdown", reply_markup: mainMenuKeyboard() });
      }
    } catch (e: any) { console.warn("[TelegramBot] /menu error:", e?.message); }
  });

  // ── Callback Query ─────────────────────────────────────────────
  bot.on("callback_query", async (query) => {
    // Always acknowledge first — silently ignore if expired
    try { await bot.answerCallbackQuery(query.id); } catch {}

    try {
    if (!query.message || !isOwner(query.message.chat.id)) return;

    const chatId  = query.message.chat.id;
    const msgId   = query.message.message_id;
    let data      = query.data ?? "";
    const session = getSession(chatId);
    const bridgeSession = getBridgeSession(chatId);

    // Helper to edit the current message (prevents double-message on button press)
    async function editNav(text: string, opts: Partial<TelegramBot.EditMessageTextOptions> = {}) {
      try {
        await bot.editMessageText(text, { chat_id: chatId, message_id: msgId, parse_mode: "Markdown", ...opts });
      } catch {
        await bot.sendMessage(chatId, text, { parse_mode: "Markdown", ...opts as any });
      }
    }

    // ═══ Full analysis behind a compact signal ═══════════════════
    if (data.startsWith("full:")) {
      const det = detailStore.get(data.slice(5));
      if (!det) { await bot.sendMessage(chatId, "⌛ انتهت صلاحية تفاصيل هذه الإشارة (يُحفظ آخر 40 إشارة فقط)."); return; }
      if (det.chart) await sendChartPhoto(bot, chatId, det.chart, det.caption);
      await deliverLong(bot, chatId, det.text);
      return;
    }

    // ═══ Bridge Menu Handlers ═══════════════════════════════════
    if (data === "pair_menu") {
      session.pair = undefined; session.tf = undefined;
      await sendPairsMenu(chatId, msgId);
      return;
    }

    if (data === "bridge:main") {
      bridgeSessions.set(chatId, {});
      await editNav("🏠 *القائمة الرئيسية*\n\nاختر القسم المطلوب:", { reply_markup: mainMenuKeyboard() });
      return;
    }

    // ── Chat AI ──
    if (data === "bridge:chat") {
      bridgeSession.mode = "chat"; bridgeSession.subStep = "waiting";
      await bot.sendMessage(chatId, "💬 *دردشة AI*\n\nاكتب رسالتك وسيرد عليك أقوى نموذج AI:", { parse_mode: "Markdown", reply_markup: { inline_keyboard: [[{ text: "🏠 القائمة", callback_data: "bridge:main" }]] } });
      return;
    }

    // ── Code Agent ──
    if (data === "bridge:agent") {
      bridgeSession.mode = "agent"; bridgeSession.subStep = "waiting";
      await bot.sendMessage(chatId, "🤖 *وكيل الكود*\n\nاكتب ما تريد برمجته وسينفّذ الوكيل المهمة:", { parse_mode: "Markdown", reply_markup: { inline_keyboard: [[{ text: "🏠 القائمة", callback_data: "bridge:main" }]] } });
      return;
    }

    // ── App Builder ──
    if (data === "bridge:appbuilder") {
      bridgeSession.mode = "appbuilder"; bridgeSession.subStep = "waiting";
      await bot.sendMessage(chatId,
        "📱 *منشئ التطبيقات*\n\n" +
        "اكتب وصف التطبيق المطلوب بالتفصيل.\n\n" +
        "🤖 سأبني لك APK جاهز للتحميل تلقائياً!",
        { parse_mode: "Markdown", reply_markup: { inline_keyboard: [[{ text: "🏠 القائمة", callback_data: "bridge:main" }]] } });
      return;
    }

    // ── Reverse Engineering ──
    if (data === "bridge:reverse") {
      bridgeSession.mode = "reverse"; bridgeSession.subStep = "waiting";
      await bot.sendMessage(chatId,
        "🔬 *الهندسة العكسية*\n\n" +
        "الصق الكود المراد تحليله أو اكتب وصف ما تريد فهمه.\n\n" +
        "🧠 Claude Opus + Gemini Pro سيحللانه معاً:",
        { parse_mode: "Markdown", reply_markup: { inline_keyboard: [[{ text: "🏠 القائمة", callback_data: "bridge:main" }]] } });
      return;
    }

    // ── Office Suite ──
    if (data === "bridge:office") {
      bridgeSession.mode = "office"; bridgeSession.subStep = "choose";
      await editNav("📄 *الأعمال المكتبية*\n\nاختر نوع الملف:", {
        reply_markup: { inline_keyboard: [
          [{ text: "📊 عرض تقديمي", callback_data: "office:pptx" }, { text: "📝 تقرير Word", callback_data: "office:word" }],
          [{ text: "🏠 القائمة", callback_data: "bridge:main" }],
        ]},
      });
      return;
    }
    if (data === "office:pptx") {
      bridgeSession.subStep = "pptx";
      await bot.sendMessage(chatId, "📊 اكتب موضوع العرض التقديمي:", { parse_mode: "Markdown", reply_markup: { inline_keyboard: [[{ text: "🏠 القائمة", callback_data: "bridge:main" }]] } });
      return;
    }
    if (data === "office:word") {
      bridgeSession.subStep = "word";
      await bot.sendMessage(chatId, "📝 اكتب موضوع التقرير:", { parse_mode: "Markdown", reply_markup: { inline_keyboard: [[{ text: "🏠 القائمة", callback_data: "bridge:main" }]] } });
      return;
    }

    // ── Studies ──
    if (data === "bridge:studies") {
      bridgeSession.mode = "studies"; bridgeSession.subStep = "choose";
      await editNav("📊 *دراسات واستشارات*\n\nاختر التصنيف:", {
        reply_markup: { inline_keyboard: [
          [{ text: "🏗️ هندسة", callback_data: "study:engineering" }, { text: "💰 تجارة", callback_data: "study:commerce" }],
          [{ text: "📊 جدوى", callback_data: "study:investment" }, { text: "🏥 طب", callback_data: "study:medical" }],
          [{ text: "💻 تقنية", callback_data: "study:tech" }, { text: "🌾 زراعة", callback_data: "study:agriculture" }],
          [{ text: "🔬 عام", callback_data: "study:general" }],
          [{ text: "🏠 القائمة", callback_data: "bridge:main" }],
        ]},
      });
      return;
    }
    if (data.startsWith("study:")) {
      bridgeSession.subStep = "study_input";
      bridgeSession.data = { category: data.split(":")[1] };
      await bot.sendMessage(chatId, "✍️ اكتب وصف مشروعك بالتفصيل:", { parse_mode: "Markdown", reply_markup: { inline_keyboard: [[{ text: "🏠 القائمة", callback_data: "bridge:main" }]] } });
      return;
    }

    // ── Prompt Factory ──
    if (data === "bridge:prompt") {
      bridgeSession.mode = "prompt"; bridgeSession.subStep = "waiting";
      await bot.sendMessage(chatId, "🪄 *مصنع البرومبت*\n\nاكتب فكرتك وسأحولها لبرومبت احترافي:", { parse_mode: "Markdown", reply_markup: { inline_keyboard: [[{ text: "🏠 القائمة", callback_data: "bridge:main" }]] } });
      return;
    }

    // ── Mind Map ──
    if (data === "bridge:mindmap") {
      bridgeSession.mode = "mindmap"; bridgeSession.subStep = "waiting";
      await bot.sendMessage(chatId, "🗺️ *خرائط ذهنية*\n\nاكتب الموضوع أو المفهوم لإنشاء خريطة ذهنية منظمة:", { parse_mode: "Markdown", reply_markup: { inline_keyboard: [[{ text: "🏠 القائمة", callback_data: "bridge:main" }]] } });
      return;
    }

    // ── OSINT ──
    if (data === "bridge:osint") {
      bridgeSession.mode = "osint"; bridgeSession.subStep = "waiting";
      await bot.sendMessage(chatId, "🔍 *OSINT — استخبارات المصادر المفتوحة*\n\nاكتب اسم شخص، شركة، نطاق، أو أي هدف للبحث والتحليل:", { parse_mode: "Markdown", reply_markup: { inline_keyboard: [[{ text: "🏠 القائمة", callback_data: "bridge:main" }]] } });
      return;
    }

    // ── Image Generation ──
    if (data === "bridge:image") {
      bridgeSession.mode = "image"; bridgeSession.subStep = "waiting";
      await bot.sendMessage(chatId, "🎨 *توليد صور AI*\n\nاكتب وصف الصورة المطلوبة:", { parse_mode: "Markdown", reply_markup: { inline_keyboard: [[{ text: "🏠 القائمة", callback_data: "bridge:main" }]] } });
      return;
    }

    // ── EA Factory ──
    if (data === "bridge:ea") {
      bridgeSession.mode = "ea"; bridgeSession.subStep = "choose";
      await editNav("⚙️ *EA Factory — مصنع الخبراء*\n\nاختر نوع الاستراتيجية:", {
        reply_markup: { inline_keyboard: [
          [{ text: "📈 تقاطع المتوسطات (MA Crossover)", callback_data: "ea:ma_cross" }],
          [{ text: "📊 RSI العكسي (Reversal)", callback_data: "ea:rsi_reversal" }],
          [{ text: "💥 اختراق النطاق (Breakout)", callback_data: "ea:breakout" }],
          [{ text: "🎯 بولنجر باند (Bollinger)", callback_data: "ea:bollinger" }],
          [{ text: "✍️ استراتيجية مخصصة", callback_data: "ea:custom" }],
          [{ text: "🏠 القائمة", callback_data: "bridge:main" }],
        ]},
      });
      return;
    }
    if (data.startsWith("ea:") && ["ea:ma_cross","ea:rsi_reversal","ea:breakout","ea:bollinger","ea:custom"].includes(data)) {
      const eaNames: Record<string,string> = { ma_cross:"تقاطع المتوسطات", rsi_reversal:"RSI العكسي", breakout:"اختراق النطاق", bollinger:"بولنجر باند", custom:"مخصصة" };
      bridgeSession.data = { eaType: data.split(":")[1] };
      bridgeSession.subStep = "ea_params";
      await bot.sendMessage(chatId,
        `⚙️ *EA — ${eaNames[data.split(":")[1]]}*\n\n` +
        `صِف معاملات الاستراتيجية:\n` +
        `• الزوج والإطار الزمني\n• معاملات الإدخال (فترات، عتبات)\n• وقف الخسارة وهدف الربح\n\n` +
        `مثال: _EURUSD، H1، MA20 و MA50، SL=20 نقطة، TP=40 نقطة_`,
        { parse_mode: "Markdown", reply_markup: { inline_keyboard: [[{ text: "🏠 القائمة", callback_data: "bridge:main" }]] } }
      );
      return;
    }

    // ── Executive Agent (Maintenance++) ──
    if (data === "bridge:executive") {
      bridgeSession.mode = "executive";
      await editNav("🚀 *المنفّذ التنفيذي الذكي*\n\nنظام صيانة وإصلاح ذاتي متكامل.\nاختر العملية:", {
        reply_markup: { inline_keyboard: [
          [{ text: "🔍 فحص شامل + تقرير", callback_data: "maint:scan" }],
          [{ text: "🟢 حالة النظام", callback_data: "maint:health" }],
          [{ text: "🧠 تشخيص AI ذكي", callback_data: "maint:diagnose" }],
          [{ text: "🚀 تنفيذ ذكي شامل (Auto-Fix)", callback_data: "exec:auto" }],
          [{ text: "🔧 إصلاح صفحة بعينها", callback_data: "exec:fix_page" }],
          [{ text: "🏠 القائمة", callback_data: "bridge:main" }],
        ]},
      });
      return;
    }
    if (data === "exec:auto") {
      await bot.sendMessage(chatId, "🚀 *تشغيل المنفّذ التنفيذي الشامل...*\n\n📊 المراحل:\n1️⃣ فحص سريع للمشروع\n2️⃣ تشخيص AI للأخطاء\n3️⃣ توليد وتطبيق الإصلاحات\n\n⏳ هذا قد يستغرق 1-2 دقيقة...", { parse_mode: "Markdown" });
      (async () => {
        try {
          const { autoExecute } = await import("../hayo/services/maintenance.js");
          const result = await autoExecute(process.cwd());
          let reply = `🚀 *نتائج المنفّذ التنفيذي:*\n\n`;
          reply += `📊 درجة الفحص: *${result.scan?.score || "N/A"}/100*\n`;
          if (result.diagnosis?.report) {
            reply += `\n🧠 *التشخيص:*\n${result.diagnosis.report.substring(0, 800)}\n`;
          }
          if (result.fixes && result.fixes.length > 0) {
            reply += `\n🔧 *تم تطبيق ${result.fixes.length} إصلاح:*\n`;
            result.fixes.slice(0, 5).forEach((f: any) => {
              reply += `\n✅ ${f.file || f.description?.substring(0, 60)}`;
            });
          } else {
            reply += `\n✅ لا إصلاحات ضرورية — المشروع سليم`;
          }
          await safeSend(chatId, reply.substring(0, 4000), { reply_markup: { inline_keyboard: [[{ text: "🔄 إعادة التنفيذ", callback_data: "exec:auto" }, { text: "🏠 القائمة", callback_data: "bridge:main" }]] } });
        } catch (e: any) {
          await bot.sendMessage(chatId, `❌ خطأ في التنفيذ الذكي: ${e.message?.substring(0, 300)}`);
        }
      })();
      return;
    }
    if (data === "exec:fix_page") {
      bridgeSession.mode = "executive"; bridgeSession.subStep = "exec_input";
      await bot.sendMessage(chatId, "🔧 *إصلاح موجّه*\n\nاكتب وصف المشكلة أو اسم الصفحة/الملف المراد إصلاحه:\n\nمثال: _صفحة TradingAnalysis لا تعمل_ أو _خطأ في providers.ts_", { parse_mode: "Markdown", reply_markup: { inline_keyboard: [[{ text: "🏠 القائمة", callback_data: "bridge:main" }]] } });
      return;
    }

    // ── Maintenance (legacy) ──
    if (data === "bridge:maintenance") {
      bridgeSession.mode = "maintenance";
      await editNav("🔧 *صيانة النظام*\n\nاختر العملية:", {
        reply_markup: { inline_keyboard: [
          [{ text: "🟢 حالة النظام", callback_data: "maint:health" }, { text: "🔍 فحص سريع", callback_data: "maint:scan" }],
          [{ text: "🧠 تشخيص AI", callback_data: "maint:diagnose" }],
          [{ text: "🚀 تنفيذ ذكي شامل", callback_data: "exec:auto" }],
          [{ text: "🏠 القائمة", callback_data: "bridge:main" }],
        ]},
      });
      return;
    }
    if (data === "maint:health") {
      await bot.sendMessage(chatId, "⏳ جاري فحص حالة النظام...");
      try {
        const { systemHealthCheck } = await import("../hayo/services/security.js");
        const health = await systemHealthCheck();
        const checks = Object.entries(health.checks).map(([k, v]: [string, any]) => `${v.ok ? "✅" : "❌"} ${k}: ${v.latency || v.error || "OK"}`).join("\n");
        await bot.sendMessage(chatId, `🏥 *حالة النظام: ${health.status}*\n\n${checks}`, { parse_mode: "Markdown" });
      } catch (e: any) { await bot.sendMessage(chatId, `❌ خطأ: ${e.message}`); }
      return;
    }
    if (data === "maint:scan") {
      await bot.sendMessage(chatId, "⏳ جاري الفحص السريع...");
      try {
        const { quickScan } = await import("../hayo/services/maintenance.js");
        const result = quickScan(process.cwd());
        const errors = result.diagnostics.filter(d => d.status === "error").length;
        const warnings = result.diagnostics.filter(d => d.status === "warning").length;
        await bot.sendMessage(chatId, `🔍 *نتيجة الفحص: ${result.score}/100*\n\n📁 ${result.scannedFiles} ملف | ${result.scannedLines} سطر\n❌ ${errors} أخطاء | ⚠️ ${warnings} تحذيرات`, { parse_mode: "Markdown" });
      } catch (e: any) { await bot.sendMessage(chatId, `❌ خطأ: ${e.message}`); }
      return;
    }
    if (data === "maint:diagnose") {
      bridgeSession.mode = "maintenance"; bridgeSession.subStep = "diagnose_input";
      await bot.sendMessage(chatId, "🧠 اكتب وصف المشكلة أو الصفحة المراد فحصها:");
      return;
    }

    // ── Pair selected ─────────────────────────────────────────
    if (data.startsWith("pair:")) {
      session.pair = data.split(":")[1];
      session.tf   = undefined;
      await sendTfMenu(chatId, msgId);
      return;
    }

    // ── Timeframe selected ────────────────────────────────────
    if (data.startsWith("tf:")) {
      session.tf = data.split(":")[1];
      if (!session.pair) { await sendPairsMenu(chatId, msgId); return; }
      await sendAnalysisMenu(chatId, msgId);
      return;
    }

    // ── Back navigation ───────────────────────────────────────
    if (data === "back:pairs") {
      session.pair = undefined;
      session.tf   = undefined;
      await sendPairsMenu(chatId, msgId);
      return;
    }
    if (data === "back:timeframes") {
      session.tf = undefined;
      if (!session.pair) { await sendPairsMenu(chatId, msgId); return; }
      await sendTfMenu(chatId, msgId);
      return;
    }

    // ── Auto-signals menu ─────────────────────────────────────
    if (data === "auto:menu") {
      await sendAutoMenu(chatId, msgId);
      return;
    }

    // ── Auto-signals settings ─────────────────────────────────
    if (data === "auto:noop") return;

    if (data === "auto:toggle") {
      autoConfig.enabled = !autoConfig.enabled;
      restartAutoScanner(bot, ownerChatId, lastSignalTimeLocal);
      await sendAutoMenu(chatId, msgId);
      return;
    }

    if (data.startsWith("auto:cons:")) {
      autoConfig.minConsensus = parseInt(data.split(":")[2]);
      await sendAutoMenu(chatId, msgId);
      return;
    }

    if (data.startsWith("auto:aiconf:")) {
      autoConfig.minAIConfidence = parseInt(data.split(":")[2]);
      await sendAutoMenu(chatId, msgId);
      return;
    }

    if (data.startsWith("auto:pair:")) {
      const p = data.split(":")[2];
      if (p === "ALL") {
        const allKeys = Object.keys(PAIRS);
        autoConfig.pairs = autoConfig.pairs.length === allKeys.length ? [] : [...allKeys];
      } else if (autoConfig.pairs.includes(p)) {
        autoConfig.pairs = autoConfig.pairs.filter(x=>x!==p);
      } else {
        autoConfig.pairs.push(p);
      }
      await sendAutoMenu(chatId, msgId);
      return;
    }

    if (data === "auto:mode:forex" || data === "auto:mode:binary") {
      autoConfig.binary = data === "auto:mode:binary";
      await sendAutoMenu(chatId, msgId);
      return;
    }
    if (data.startsWith("auto:exp:")) {
      const n = parseInt(data.split(":")[2]);
      if ([0, 3, 5, 7, 10].includes(n)) autoConfig.binaryExpiry = n;
      await sendAutoMenu(chatId, msgId);
      return;
    }

    if (data === "auto:ai:on" || data === "auto:ai:off") {
      autoConfig.useAI = data === "auto:ai:on";
      await sendAutoMenu(chatId, msgId);
      return;
    }

    if (data === "auto:now") {
      if (!autoConfig.pairs.length || !autoConfig.timeframes.length) {
        await bot.sendMessage(chatId, "⚠️ اختر زوجاً واحداً وإطاراً واحداً على الأقل.", { reply_markup: { inline_keyboard: [[{ text: "⚙️ الإعدادات", callback_data: "auto:menu" }]] } });
        return;
      }
      const n = autoConfig.pairs.length * autoConfig.timeframes.length;
      await bot.editMessageText(
        `📡 <b>جاري الفحص...</b>\n${autoConfig.pairs.length} زوج × ${autoConfig.timeframes.length} إطار = ${n} فحص (${autoConfig.useAI ? "مع AI" : "بدون AI"})\n<i>ستصلك الإشارات القوية فور ظهورها، ثم ملخص الفحص.</i>`,
        { chat_id: chatId, message_id: msgId, parse_mode: "HTML" });
      const sum = await runAutoScan(bot, ownerChatId, lastSignalTimeLocal, true);
      const head = sum.busy ? "⏳ فحص آخر قيد التشغيل — حاول بعد قليل." : `✅ <b>اكتمل الفحص</b>: ${sum.checked} فحص — ${sum.sent} إشارة أُرسلت`;
      await deliverLong(bot, chatId, [head, "", ...sum.lines.slice(0, 120)].join("\n"), { replyMarkup: { inline_keyboard: [[{ text: "⚙️ الإعدادات", callback_data: "auto:menu" }, { text: "🏠 القائمة", callback_data: "back:pairs" }]] } });
      return;
    }

    if (data.startsWith("auto:tf:")) {
      const t = data.split(":")[2];
      if (t === "ALL") {
        const all = Object.keys(TIMEFRAMES);
        autoConfig.timeframes = autoConfig.timeframes.length === all.length ? [] : [...all];
      } else if (autoConfig.timeframes.includes(t)) {
        autoConfig.timeframes = autoConfig.timeframes.filter(x=>x!==t);
      } else {
        autoConfig.timeframes.push(t);
      }
      await sendAutoMenu(chatId, msgId);
      return;
    }

    if (data.startsWith("auto:interval:")) {
      autoConfig.intervalMinutes = parseInt(data.split(":")[2]);
      if (autoConfig.enabled) restartAutoScanner(bot, ownerChatId, lastSignalTimeLocal);
      await sendAutoMenu(chatId, msgId);
      return;
    }

    // ── Convergence (التطابق) ────────────────────────────────
    if (data.startsWith("conv:pair:")) {
      const k = data.split(":")[2];
      const all = Object.keys(PAIRS);
      let next = [...convergenceConfig.pairs];
      if (k === "ALL") next = next.length === all.length ? [] : [...all];
      else if (next.includes(k)) next = next.filter(x => x !== k);
      else if (PAIRS[k]) next.push(k);
      setConvergenceConfig({ pairs: next });
      // re-open the menu with the updated ticks
      data = "conv:menu";
    }

    if (data === "conv:menu") {
      const c = convergenceConfig;
      const text = [
        `🎯 <b>نظام التطابق</b>`,
        ``,
        `الحالة: ${c.enabled ? "✅ <b>مفعّل</b>" : "❌ <b>معطّل</b>"}`,
        `الفحص: كل <code>${c.intervalMinutes}</code> دقائق`,
        `النوع: ${c.useAI ? "🤖 <b>مع AI</b> (القرار = الأكثر توافقاً بين النماذج)" : "⚡ <b>بدون AI</b> (قرار فني)"}`,
        `الأزواج: <code>${c.pairs.length === Object.keys(PAIRS).length ? `جميع الأزواج — SCAN (${c.pairs.length})` : c.pairs.map(x => PAIRS[x]?.label || x).join(", ") || "لا يوجد"}</code>`,
        `الفريمات: <code>${CONVERGENCE_PRESETS[c.preset].label}</code>`,
        ``,
        `<i>عند تطابق الاتجاه في الفريمات الثلاثة + موافقة القرار النهائي تصل إشارة تلقائية.</i>`,
      ].join("\n");

      const kb: TelegramBot.InlineKeyboardMarkup = {
        inline_keyboard: [
          [{ text: c.enabled ? "🔴 إيقاف التطابق التلقائي" : "🟢 تفعيل التطابق التلقائي", callback_data: "conv:toggle" }],
          [{ text: "▶️ فحص فوري الآن", callback_data: "conv:now" }],
          [{ text: "━━ نوع التحليل ━━", callback_data: "conv:noop" }],
          [
            { text: `${c.useAI ? "✅ " : ""}🤖 مع AI`, callback_data: "conv:ai:on" },
            { text: `${!c.useAI ? "✅ " : ""}⚡ بدون AI (فني)`, callback_data: "conv:ai:off" },
          ],
          [{ text: `━━ الأزواج (${c.pairs.length}/${Object.keys(PAIRS).length}) ━━`, callback_data: "conv:noop" }],
          [{ text: `${c.pairs.length === Object.keys(PAIRS).length ? "✅ " : ""}جميع الأزواج (SCAN)`, callback_data: "conv:pair:ALL" }],
          ...chunk(Object.keys(PAIRS).map(k => ({ text: `${c.pairs.includes(k) ? "✅ " : ""}${PAIRS[k].label}`, callback_data: `conv:pair:${k}` })), 3),
          [{ text: "━━ فترة الفحص ━━", callback_data: "conv:noop" }],
          [
            { text: `${c.intervalMinutes===1?"✅ ":""}1د`, callback_data: "conv:int:1" },
            { text: `${c.intervalMinutes===2?"✅ ":""}2د`, callback_data: "conv:int:2" },
            { text: `${c.intervalMinutes===3?"✅ ":""}3د`, callback_data: "conv:int:3" },
            { text: `${c.intervalMinutes===5?"✅ ":""}5د`, callback_data: "conv:int:5" },
          ],
          [
            { text: `${c.intervalMinutes===7?"✅ ":""}7د`, callback_data: "conv:int:7" },
            { text: `${c.intervalMinutes===10?"✅ ":""}10د`, callback_data: "conv:int:10" },
            { text: `${c.intervalMinutes===15?"✅ ":""}15د`, callback_data: "conv:int:15" },
          ],
          [{ text: "━━ الفريمات المتطابقة ━━", callback_data: "conv:noop" }],
          ...(Object.keys(CONVERGENCE_PRESETS) as ConvergencePreset[]).map(k => [
            { text: `${c.preset === k ? "✅ " : ""}${CONVERGENCE_PRESETS[k].label}`, callback_data: `conv:preset:${k}` },
          ]),
          [{ text: "◀️ رجوع", callback_data: "back:pairs" }],
        ],
      };

      if (msgId) {
        await bot.editMessageText(text, { chat_id: chatId, message_id: msgId, parse_mode: "HTML", reply_markup: kb });
      } else {
        await bot.sendMessage(chatId, text, { parse_mode: "HTML", reply_markup: kb });
      }
      return;
    }

    if (data === "conv:noop" || data === "noop") return;

    if (data === "conv:toggle") {
      convergenceConfig.enabled = !convergenceConfig.enabled;
      persistConvergenceConfig();
      restartConvergenceScanner(bot, ownerChatId);
      await bot.editMessageText(
        `🎯 التطابق: ${convergenceConfig.enabled ? "✅ <b>مفعّل</b> — يتم فحص جميع الأزواج كل ${convergenceConfig.intervalMinutes} دقائق" : "❌ <b>معطّل</b>"}`,
        { chat_id: chatId, message_id: msgId, parse_mode: "HTML", reply_markup: { inline_keyboard: [[{ text: "◀️ إعدادات التطابق", callback_data: "conv:menu" }, { text: "🏠 القائمة", callback_data: "back:pairs" }]] } }
      );
      return;
    }

    if (data === "conv:ai:on" || data === "conv:ai:off") {
      setConvergenceConfig({ useAI: data === "conv:ai:on" });
      await bot.editMessageText(`✅ نوع التحليل في التطابق: <b>${convergenceConfig.useAI ? "مع AI" : "بدون AI (فني)"}</b>`,
        { chat_id: chatId, message_id: msgId, parse_mode: "HTML", reply_markup: { inline_keyboard: [[{ text: "◀️ إعدادات التطابق", callback_data: "conv:menu" }]] } });
      return;
    }

    if (data.startsWith("conv:preset:")) {
      const k = data.split(":")[2] as ConvergencePreset;
      if (CONVERGENCE_PRESETS[k]) setConvergenceConfig({ preset: k });
      await bot.editMessageText(`✅ فريمات التطابق: <b>${CONVERGENCE_PRESETS[convergenceConfig.preset].label}</b>`,
        { chat_id: chatId, message_id: msgId, parse_mode: "HTML", reply_markup: { inline_keyboard: [[{ text: "◀️ إعدادات التطابق", callback_data: "conv:menu" }]] } });
      return;
    }

    if (data.startsWith("conv:int:")) {
      convergenceConfig.intervalMinutes = parseInt(data.split(":")[2]);
      persistConvergenceConfig();
      if (convergenceConfig.enabled) restartConvergenceScanner(bot, ownerChatId);
      await bot.editMessageText(
        `🎯 فترة الفحص: <code>${convergenceConfig.intervalMinutes}</code> دقائق`,
        { chat_id: chatId, message_id: msgId, parse_mode: "HTML", reply_markup: { inline_keyboard: [[{ text: "◀️ إعدادات التطابق", callback_data: "conv:menu" }]] } }
      );
      return;
    }

    if (data === "conv:now") {
      const c = convergenceConfig;
      if (!c.pairs.length) {
        await bot.sendMessage(chatId, "⚠️ اختر زوجاً واحداً على الأقل في إعدادات التطابق.", { reply_markup: { inline_keyboard: [[{ text: "◀️ إعدادات التطابق", callback_data: "conv:menu" }]] } });
        return;
      }
      const estMin = Math.max(1, Math.round(c.pairs.length * 3 * 3.5 / 60));
      await bot.editMessageText(
        `🎯 <b>جاري فحص التطابق...</b>\n${c.pairs.length} زوج × ${CONVERGENCE_PRESETS[c.preset].label} (${c.useAI ? "مع AI" : "بدون AI"})\n⏱ المدة التقريبية: ~${estMin} دقيقة\n<i>تصلك إشارة لكل تطابق فور حدوثه، ثم ملخص الفحص.</i>`,
        { chat_id: chatId, message_id: msgId, parse_mode: "HTML" }
      );
      const sum = await runConvergenceScan(bot, ownerChatId, true);
      const head = sum.busy ? "⏳ فحص تطابق آخر قيد التشغيل — حاول بعد قليل." : `✅ <b>اكتمل فحص التطابق</b>: ${sum.checked} زوج — ${sum.sent} إشارة أُرسلت`;
      await deliverLong(bot, chatId, [head, "", ...sum.lines].join("\n"), {
        replyMarkup: { inline_keyboard: [[{ text: "◀️ إعدادات التطابق", callback_data: "conv:menu" }, { text: "🏠 القائمة", callback_data: "back:pairs" }]] },
      });
      return;
    }

    // ── Analyze ───────────────────────────────────────────────
    if (data.startsWith("analyze:")) {
      const type = data.split(":")[1];
      const { pair, tf } = session;
      if (!pair || !tf) { await sendPairsMenu(chatId, msgId); return; }

      const p = PAIRS[pair];
      const loadingMsg = await bot.sendMessage(chatId,
        type === "quick"
          ? `${p.flag} <b>${p.label}</b> | <code>${tf}</code>\n\n⏳ جاري الحساب...`
          : `${p.flag} <b>${p.label}</b> | <code>${tf}</code>\n\n⏳ جاري جلب البيانات...\n🔄 15 استراتيجية + 4 فلاتر\n📸 التقاط الشارت الحي\n🤖 5 نماذج AI تقرأ الشارت وتحلل...\n<i>لحظات (30-90 ثانية)</i>`,
        { parse_mode:"HTML" }
      );
      const loadMsgId = loadingMsg.message_id;

      try {
        const marketData = await fetchMarket(pair, TIMEFRAMES[tf], { useTwelveData: true });
        if (type === "quick") {
          const [news, htfBias] = await Promise.all([fetchEconomicNews(pair), computeHtfBias(pair, tf)]);
          (marketData as any).htfBias = htfBias;
          await journalRecommendation(pair, TIMEFRAMES[tf].interval, computeRecommendation(pair, marketData, [], news), "tg-manual-tech");
          await deliverLong(bot, chatId, buildQuickMsg(pair, tf, marketData, news, await journalStatsLine()), {
            editMessageId: loadMsgId, replyMarkup: afterResultKeyboard(),
          });
        } else {
          await bot.editMessageText(
            `${p.flag} <b>${p.label}</b> | <code>${tf}</code>\n\n✅ تم جلب البيانات\n📰 جلب الأخبار + 📸 التقاط الشارت...\n🤖 5 نماذج AI تقرأ الشارت وتحلل الآن...\n<i>لحظات (30-90 ثانية)</i>`,
            { chat_id:chatId, message_id:loadMsgId, parse_mode:"HTML" }
          );
          const [news, chart, htfBias] = await Promise.all([fetchEconomicNews(pair), renderPairChart(pair, tf, marketData), computeHtfBias(pair, tf)]);
          (marketData as any).htfBias = htfBias;
          const aiResults = await runAI(pair, tf, marketData, news, chart, htfBias);
          await journalRecommendation(pair, TIMEFRAMES[tf].interval, computeRecommendation(pair, marketData, aiResults, news), "tg-manual");
          await deliverLong(bot, chatId, buildAIMsg(pair, tf, marketData, aiResults, false, news, htfBias, await journalStatsLine()), {
            editMessageId: loadMsgId, replyMarkup: afterResultKeyboard(),
          });
          await sendChartPhoto(bot, chatId, chart, `📸 ${p.label} | ${tf} — الشارت الحي الذي قرأته نماذج AI`);
        }
      } catch (err: any) {
        try {
          await bot.editMessageText(`❌ خطأ: ${err.message}\n\nاضغط /menu للمحاولة مجدداً`,
            { chat_id:chatId, message_id:loadMsgId, parse_mode:"HTML" });
        } catch {}
      }
      return;
    }

    } catch (outerErr: any) {
      console.error("[TelegramBot] Callback handler error:", outerErr?.message || outerErr);
    }
  });

  // ── Unknown text ───────────────────────────────────────────────
  bot.on("message", async (msg) => {
    try {
      if (!isOwner(msg.chat.id)) return;
      if (!msg.text || msg.text.startsWith("/")) return;

      const chatId = msg.chat.id;
      const text = msg.text.trim();
      const bs = getBridgeSession(chatId);

      // ═══ Bridge Mode Processing ═══
      if (bs.mode) {
        const APP_URL = process.env.APP_URL || "http://localhost:5000";

        // ── Chat AI ──
        if (bs.mode === "chat") {
          await bot.sendMessage(chatId, "⏳ AI يفكر...");
          try {
            const { callPowerAI } = await import("../hayo/providers.js");
            const result = await callPowerAI("أنت مساعد ذكي شامل. أجب بدقة وإيجاز.", text, 4000);
            await safeSend(chatId, `🤖 *${result.modelUsed}:*\n\n${result.content}`, { reply_markup: { inline_keyboard: [[{ text: "🏠 القائمة", callback_data: "bridge:main" }]] } });
          } catch (e: any) { await bot.sendMessage(chatId, `❌ ${e.message}`); }
          return;
        }

        // ── Code Agent ──
        if (bs.mode === "agent") {
          await bot.sendMessage(chatId, "⏳ وكيل الكود يعمل...");
          try {
            const { callPowerAI } = await import("../hayo/providers.js");
            const result = await callPowerAI("أنت مبرمج خبير. اكتب كود نظيف وقابل للتشغيل مع شرح.", text, 8000);
            await safeSend(chatId, `💻 *الكود:*\n\n${result.content}`, { reply_markup: { inline_keyboard: [[{ text: "🏠 القائمة", callback_data: "bridge:main" }]] } });
          } catch (e: any) { await bot.sendMessage(chatId, `❌ ${e.message}`); }
          return;
        }

        // ── App Builder ──
        if (bs.mode === "appbuilder") {
          bs.mode = undefined;
          const appDesc = text;
          const appName = text.substring(0, 28).trim() || "HayoApp";

          await bot.sendMessage(chatId,
            `📱 *بدء بناء التطبيق*\n\n` +
            `📝 الوصف: ${appDesc.substring(0, 120)}\n\n` +
            `⏳ الخطوات:\n1️⃣ توليد الكود بالذكاء الاصطناعي\n2️⃣ مراجعة وإصلاح الكود\n3️⃣ إرسال للبناء على Expo EAS\n4️⃣ إشعارك عند الانتهاء\n\n` +
            `⏱️ المدة المتوقعة: 10-20 دقيقة`,
            { parse_mode: "Markdown" }
          );

          // Run build pipeline in background — don't await
          (async () => {
            try {
              const { callPowerAI } = await import("../hayo/providers.js");
              const { createExpoProject, submitEASBuild, aiReviewAndFix, checkEASBuildStatus, cleanupProjectDir } = await import("../hayo/services/eas-builder.js");

              // ── Step 1: Generate code ──
              await bot.sendMessage(chatId, "1️⃣ 🤖 جاري توليد كود التطبيق...");
              const codeResult = await callPowerAI(
                `أنت مطور React Native/Expo محترف. أنشئ كود App.tsx كامل وجاهز للبناء.
القواعد الصارمة:
- ملف واحد فقط (App.tsx) يبدأ بـ import React ويحتوي export default
- الحزم المسموح بها فقط: react-native, expo-status-bar, @expo/vector-icons, expo-linear-gradient, expo-haptics, expo-blur, @react-native-async-storage/async-storage, expo-clipboard
- ممنوع: react-navigation, expo-router, expo-camera, expo-av, expo-font, useFonts
- ممنوع: registerRootComponent في App.tsx (يكون في index.js منفصل)
- ممنوع: StatusBar من react-native — استخدم expo-status-bar
- استخدم فقط: fontFamily: "sans-serif" أو "monospace"
- أعد الكود فقط بدون أي شرح`,
                `أنشئ تطبيق موبايل: ${appDesc}`, 10000
              );

              let rawCode = codeResult.content.replace(/^```(?:tsx?|javascript|jsx|js)?\n?/im, "").replace(/\n?```\s*$/im, "").trim();

              // ── Step 2: AI Review & Fix ──
              await bot.sendMessage(chatId, "2️⃣ 🔍 مراجعة الكود وإصلاح المشاكل...");
              const reviewed = await aiReviewAndFix(rawCode);
              const finalCode = reviewed.fixedCode;

              if (reviewed.issues.length > 0) {
                await bot.sendMessage(chatId, `🔧 تم إصلاح ${reviewed.issues.length} مشكلة:\n• ${reviewed.issues.slice(0, 3).join("\n• ")}`);
              }

              // ── Step 3: Create Expo Project ──
              await bot.sendMessage(chatId, "3️⃣ 📦 إنشاء مشروع Expo وتثبيت الحزم (4-6 دقائق)...");
              const { projectDir, slug } = await createExpoProject(appName, finalCode);

              // ── Step 4: Submit to EAS ──
              await bot.sendMessage(chatId, "4️⃣ 🚀 إرسال للبناء على Expo EAS...");
              let buildResult;
              try {
                buildResult = await submitEASBuild(projectDir, slug);
              } catch (buildErr: any) {
                // If first try fails, run AI fix with the error and retry once
                await bot.sendMessage(chatId, "⚠️ فشل أولي — جاري إصلاح الكود بناءً على الخطأ...");
                const retried = await aiReviewAndFix(finalCode, buildErr.message);
                const { projectDir: pDir2, slug: slug2 } = await createExpoProject(appName + "2", retried.fixedCode);
                buildResult = await submitEASBuild(pDir2, slug2);
                cleanupProjectDir(projectDir);
              }

              await bot.sendMessage(chatId,
                `✅ *تم إرسال البناء!*\n\n` +
                `🆔 معرّف البناء: \`${buildResult.expoJobId}\`\n` +
                `📊 متابعة التقدم:\n${buildResult.buildLogsUrl}\n\n` +
                `⏱️ سيستغرق البناء 8-15 دقيقة على Expo EAS.\nسأُعلمك فور الانتهاء!`,
                { parse_mode: "Markdown", reply_markup: { inline_keyboard: [[{ text: "📊 متابعة البناء", url: buildResult.buildLogsUrl }], [{ text: "🏠 القائمة", callback_data: "bridge:main" }]] } }
              );

              // ── Step 5: Poll for completion ──
              let attempts = 0;
              const maxAttempts = 40; // 40 * 30s = 20 min
              const pollTimer = setInterval(async () => {
                attempts++;
                try {
                  const status = await checkEASBuildStatus(buildResult.expoJobId, buildResult.expoSlug);

                  if (status.status === "finished" && status.downloadUrl) {
                    clearInterval(pollTimer);
                    cleanupProjectDir(projectDir);
                    await bot.sendMessage(chatId,
                      `🎉 *اكتمل البناء!*\n\n` +
                      `📥 رابط التحميل:\n${status.downloadUrl}\n\n` +
                      `⏰ الرابط صالح لـ 30 يوماً`,
                      { parse_mode: "Markdown", reply_markup: { inline_keyboard: [[{ text: "📥 تحميل APK", url: status.downloadUrl }], [{ text: "🏠 القائمة", callback_data: "bridge:main" }]] } }
                    );
                  } else if (status.status === "errored") {
                    clearInterval(pollTimer);
                    cleanupProjectDir(projectDir);
                    await bot.sendMessage(chatId,
                      `❌ *فشل البناء*\n\n${status.errorMessage || "خطأ غير محدد"}\n\n` +
                      `🔗 السجلات الكاملة:\n${buildResult.buildLogsUrl}`,
                      { parse_mode: "Markdown", reply_markup: { inline_keyboard: [[{ text: "📋 عرض السجلات", url: buildResult.buildLogsUrl }], [{ text: "🏠 القائمة", callback_data: "bridge:main" }]] } }
                    );
                  } else if (status.status === "cancelled") {
                    clearInterval(pollTimer);
                    cleanupProjectDir(projectDir);
                    await bot.sendMessage(chatId, "🚫 تم إلغاء البناء");
                  } else if (attempts >= maxAttempts) {
                    clearInterval(pollTimer);
                    await bot.sendMessage(chatId,
                      `⏰ *انتهت مهلة المتابعة*\n\nيمكنك متابعة البناء يدوياً:\n${buildResult.buildLogsUrl}`,
                      { parse_mode: "Markdown", reply_markup: { inline_keyboard: [[{ text: "📊 متابعة البناء", url: buildResult.buildLogsUrl }]] } }
                    );
                  }
                } catch { /* polling error — ignore, try again */ }
              }, 30_000); // poll every 30 seconds

            } catch (e: any) {
              await bot.sendMessage(chatId, `❌ *خطأ في البناء*\n\n${e.message?.substring(0, 400) || "خطأ غير معروف"}`, { parse_mode: "Markdown" });
            }
          })();

          return;
        }

        // ── Office: PPTX ──
        if (bs.mode === "office" && bs.subStep === "pptx") {
          await bot.sendMessage(chatId, "⏳ 📊 جاري إنشاء العرض التقديمي...");
          try {
            const res = await fetch(`${APP_URL}/api/office/generate-pptx`, {
              method: "POST", headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ topic: text, slideCount: 10, style: "professional", language: "ar" }),
            });
            if (res.ok) {
              const buffer = await res.arrayBuffer();
              await bot.sendDocument(chatId, Buffer.from(buffer), { caption: `📊 ${text}` }, { filename: `${text.substring(0, 20)}.pptx`, contentType: "application/vnd.openxmlformats-officedocument.presentationml.presentation" });
            } else {
              await bot.sendMessage(chatId, "❌ فشل الإنشاء — جرّب من المنصة مباشرة");
            }
          } catch (e: any) { await bot.sendMessage(chatId, `❌ ${e.message}`); }
          bs.mode = undefined;
          return;
        }

        // ── Office: Word ──
        if (bs.mode === "office" && bs.subStep === "word") {
          await bot.sendMessage(chatId, "⏳ 📝 جاري إنشاء التقرير...");
          try {
            const res = await fetch(`${APP_URL}/api/office/generate-report`, {
              method: "POST", headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ topic: text, type: "business", language: "ar", pageCount: 5 }),
            });
            if (res.ok) {
              const buffer = await res.arrayBuffer();
              await bot.sendDocument(chatId, Buffer.from(buffer), { caption: `📝 ${text}` }, { filename: `تقرير-${text.substring(0, 15)}.docx`, contentType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document" });
            } else {
              await bot.sendMessage(chatId, "❌ فشل الإنشاء");
            }
          } catch (e: any) { await bot.sendMessage(chatId, `❌ ${e.message}`); }
          bs.mode = undefined;
          return;
        }

        // ── Studies ──
        if (bs.mode === "studies" && bs.subStep === "study_input") {
          const category = bs.data?.category || "general";
          await bot.sendMessage(chatId, `⏳ 📊 جاري إنشاء الدراسة (${category})... قد يستغرق دقيقتين`);
          try {
            const res = await fetch(`${APP_URL}/api/studies/generate`, {
              method: "POST", headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ category, userInput: text, detailLevel: "detailed" }),
            });
            const data = await res.json();
            if (data.study) {
              await safeSend(chatId, `📊 *الدراسة — ${category}*\n\n${data.study}\n\n🤖 نموذج: ${data.modelUsed || "AI"}`, { reply_markup: { inline_keyboard: [[{ text: "🏠 القائمة", callback_data: "bridge:main" }]] } });
            } else {
              await bot.sendMessage(chatId, `❌ ${data.error || "فشل الإنشاء"}`);
            }
          } catch (e: any) { await bot.sendMessage(chatId, `❌ ${e.message}`); }
          bs.mode = undefined;
          return;
        }

        // ── EA Factory ──
        if (bs.mode === "ea" && (bs.subStep === "ea_params" || bs.subStep === "waiting")) {
          await bot.sendMessage(chatId, "⏳ ⚙️ جاري توليد كود EA بـ MQL5...");
          try {
            const { callPowerAI } = await import("../hayo/providers.js");
            const eaType = bs.data?.eaType || "custom";
            const eaSystemPrompts: Record<string, string> = {
              ma_cross:     "أنت خبير في برمجة MQL5. اكتب Expert Advisor كامل لاستراتيجية تقاطع المتوسطات المتحركة. اشمل: إدارة المخاطر، وقف الخسارة، هدف الربح، TrailingStop اختياري. أعد الكود فقط مع تعليقات عربية.",
              rsi_reversal: "أنت خبير في برمجة MQL5. اكتب Expert Advisor كامل لاستراتيجية RSI العكسية (ذروة شراء/بيع). اشمل: إدارة المخاطر، وقف الخسارة، هدف الربح. أعد الكود فقط مع تعليقات عربية.",
              breakout:     "أنت خبير في برمجة MQL5. اكتب Expert Advisor كامل لاستراتيجية اختراق النطاق (High/Low Breakout). اشمل: إدارة المخاطر، وقف الخسارة، هدف الربح. أعد الكود فقط مع تعليقات عربية.",
              bollinger:    "أنت خبير في برمجة MQL5. اكتب Expert Advisor كامل لاستراتيجية بولنجر باند (Bollinger Bands). اشمل: إدارة المخاطر، وقف الخسارة، هدف الربح. أعد الكود فقط مع تعليقات عربية.",
              custom:       "أنت خبير في برمجة MQL5. اكتب Expert Advisor كامل للاستراتيجية الموصوفة. اشمل: إدارة المخاطر، وقف الخسارة، هدف الربح. أعد الكود فقط مع تعليقات عربية.",
            };
            const result = await callPowerAI(eaSystemPrompts[eaType] || eaSystemPrompts.custom, `المعاملات: ${text}`, 8000);
            // Send as file if code is long, otherwise as message
            const code = result.content;
            if (code.length > 2000) {
              const buf = Buffer.from(code, "utf-8");
              await bot.sendDocument(chatId, buf,
                { caption: `⚙️ EA جاهز (${eaType}) — ${text.substring(0, 40)}` },
                { filename: `EA_${eaType}_${Date.now()}.mq5`, contentType: "text/plain" }
              );
            } else {
              await safeSend(chatId, `⚙️ *كود EA جاهز:*\n\n\`\`\`mql5\n${code}\n\`\`\``, {
                reply_markup: { inline_keyboard: [[{ text: "🏠 القائمة", callback_data: "bridge:main" }]] }
              });
            }
          } catch (e: any) { await bot.sendMessage(chatId, `❌ ${e.message}`); }
          bs.mode = undefined;
          return;
        }

        // ── Prompt Factory ──
        if (bs.mode === "prompt") {
          await bot.sendMessage(chatId, "⏳ 🪄 جاري توليد البرومبت...");
          try {
            const res = await fetch(`${APP_URL}/api/prompt-factory/generate`, {
              method: "POST", headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ request: text }),
            });
            const data = await res.json();
            await safeSend(chatId, `🪄 *البرومبت الاحترافي:*\n\n${data.result || "فشل"}`, { reply_markup: { inline_keyboard: [[{ text: "🏠 القائمة", callback_data: "bridge:main" }]] } });
          } catch (e: any) { await bot.sendMessage(chatId, `❌ ${e.message}`); }
          return;
        }

        // ── Image Generation ──
        if (bs.mode === "image") {
          await bot.sendMessage(chatId, "⏳ 🎨 جاري توليد الصورة...");
          try {
            const res = await fetch(`${APP_URL}/api/chat/generate-image`, {
              method: "POST", headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ prompt: text }),
            });
            const data = await res.json();
            if (data.imageUrl) {
              if (data.imageUrl.startsWith("data:")) {
                // SVG data URL — send as document
                const svgBuffer = Buffer.from(data.imageUrl.split(",")[1], "base64");
                await bot.sendDocument(chatId, svgBuffer, { caption: `🎨 ${text}` }, { filename: "image.svg", contentType: "image/svg+xml" });
              } else {
                await bot.sendPhoto(chatId, data.imageUrl, { caption: `🎨 ${text}\n🤖 ${data.model}` });
              }
            } else {
              await bot.sendMessage(chatId, `❌ ${data.error || "فشل التوليد"}`);
            }
          } catch (e: any) { await bot.sendMessage(chatId, `❌ ${e.message}`); }
          return;
        }

        // ── Maintenance Diagnose ──
        if (bs.mode === "maintenance" && bs.subStep === "diagnose_input") {
          await bot.sendMessage(chatId, "⏳ 🧠 AI يشخّص المشكلة...");
          try {
            const { aiDiagnose, getProjectStructure } = await import("../hayo/services/maintenance.js");
            const root = process.cwd();
            const structure = getProjectStructure(root);
            const files = structure.files.slice(0, 8).map(f => f.path);
            const result = await aiDiagnose(files, root, text);
            let reply = `🧠 *تقرير التشخيص:*\n\n${result.report.substring(0, 3000)}`;
            if (result.fixes?.length > 0) {
              reply += `\n\n🔧 *${result.fixes.length} إصلاحات مقترحة:*\n`;
              result.fixes.slice(0, 5).forEach((f: any) => { reply += `\n📄 ${f.file}: ${f.description.substring(0, 100)}`; });
            }
            await safeSend(chatId, reply, { reply_markup: { inline_keyboard: [[{ text: "🏠 القائمة", callback_data: "bridge:main" }]] } });
          } catch (e: any) { await bot.sendMessage(chatId, `❌ ${e.message}`); }
          bs.mode = undefined;
          return;
        }

        // ── Executive Agent — Guided Fix ──
        if (bs.mode === "executive" && bs.subStep === "exec_input") {
          await bot.sendMessage(chatId, `⏳ 🚀 المنفّذ الذكي يعمل على: "${text.substring(0, 60)}..."\n\n📊 المراحل: فحص → تشخيص → إصلاح`);
          bs.mode = undefined; bs.subStep = undefined;
          (async () => {
            try {
              const { aiDiagnose, getProjectStructure, quickScan } = await import("../hayo/services/maintenance.js");
              const root = process.cwd();
              // Step 1: Scan
              await bot.sendMessage(chatId, "1️⃣ 🔍 جاري فحص المشروع...");
              const scan = quickScan(root);
              await bot.sendMessage(chatId, `✅ الفحص: ${scan.score}/100 | ${scan.scannedFiles} ملف | ${scan.diagnostics.filter((d: any) => d.status === "error").length} أخطاء`);
              // Step 2: Diagnose with user context
              await bot.sendMessage(chatId, "2️⃣ 🧠 AI يشخّص المشكلة المحددة...");
              const structure = getProjectStructure(root);
              const files = structure.files.slice(0, 10).map((f: any) => f.path);
              const diagnosis = await aiDiagnose(files, root, text);
              await bot.sendMessage(chatId, `✅ التشخيص جاهز — ${diagnosis.fixes?.length || 0} إصلاح مقترح`);
              // Step 3: Report
              let reply = `🚀 *نتيجة التنفيذ الذكي:*\n\n📋 *السياق:* ${text.substring(0, 100)}\n\n`;
              reply += `📊 *الفحص:* ${scan.score}/100\n`;
              reply += `\n🧠 *التشخيص:*\n${diagnosis.report.substring(0, 1500)}`;
              if (diagnosis.fixes?.length > 0) {
                reply += `\n\n🔧 *الإصلاحات المقترحة (${diagnosis.fixes.length}):*\n`;
                diagnosis.fixes.slice(0, 5).forEach((f: any) => {
                  reply += `\n📄 ${f.file || "?"}: ${(f.description || "").substring(0, 80)}`;
                });
              }
              await safeSend(chatId, reply.substring(0, 4000), {
                reply_markup: { inline_keyboard: [
                  [{ text: "🔧 إصلاح آخر", callback_data: "exec:fix_page" }, { text: "🚀 تنفيذ شامل", callback_data: "exec:auto" }],
                  [{ text: "🏠 القائمة", callback_data: "bridge:main" }],
                ]},
              });
            } catch (e: any) {
              await bot.sendMessage(chatId, `❌ خطأ: ${e.message?.substring(0, 300)}`);
            }
          })();
          return;
        }

        // ── Mind Map ──
        if (bs.mode === "mindmap") {
          await bot.sendMessage(chatId, "⏳ 🗺️ جاري إنشاء الخريطة الذهنية...");
          bs.mode = undefined;
          try {
            const { callPowerAI } = await import("../hayo/providers.js");
            const result = await callPowerAI(
              `أنت خبير في الخرائط الذهنية. أنشئ خريطة ذهنية منظمة ومفصلة بالعربية.
استخدم هذا التنسيق بالضبط:
🎯 المحور الرئيسي: [الموضوع]

📌 الفرع 1: [اسم]
  ├── نقطة فرعية
  ├── نقطة فرعية
  └── نقطة فرعية

📌 الفرع 2: [اسم]
  ├── نقطة فرعية
  └── نقطة فرعية

[كرر لـ 5-7 فروع رئيسية]

💡 الخلاصة: [ملاحظة ختامية]`,
              `أنشئ خريطة ذهنية شاملة حول: ${text}`, 3000
            );
            await safeSend(chatId, `🗺️ *خريطة ذهنية: ${text.substring(0, 40)}*\n\n${result.content}`, {
              reply_markup: { inline_keyboard: [[{ text: "🗺️ موضوع جديد", callback_data: "bridge:mindmap" }, { text: "🏠 القائمة", callback_data: "bridge:main" }]] },
            });
          } catch (e: any) { await bot.sendMessage(chatId, `❌ ${e.message}`); }
          return;
        }

        // ── OSINT ──
        if (bs.mode === "osint") {
          await bot.sendMessage(chatId, `⏳ 🔍 OSINT يحلل الهدف: "${text.substring(0, 50)}"...`);
          bs.mode = undefined;
          try {
            const { callPowerAI } = await import("../hayo/providers.js");
            const result = await callPowerAI(
              `أنت محلل OSINT (استخبارات المصادر المفتوحة) خبير. قدّم تحليلاً شاملاً لأي هدف بناءً على المعلومات العامة المتاحة.

اشمل دائماً:
🎯 **ملف الهدف**: معلومات أساسية
🔗 **الروابط الرقمية**: مواقع، شبكات اجتماعية متوقعة
📊 **التحليل**: أنماط، سلوك، معلومات مهنية
⚠️ **نقاط الاهتمام**: أي معلومات لافتة
🔒 **ملاحظة**: هذا للأغراض التعليمية والمشروعة فقط

أجب بالعربية بشكل مفصل ومنظم.`,
              `هدف OSINT للتحليل: ${text}`, 4000
            );
            await safeSend(chatId, `🔍 *تحليل OSINT: ${text.substring(0, 40)}*\n\n${result.content}`, {
              reply_markup: { inline_keyboard: [[{ text: "🔍 هدف جديد", callback_data: "bridge:osint" }, { text: "🏠 القائمة", callback_data: "bridge:main" }]] },
            });
          } catch (e: any) { await bot.sendMessage(chatId, `❌ ${e.message}`); }
          return;
        }

        // ── Reverse Engineering ──
        if (bs.mode === "reverse") {
          await bot.sendMessage(chatId, "⏳ 🔬 جاري تحليل الكود بـ Claude Opus...");
          bs.mode = undefined;
          try {
            const { callProvider } = await import("../hayo/providers.js");
            const systemPrompt = `أنت خبير هندسة عكسية وأمن معلومات. حلّل الكود أو الطلب بعمق واشمل:
🔬 **ما يفعله الكود**: شرح مبسط وتقني
🏗️ **البنية والمعمارية**: الأنماط المستخدمة
⚠️ **الثغرات والمخاطر**: أي مشاكل أمنية أو تقنية
🔧 **التحسينات المقترحة**: كيف يمكن تحسينه
💡 **الخلاصة**: النقاط الرئيسية

أجب بالعربية مع أمثلة كود إن لزم.`;
            const result = await callProvider("claude", systemPrompt, `تحليل: ${text}`, 5000);
            await safeSend(chatId, `🔬 *تحليل الهندسة العكسية:*\n\n${result.content}`, {
              reply_markup: { inline_keyboard: [[{ text: "🔬 تحليل آخر", callback_data: "bridge:reverse" }, { text: "🏠 القائمة", callback_data: "bridge:main" }]] },
            });
          } catch (e: any) { await bot.sendMessage(chatId, `❌ ${e.message}`); }
          return;
        }
      }

      // Default: show main menu
      await bot.sendMessage(chatId, "🏠 اختر قسم من القائمة:", { reply_markup: mainMenuKeyboard() });
    } catch {}
  });

  if (useWebhook && webhookUrl) {
    // Webhook mode — app.ts handles setWebhook registration externally
    console.log(`[TelegramBot] ✅ Bot started in WEBHOOK mode — owner only (ID: ${ownerChatId})`);
  } else {
    // Polling mode (development)
    bot.on("polling_error", (err) => {
      console.warn("[TelegramBot] Polling error (suppressed):", (err as any).message?.slice(0, 100));
    });
    console.log(`[TelegramBot] ✅ Bot started in POLLING mode — owner only (ID: ${ownerChatId})`);
  }

  // Host the auto-signal scanners on the trading bot; but if no trading bot is
  // configured (TELEGRAM_BOT_TOKEN unset), fall back to the bridge bot so the
  // owner's existing bot still delivers automatic signals. Without this, _botRef
  // stayed null for a bridge-only setup, so neither startup nor the web-UI toggle
  // (setConvergenceConfig) could ever start the scanner → no auto signals.
  const tradingConfigured = !!(process.env.TELEGRAM_BOT_TOKEN && process.env.TELEGRAM_BOT_TOKEN.trim());
  if (botRole === "trading" || (botRole === "bridge" && !tradingConfigured)) {
    _botRef = bot;
    _ownerRef = ownerChatId;
    // Restore the owner's saved settings first, then start the scanners with them.
    void (async () => {
      await loadPersistedBotSettings();
      if (convergenceConfig.enabled) {
        console.log(`[Convergence] Auto-starting convergence scanner on ${botRole} bot (interval: ${convergenceConfig.intervalMinutes}min)`);
        restartConvergenceScanner(bot, ownerChatId);
      }
      if (autoConfig.enabled) {
        console.log(`[AutoSignal] Auto-starting signal scanner on ${botRole} bot`);
        restartAutoScanner(bot, ownerChatId, lastSignalTimeLocal);
      }
    })();
  }

  return bot;
}

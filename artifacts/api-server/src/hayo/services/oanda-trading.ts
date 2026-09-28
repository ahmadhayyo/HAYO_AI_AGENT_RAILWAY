/**
 * OANDA Forex Trading Service
 * Real API integration with OANDA v20 REST API
 * Supports: market orders, limit orders, position management, account info
 * 
 * Docs: https://developer.oanda.com/rest-live-v20/introduction/
 */

// ─── Types ───────────────────────────────────────────────────────────
export interface OandaConfig {
  apiToken: string;
  accountId: string;
  environment: "practice" | "live";
}

export interface OandaAccountInfo {
  id: string;
  currency: string;
  balance: number;
  unrealizedPL: number;
  marginUsed: number;
  marginAvailable: number;
  openTradeCount: number;
  openPositionCount: number;
}

export interface OandaOrder {
  instrument: string;      // e.g. "EUR_USD"
  units: number;           // positive = buy, negative = sell
  type: "MARKET" | "LIMIT" | "STOP";
  price?: number;          // for LIMIT/STOP
  stopLossPrice?: number;
  takeProfitPrice?: number;
  trailingStopDistance?: number;
}

export interface OandaOrderResult {
  success: boolean;
  orderId?: string;
  tradeId?: string;
  price?: number;
  units?: number;
  error?: string;
}

export interface OandaPosition {
  instrument: string;
  long: { units: number; averagePrice: number; unrealizedPL: number };
  short: { units: number; averagePrice: number; unrealizedPL: number };
}

export interface OandaPrice {
  instrument: string;
  bid: number;
  ask: number;
  spread: number;
  time: string;
}

// ─── Base URL ────────────────────────────────────────────────────────
function getBaseUrl(env: "practice" | "live"): string {
  return env === "live"
    ? "https://api-fxtrade.oanda.com/v3"
    : "https://api-fxpractice.oanda.com/v3";
}

function getStreamUrl(env: "practice" | "live"): string {
  return env === "live"
    ? "https://stream-fxtrade.oanda.com/v3"
    : "https://stream-fxpractice.oanda.com/v3";
}

// ─── API Helper ──────────────────────────────────────────────────────
async function oandaFetch(
  config: OandaConfig,
  path: string,
  method: "GET" | "POST" | "PUT" | "DELETE" = "GET",
  body?: any
): Promise<any> {
  const url = `${getBaseUrl(config.environment)}${path}`;
  const headers: Record<string, string> = {
    "Authorization": `Bearer ${config.apiToken}`,
    "Content-Type": "application/json",
    "Accept-Datetime-Format": "UNIX",
  };

  const res = await fetch(url, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(15_000),
  });

  if (!res.ok) {
    const errBody = await res.json().catch(() => ({}));
    const errMsg = (errBody as any)?.errorMessage || (errBody as any)?.rejectReason || `HTTP ${res.status}`;
    throw new Error(`OANDA Error: ${errMsg}`);
  }

  return res.json();
}

// ─── Account Info ────────────────────────────────────────────────────
export async function getAccountInfo(config: OandaConfig): Promise<OandaAccountInfo> {
  const data = await oandaFetch(config, `/accounts/${config.accountId}/summary`);
  const acc = data.account;
  return {
    id: acc.id,
    currency: acc.currency,
    balance: parseFloat(acc.balance),
    unrealizedPL: parseFloat(acc.unrealizedPL),
    marginUsed: parseFloat(acc.marginUsed),
    marginAvailable: parseFloat(acc.marginAvailable),
    openTradeCount: acc.openTradeCount,
    openPositionCount: acc.openPositionCount,
  };
}

// ─── Get Prices ──────────────────────────────────────────────────────
export async function getPrices(config: OandaConfig, instruments: string[]): Promise<OandaPrice[]> {
  const query = instruments.join(",");
  const data = await oandaFetch(config, `/accounts/${config.accountId}/pricing?instruments=${query}`);
  return (data.prices || []).map((p: any) => ({
    instrument: p.instrument,
    bid: parseFloat(p.bids?.[0]?.price || "0"),
    ask: parseFloat(p.asks?.[0]?.price || "0"),
    spread: parseFloat(p.asks?.[0]?.price || "0") - parseFloat(p.bids?.[0]?.price || "0"),
    time: p.time,
  }));
}

// ─── Place Order ─────────────────────────────────────────────────────
export async function placeOrder(config: OandaConfig, order: OandaOrder): Promise<OandaOrderResult> {
  const orderBody: any = {
    order: {
      type: order.type,
      instrument: order.instrument,
      units: String(order.units),
      timeInForce: order.type === "MARKET" ? "FOK" : "GTC",
      positionFill: "DEFAULT",
    },
  };

  if (order.type === "LIMIT" && order.price) {
    orderBody.order.price = String(order.price);
  }
  if (order.type === "STOP" && order.price) {
    orderBody.order.price = String(order.price);
  }

  // Stop Loss
  if (order.stopLossPrice) {
    orderBody.order.stopLossOnFill = {
      price: String(order.stopLossPrice),
      timeInForce: "GTC",
    };
  }

  // Take Profit
  if (order.takeProfitPrice) {
    orderBody.order.takeProfitOnFill = {
      price: String(order.takeProfitPrice),
    };
  }

  // Trailing Stop
  if (order.trailingStopDistance) {
    orderBody.order.trailingStopLossOnFill = {
      distance: String(order.trailingStopDistance),
    };
  }

  try {
    const data = await oandaFetch(config, `/accounts/${config.accountId}/orders`, "POST", orderBody);

    // Check if order was filled immediately (market order)
    if (data.orderFillTransaction) {
      return {
        success: true,
        orderId: data.orderFillTransaction.id,
        tradeId: data.orderFillTransaction.tradeOpened?.tradeID || data.orderFillTransaction.id,
        price: parseFloat(data.orderFillTransaction.price),
        units: parseInt(data.orderFillTransaction.units),
      };
    }

    // Order created but not filled yet (limit/stop)
    if (data.orderCreateTransaction) {
      return {
        success: true,
        orderId: data.orderCreateTransaction.id,
        price: order.price,
        units: order.units,
      };
    }

    // Order rejected
    if (data.orderRejectTransaction) {
      return {
        success: false,
        error: data.orderRejectTransaction.rejectReason || "Order rejected",
      };
    }

    return { success: true, orderId: "unknown" };
  } catch (err: any) {
    return { success: false, error: err.message };
  }
}

// ─── Close Position ──────────────────────────────────────────────────
export async function closePosition(config: OandaConfig, instrument: string, side: "long" | "short" | "all" = "all"): Promise<OandaOrderResult> {
  const body: any = {};
  if (side === "long" || side === "all") body.longUnits = "ALL";
  if (side === "short" || side === "all") body.shortUnits = "ALL";

  try {
    const data = await oandaFetch(config, `/accounts/${config.accountId}/positions/${instrument}/close`, "PUT", body);
    return {
      success: true,
      orderId: data.longOrderFillTransaction?.id || data.shortOrderFillTransaction?.id || "closed",
      price: parseFloat(data.longOrderFillTransaction?.price || data.shortOrderFillTransaction?.price || "0"),
    };
  } catch (err: any) {
    return { success: false, error: err.message };
  }
}

// ─── Get Open Positions ──────────────────────────────────────────────
export async function getOpenPositions(config: OandaConfig): Promise<OandaPosition[]> {
  const data = await oandaFetch(config, `/accounts/${config.accountId}/openPositions`);
  return (data.positions || []).map((p: any) => ({
    instrument: p.instrument,
    long: {
      units: parseInt(p.long?.units || "0"),
      averagePrice: parseFloat(p.long?.averagePrice || "0"),
      unrealizedPL: parseFloat(p.long?.unrealizedPL || "0"),
    },
    short: {
      units: Math.abs(parseInt(p.short?.units || "0")),
      averagePrice: parseFloat(p.short?.averagePrice || "0"),
      unrealizedPL: parseFloat(p.short?.unrealizedPL || "0"),
    },
  }));
}

// ─── Get Open Trades ─────────────────────────────────────────────────
export async function getOpenTrades(config: OandaConfig): Promise<any[]> {
  const data = await oandaFetch(config, `/accounts/${config.accountId}/openTrades`);
  return (data.trades || []).map((t: any) => ({
    id: t.id,
    instrument: t.instrument,
    units: parseInt(t.currentUnits),
    price: parseFloat(t.price),
    unrealizedPL: parseFloat(t.unrealizedPL),
    openTime: t.openTime,
    stopLoss: t.stopLossOrder?.price ? parseFloat(t.stopLossOrder.price) : null,
    takeProfit: t.takeProfitOrder?.price ? parseFloat(t.takeProfitOrder.price) : null,
  }));
}

// ─── Close Trade by ID ───────────────────────────────────────────────
export async function closeTrade(config: OandaConfig, tradeId: string): Promise<OandaOrderResult> {
  try {
    const data = await oandaFetch(config, `/accounts/${config.accountId}/trades/${tradeId}/close`, "PUT", { units: "ALL" });
    return {
      success: true,
      orderId: data.orderFillTransaction?.id || tradeId,
      price: parseFloat(data.orderFillTransaction?.price || "0"),
    };
  } catch (err: any) {
    return { success: false, error: err.message };
  }
}

// ─── Test Connection ─────────────────────────────────────────────────
export async function testConnection(config: OandaConfig): Promise<{ success: boolean; info?: OandaAccountInfo; error?: string }> {
  try {
    const info = await getAccountInfo(config);
    return { success: true, info };
  } catch (err: any) {
    return { success: false, error: err.message };
  }
}

// ─── Convert HAYO pair format to OANDA format ────────────────────────
// Explicit map: guessing ("USOIL" → "USOIL") produced instruments OANDA rejects.
const HAYO_TO_OANDA: Record<string, string> = {
  EURUSD: "EUR_USD", USDJPY: "USD_JPY", GBPUSD: "GBP_USD", GBPJPY: "GBP_JPY",
  USDCHF: "USD_CHF", AUDUSD: "AUD_USD", NZDUSD: "NZD_USD", USDCAD: "USD_CAD",
  EURGBP: "EUR_GBP", EURJPY: "EUR_JPY", EURCHF: "EUR_CHF", AUDCAD: "AUD_CAD",
  XAUUSD: "XAU_USD", XAGUSD: "XAG_USD", BTCUSD: "BTC_USD",
  US30: "US30_USD", USOIL: "WTICO_USD",
};

export function toOandaInstrument(pair: string): string | null {
  const clean = pair.replace(/[^A-Za-z0-9]/g, "").toUpperCase();
  return HAYO_TO_OANDA[clean] ?? null;
}

// ─── Quote → account-currency conversion ─────────────────────────────
/**
 * Value, in the ACCOUNT currency, of a 1.0 move in the instrument's QUOTE
 * currency — i.e. what 1 unit loses per 1.0 of adverse price movement.
 * Uses OANDA's own home-conversion factors (the rate OANDA applies to
 * realised P/L), falling back to exact algebra when quote/base IS the account
 * currency. Returns null when it can't be determined — callers must refuse.
 */
async function quoteToAccountRate(config: OandaConfig, instrument: string, accountCurrency: string, mid: number): Promise<number | null> {
  const [base, quote] = instrument.split("_");
  if (quote === accountCurrency) return 1;
  try {
    const data = await oandaFetch(config, `/accounts/${config.accountId}/pricing?instruments=${instrument}&includeHomeConversions=true`);
    const conv = (data.homeConversions || []).find((h: any) => h.currency === quote);
    const loss = parseFloat(conv?.accountLoss);
    if (isFinite(loss) && loss > 0) return loss;
  } catch { /* fall through */ }
  if (base === accountCurrency && mid > 0) return 1 / mid;
  return null;
}

// ─── Auto-Execute Signal ─────────────────────────────────────────────
/** Hard ceiling on position notional vs. balance, independent of the stop. */
const MAX_EFFECTIVE_LEVERAGE = 20;

export async function autoExecuteSignal(
  config: OandaConfig,
  signal: {
    pair: string;
    direction: "BUY" | "SELL";
    confidence: number;
    stopLoss?: number;
    takeProfit?: number;
  },
  riskPercent: number = 1,
): Promise<OandaOrderResult & { riskInfo?: string }> {
  // 0. A protective stop is mandatory: no stop = unbounded risk.
  const sl = signal.stopLoss;
  if (sl === undefined || !isFinite(sl) || sl <= 0) {
    return { success: false, error: "رُفض التنفيذ: لا يوجد وقف خسارة صالح — لا تُفتح صفقات بدون وقف" };
  }
  const risk = Math.min(Math.max(riskPercent, 0.1), 5);

  const instrument = toOandaInstrument(signal.pair);
  if (!instrument) return { success: false, error: `الأداة ${signal.pair} غير مدعومة على OANDA` };

  // 1. Account + live price
  const account = await getAccountInfo(config);
  const prices = await getPrices(config, [instrument]);
  const price = prices[0];
  if (!price || !(price.bid > 0) || !(price.ask > 0)) {
    return { success: false, error: `لم يتم العثور على سعر ${instrument}` };
  }
  const isBuy = signal.direction === "BUY";
  const entry = isBuy ? price.ask : price.bid; // the side we actually fill at
  const mid = (price.bid + price.ask) / 2;

  // 2. Stop / target must sit on the correct side of the fill price.
  if (isBuy ? sl >= price.bid : sl <= price.ask) {
    return { success: false, error: `رُفض التنفيذ: وقف الخسارة ${sl} في الجهة الخاطئة من السعر (${isBuy ? "شراء" : "بيع"} @ ${entry})` };
  }
  const tp = signal.takeProfit;
  if (tp !== undefined && (isBuy ? tp <= entry : tp >= entry)) {
    return { success: false, error: `رُفض التنفيذ: الهدف ${tp} في الجهة الخاطئة من سعر الدخول ${entry}` };
  }

  // 3. Risk-based size: units = riskAmount / (stop distance × quote→account rate)
  const slDistance = Math.abs(entry - sl);
  const rate = await quoteToAccountRate(config, instrument, account.currency, mid);
  if (!rate) {
    return { success: false, error: `تعذّر تحويل عملة التسعير لـ ${instrument} إلى ${account.currency} — رُفض التنفيذ بدل تخمين الحجم` };
  }
  const riskAmount = account.balance * (risk / 100);
  const lossPerUnit = slDistance * rate;
  let units = Math.floor(riskAmount / lossPerUnit);

  // Leverage ceiling: a very tight stop must not produce a huge position.
  const notionalPerUnit = mid * rate;
  const maxUnits = Math.floor((account.balance * MAX_EFFECTIVE_LEVERAGE) / notionalPerUnit);
  const capped = units > maxUnits;
  if (capped) units = maxUnits;
  if (units < 1) {
    return { success: false, error: `الحجم المحسوب أقل من وحدة واحدة (مخاطرة ${riskAmount.toFixed(2)} ${account.currency}، الوقف بعيد جداً)` };
  }

  // 4. Place order
  const result = await placeOrder(config, {
    instrument,
    units: isBuy ? units : -units,
    type: "MARKET",
    stopLossPrice: sl,
    takeProfitPrice: tp,
  });

  const actualRisk = units * lossPerUnit;
  return {
    ...result,
    riskInfo: `المخاطرة: ${(actualRisk / account.balance * 100).toFixed(2)}% = ${actualRisk.toFixed(2)} ${account.currency} | الحجم: ${units} وحدة${capped ? ` (مقيّد بسقف رافعة ${MAX_EFFECTIVE_LEVERAGE}x)` : ""} | الدخول: ${entry}`,
  };
}

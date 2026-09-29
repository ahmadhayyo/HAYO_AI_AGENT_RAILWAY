/**
 * Trading Bridge Service — يربط بين قسم الأسواق المالية ومنصات التداول
 *
 * المسؤوليات:
 *  1. اختبار الاتصال الفعلي بالمنصة (OANDA فقط عبر REST API الرسمي)
 *  2. تنفيذ الصفقات تلقائياً على OANDA بناءً على الإشارات القادمة من قسم التحليل
 *  3. تخزين نتيجة كل صفقة في جدول broker_trades
 *
 * ملاحظات (بصدق):
 *  - منصات الخيارات الثنائية (Quotex/IQ/PocketOption/OlympTrade) لا تنشر API رسمياً،
 *    وMT4/MT5 يحتاج جسراً (MetaApi) غير مبني بعد. لذلك لا يمكن التحقق من بيانات
 *    الدخول ولا التنفيذ الآلي عليها: تُعلَّم "غير متحقق" وتُرسل إشاراتها إلى
 *    Telegram للتنفيذ اليدوي فقط. لا نطلب ولا نخزّن كلمات مرور هذه المنصات.
 *  - منصة OANDA تعمل كاملاً عبر REST API الرسمي (placeOrder حقيقي).
 */

import { encrypt, decrypt } from "./encryption.js";
import { autoExecuteSignal, testConnection as testOanda } from "./oanda-trading.js";

// ─── Types ───────────────────────────────────────────────────────────
export type SupportedPlatform =
  | "quotex"
  | "iqoption"
  | "pocketoption"
  | "olymptrade"
  | "oanda"
  | "mt4"
  | "mt5";

export interface BrokerCredentials {
  platform: SupportedPlatform;
  accountEmail?: string | null;
  accountPasswordEnc?: string | null;
  apiTokenEnc?: string | null;
  apiSecretEnc?: string | null;
  externalAccountId?: string | null;
  serverHost?: string | null;
  environment?: string | null;
}

export interface SignalInput {
  pair: string;
  direction: "BUY" | "SELL" | "CALL" | "PUT";
  confidence: number;
  amount?: number;
  durationSeconds?: number;
  stopLoss?: number;
  takeProfit?: number;
  riskPercent?: number;
}

export interface TradeExecutionResult {
  success: boolean;
  /** true when the platform has no automated execution — signal was only notified */
  manualOnly?: boolean;
  platform: SupportedPlatform;
  tradeId?: string;
  externalId?: string;
  price?: number;
  units?: number;
  message: string;
  error?: string;
}

// ─── Encryption helpers (safe wrappers) ──────────────────────────────
export function encryptCred(value: string | undefined | null): string | null {
  if (!value) return null;
  try { return encrypt(value); } catch { return null; }
}

export function decryptCred(value: string | undefined | null): string | null {
  if (!value) return null;
  try { return decrypt(value) || null; } catch { return null; }
}

// ─── Connection Test ─────────────────────────────────────────────────
export type ConnectionStatus = "connected" | "error" | "unverified";

/**
 * يختبر الاتصال بمنصة التداول. success=true فقط عند نجاح مصادقة حقيقية (OANDA).
 * المنصات بلا API رسمي تُعاد بحالة "unverified" — لا ندّعي تحققاً لم يحدث.
 */
export async function testBrokerConnection(creds: BrokerCredentials): Promise<{ success: boolean; status: ConnectionStatus; message: string; details?: any }> {
  const apiToken = decryptCred(creds.apiTokenEnc);

  // OANDA — REST API check
  if (creds.platform === "oanda") {
    if (!apiToken || !creds.externalAccountId) {
      return { success: false, status: "error", message: "OANDA يتطلب API Token + Account ID" };
    }
    const env = (creds.environment === "live" ? "live" : "practice") as "live" | "practice";
    const r = await testOanda({ apiToken, accountId: creds.externalAccountId, environment: env });
    if (!r.success) return { success: false, status: "error", message: r.error || "فشل المصادقة على OANDA" };
    return { success: true, status: "connected", message: "✅ تم الاتصال بـ OANDA بنجاح", details: r.info };
  }

  // MT4 / MT5 — no bridge yet: nothing can be verified.
  if (creds.platform === "mt4" || creds.platform === "mt5") {
    return {
      success: false, status: "unverified",
      message: "⚠️ غير متحقق: جسر MT4/MT5 غير متوفر بعد — الإشارات تُرسل إلى Telegram للتنفيذ اليدوي فقط",
    };
  }

  // Binary-options platforms — no official public API.
  if (["quotex", "iqoption", "pocketoption", "olymptrade"].includes(creds.platform)) {
    return {
      success: false, status: "unverified",
      message: `⚠️ غير متحقق: ${creds.platform} لا توفّر API رسمياً — لا يمكن التحقق من الحساب أو التنفيذ الآلي؛ الإشارات تُرسل إلى Telegram للتنفيذ اليدوي فقط`,
    };
  }

  return { success: false, status: "error", message: "منصة غير مدعومة بعد" };
}

// ─── Execute Signal on Broker ────────────────────────────────────────
/**
 * ينفذ الإشارة على المنصة الفعلية إن كانت تدعم API،
 * أو يحفظها كصفقة pending مع إشعار Telegram للتنفيذ اليدوي.
 */
export async function executeSignalOnBroker(
  creds: BrokerCredentials,
  signal: SignalInput,
): Promise<TradeExecutionResult> {
  const apiToken = decryptCred(creds.apiTokenEnc);

  // OANDA — تنفيذ حقيقي
  if (creds.platform === "oanda") {
    if (!apiToken || !creds.externalAccountId) {
      return {
        success: false,
        platform: "oanda",
        message: "بيانات OANDA ناقصة",
        error: "missing_credentials",
      };
    }
    const env = (creds.environment === "live" ? "live" : "practice") as "live" | "practice";
    const dir: "BUY" | "SELL" =
      signal.direction === "BUY" || signal.direction === "CALL" ? "BUY" : "SELL";
    const r = await autoExecuteSignal(
      { apiToken, accountId: creds.externalAccountId, environment: env },
      {
        pair: signal.pair,
        direction: dir,
        confidence: signal.confidence,
        stopLoss: signal.stopLoss,
        takeProfit: signal.takeProfit,
      },
      signal.riskPercent ?? 1,
    );
    return {
      success: !!r.success,
      platform: "oanda",
      externalId: r.tradeId || r.orderId,
      price: r.price,
      units: r.units,
      message: r.success ? r.riskInfo || "تم التنفيذ" : r.error || "فشل التنفيذ",
      error: r.success ? undefined : r.error,
    };
  }

  // No automated execution exists for this platform: nothing was traded.
  return {
    success: false,
    manualOnly: true,
    platform: creds.platform,
    message: `لم تُنفَّذ صفقة: ${creds.platform} لا تدعم التنفيذ الآلي — أُرسلت الإشارة ${signal.direction} على ${signal.pair} إلى Telegram للتنفيذ اليدوي`,
  };
}

// ─── Format helper ────────────────────────────────────────────────────
export function formatSignalMessage(signal: SignalInput, platform: string, result?: TradeExecutionResult): string {
  const dirEmoji = signal.direction === "BUY" || signal.direction === "CALL" ? "🟢" : "🔴";
  const dirText = signal.direction === "BUY" || signal.direction === "CALL" ? "شراء (CALL)" : "بيع (PUT)";
  const status = result
    ? result.manualOnly
      ? "📝 *للتنفيذ اليدوي* — هذه المنصة لا تدعم التنفيذ الآلي"
      : result.success
      ? "✅ *تم التنفيذ بنجاح*"
      : `❌ *فشل التنفيذ:* ${result.error || result.message}`
    : "⏳ *قيد الإرسال*";

  return [
    `${dirEmoji} *إشارة HAYO AI*`,
    "",
    `📊 الزوج: \`${signal.pair}\``,
    `🎯 الاتجاه: ${dirText}`,
    `📈 الثقة: *${signal.confidence}%*`,
    `🏦 المنصة: \`${platform}\``,
    signal.amount ? `💰 المبلغ: $${signal.amount}` : "",
    signal.durationSeconds ? `⏱ المدة: ${signal.durationSeconds}ث` : "",
    signal.stopLoss ? `🛑 SL: ${signal.stopLoss}` : "",
    signal.takeProfit ? `🎯 TP: ${signal.takeProfit}` : "",
    "",
    status,
    result?.price ? `💲 السعر المنفذ: ${result.price}` : "",
    result?.externalId ? `🔖 معرّف الصفقة: \`${result.externalId}\`` : "",
  ].filter(Boolean).join("\n");
}

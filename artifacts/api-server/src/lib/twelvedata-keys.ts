const allKeys: string[] = [];
let currentIndex = 0;
const exhaustedKeys = new Set<string>();
let lastResetDay = new Date().getUTCDate();

function loadKeys() {
  if (allKeys.length > 0) return;

  // TWELVE_DATA_API_KEYS (plural) — primary: comma-separated list of keys
  const multi = process.env.TWELVE_DATA_API_KEYS;
  if (multi) {
    allKeys.push(...multi.split(",").map(k => k.trim()).filter(Boolean));
  }

  // TWELVE_DATA_API_KEY (singular) — also supports comma-separated values
  // e.g. TWELVE_DATA_API_KEY=key1,key2,key3 works correctly
  const single = process.env.TWELVE_DATA_API_KEY;
  if (single) {
    const singleKeys = single.split(",").map(k => k.trim()).filter(Boolean);
    for (const k of singleKeys) {
      if (!allKeys.includes(k)) allKeys.push(k);
    }
  }

  if (allKeys.length === 0) {
    console.error("[TwelveData] No API keys found! Set TWELVE_DATA_API_KEYS (comma-separated) or TWELVE_DATA_API_KEY");
  } else {
    console.log(`[TwelveData] Loaded ${allKeys.length} API key(s) for rotation`);
  }
}

function checkDailyReset() {
  const today = new Date().getUTCDate();
  if (today !== lastResetDay) {
    exhaustedKeys.clear();
    lastResetDay = today;
    currentIndex = 0;
    console.log("[TwelveData] Daily reset (new UTC day) — all keys available again");
  }
}

export function getTwelveDataKey(): string {
  loadKeys();
  if (allKeys.length === 0) return "";

  checkDailyReset();

  if (exhaustedKeys.size >= allKeys.length) {
    console.warn("[TwelveData] All keys exhausted for the day!");
    return allKeys[0];
  }

  let attempts = 0;
  while (attempts < allKeys.length) {
    const key = allKeys[currentIndex % allKeys.length];
    if (!exhaustedKeys.has(key)) return key;
    currentIndex++;
    attempts++;
  }
  return allKeys[0];
}

export function rotateToNextKey() {
  currentIndex++;
}

export function markKeyExhausted(key: string) {
  exhaustedKeys.add(key);
  currentIndex++;
  const remaining = allKeys.length - exhaustedKeys.size;
  console.log(`[TwelveData] Key ...${key.slice(-6)} exhausted (daily limit). ${remaining}/${allKeys.length} keys remaining`);
}

export async function checkAndMarkIfDailyExhausted(key: string): Promise<boolean> {
  try {
    const res = await fetch(`https://api.twelvedata.com/api_usage?apikey=${key}`, { signal: AbortSignal.timeout(5000) });
    const data = await res.json() as any;
    if (data.daily_usage >= data.plan_daily_limit * 0.95) {
      markKeyExhausted(key);
      return true;
    }
  } catch {}
  return false;
}

export function isRateLimitError(responseOrMsg: any): boolean {
  if (typeof responseOrMsg === "string") {
    return responseOrMsg.includes("run out of API credits") || responseOrMsg.includes("429") || responseOrMsg.includes("Too many requests");
  }
  if (responseOrMsg?.status === "error") {
    const msg = (responseOrMsg.message || "").toLowerCase();
    return msg.includes("run out of api credits") || msg.includes("too many requests") || msg.includes("per minute") || responseOrMsg.code === 429;
  }
  return false;
}

export functi
/**
 * Multi-Model AI Provider System
 * claude:    Claude Opus 4.6   — Anthropic (PRIMARY ✅)
 * gpt4:      GPT-4o            — OpenAI    (working ✅)
 * gemini:    Gemini 2.5 Flash  — Google    (no key ❌)
 * geminiPro: Gemini 2.5 Pro   — Google    (no key ❌)
 * deepseek:  DeepSeek R1       — DeepSeek  (working ✅)
 *
 * Active keys: OPENAI_API_KEY (gpt-4o-2024-08-06, backup: OPENAI_API_KEY_BACKUP) + OPENAI_API_KEY_ (DeepSeek)
 */
import { createAnthropicClient } from "./llm";

export type AIProvider = "claude" | "gpt4" | "gemini" | "geminiPro" | "deepseek";

/** DeepSeek API key — stored as DEEPSEEK_API_KEY or OPENAI_API_KEY_ (both valid) */
const dsKey = () => process.env.DEEPSEEK_API_KEY || process.env.OPENAI_API_KEY_ || "";

/**
 * OpenRouter (openrouter.ai) — one key → many models, incl. FREE ones. Used as an
 * automatic fallback so each model slot keeps working when its native key is
 * missing OR fails (e.g. out of credit) — at zero cost via `:free` models.
 * Set OPENROUTER_API_KEY. Override any slot's model via OPENROUTER_MODEL_<SLOT>.
 */
const orKey = () => process.env.OPENROUTER_API_KEY || "";
const OPENROUTER_MODEL: Record<AIProvider, string> = {
  claude:    process.env.OPENROUTER_MODEL_CLAUDE    || "deepseek/deepseek-r1:free",
  gpt4:      process.env.OPENROUTER_MODEL_GPT4      || "meta-llama/llama-3.3-70b-instruct:free",
  gemini:    process.env.OPENROUTER_MODEL_GEMINI    || "google/gemini-2.0-flash-exp:free",
  geminiPro: process.env.OPENROUTER_MODEL_GEMINIPRO || "google/gemini-2.0-flash-exp:free",
  deepseek:  process.env.OPENROUTER_MODEL_DEEPSEEK  || "deepseek/deepseek-chat:free",
};

async function callOpenRouter(model: string, systemPrompt: string, userMessage: string, maxTokens = 8192): Promise<string> {
  const res = await fetch("https://openrouter.ai/api/v1/chat/completions", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${orKey()}`,
      "Content-Type": "application/json",
      "HTTP-Referer": "https://hayoaiagentrailway-production.up.railway.app",
      "X-Title": "HAYO AI",
    },
    body: JSON.stringify({
      model,
      max_tokens: Math.min(maxTokens, 8192),
      messages: [{ role: "system", content: systemPrompt }, { role: "user", content: userMessage }],
    }),
    signal: AbortSignal.timeout(120000),
  });
  const data = await res.json() as any;
  if (!res.ok || data.error) throw new Error(`OpenRouter ${res.status}: ${data.error?.message || JSON.stringify(data).slice(0, 140)}`);
  const content = data.choices?.[0]?.message?.content || "";
  if (!content) throw new Error("OpenRouter: رد فارغ");
  return content;
}

export interface ProviderConfig {
  id: AIProvider;
  name: string;
  model: string;
  icon: string;
  color: string;
  role: string;
  envKey: string;
}

export const PROVIDER_CONFIGS: Record<AIProvider, ProviderConfig> = {
  claude: {
    id: "claude",
    name: "Claude Opus",
    model: "claude-opus-4-6",
    icon: "🟣",
    color: "#7C3AED",
    role: "coordinator",
    envKey: "AI_INTEGRATIONS_ANTHROPIC_API_KEY",
  },
  gpt4: {
    id: "gpt4",
    name: "GPT-4o",
    model: "gpt-4o-2024-08-06",
    icon: "🟡",
    color: "#10A37F",
    role: "coder",
    envKey: "OPENAI_API_KEY",
  },
  gemini: {
    id: "gemini",
    name: "Gemini 2.5 Flash",
    model: "gemini-2.5-flash",
    icon: "🔵",
    color: "#3B82F6",
    role: "reviewer",
    envKey: "GOOGLE_API_KEY3",
  },
  geminiPro: {
    id: "geminiPro",
    name: "Gemini 2.5 Pro",
    model: "gemini-2.5-pro",
    icon: "💎",
    color: "#06B6D4",
    role: "deep-analyst",
    envKey: "GOOGLE_API_KEY3",
  },
  deepseek: {
    id: "deepseek",
    name: "DeepSeek R1",
    model: "deepseek-reasoner",
    icon: "⚡",
    color: "#F59E0B",
    role: "planner",
    envKey: "DEEPSEEK_API_KEY",
  },
};

/**
 * OpenAI keys in priority order: OPENAI_API_KEY, then OPENAI_API_KEY_BACKUP.
 * A key that answers 401/403 (invalid) or 429 (out of credit / rate-limited)
 * is benched for 10 minutes and the next key is tried, so GPT-4o keeps
 * working when one key runs dry.
 */
function openaiKeys(): string[] {
  return [...new Set([process.env.OPENAI_API_KEY, process.env.OPENAI_API_KEY_BACKUP].map(k => (k || "").trim()).filter(Boolean))];
}
const openaiBenchedUntil = new Map<string, number>();
const keyLabel = (i: number) => (i === 0 ? "OPENAI_API_KEY" : "OPENAI_API_KEY_BACKUP");

async function openaiFetch(body: string, timeoutMs: number): Promise<Response> {
  const keys = openaiKeys();
  if (!keys.length) throw new Error("OpenAI: no API key configured");
  const now = Date.now();
  const order = [...keys.filter(k => (openaiBenchedUntil.get(k) ?? 0) <= now), ...keys.filter(k => (openaiBenchedUntil.get(k) ?? 0) > now)];
  let last: Response | null = null;
  for (const key of order) {
    const res = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" },
      body,
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (res.status !== 401 && res.status !== 403 && res.status !== 429) {
      openaiBenchedUntil.delete(key);
      return res;
    }
    openaiBenchedUntil.set(key, Date.now() + 10 * 60_000);
    console.warn(`[OpenAI] ${keyLabel(keys.indexOf(key))} → HTTP ${res.status}; trying the next key`);
    last = res;
  }
  return last!;
}

/** Boot-time check of every OpenAI key (1-token call) — logs status, never the key. */
export async function checkOpenAIKeys(): Promise<void> {
  const keys = openaiKeys();
  if (!keys.length) { console.log("[OpenAI] no key configured"); return; }
  for (let i = 0; i < keys.length; i++) {
    try {
      const res = await fetch("https://api.openai.com/v1/chat/completions", {
        method: "POST",
        headers: { Authorization: `Bearer ${keys[i]}`, "Content-Type": "application/json" },
        body: JSON.stringify({ model: "gpt-4o-mini", max_tokens: 1, messages: [{ role: "user", content: "ok" }] }),
        signal: AbortSignal.timeout(15000),
      });
      const j: any = await res.json().catch(() => ({}));
      const status = res.ok ? "✅ يعمل وفيه رصيد"
        : res.status === 401 ? "❌ مفتاح غير صالح (401)"
        : j?.error?.code === "insufficient_quota" ? "❌ لا يوجد رصيد (insufficient_quota)"
        : `⚠️ HTTP ${res.status}: ${String(j?.error?.message ?? "").slice(0, 80)}`;
      console.log(`[OpenAI] ${keyLabel(i)}: ${status}`);
      if (!res.ok) openaiBenchedUntil.set(keys[i], Date.now() + 10 * 60_000);
    } catch (e: any) {
      console.log(`[OpenAI] ${keyLabel(i)}: ⚠️ تعذّر الفحص — ${e.message?.slice(0, 60)}`);
    }
  }
}

/** True only when the provider's OWN (native) key is configured. */
function isNativeAvailable(provider: AIProvider): boolean {
  if (provider === "claude") {
    return !!(process.env.ANTHROPIC_API_KEY || process.env.AI_INTEGRATIONS_ANTHROPIC_API_KEY);
  }
  if (provider === "gpt4") {
    return openaiKeys().length > 0;
  }
  if (provider === "deepseek") {
    return !!(dsKey());
  }
  const config = PROVIDER_CONFIGS[provider];
  return !!(process.env[config.envKey]);
}

/** A slot is usable if it has a native key OR OpenRouter can serve it. */
export function isProviderAvailable(provider: AIProvider): boolean {
  return isNativeAvailable(provider) || !!orKey();
}

export function getAvailableProviders(): ProviderConfig[] {
  return Object.values(PROVIDER_CONFIGS).map(p => ({
    ...p,
    available: isProviderAvailable(p.id as AIProvider),
  } as any));
}

/**
 * Call a specific AI provider with a prompt.
 * Falls back to the best available model when the requested one is unavailable.
 * Priority fallback: gpt4 (OpenAI) → deepseek-chat → deepseek-reasoner
 */
export async function callProvider(
  provider: AIProvider,
  systemPrompt: string,
  userMessage: string
): Promise<{ content: string; provider: AIProvider; duration: number }> {
  const startTime = Date.now();

  let enrichedPrompt = systemPrompt;
  try {
    const { withModelInstruction, resolveModelId } = await import("./system-prompts.js");
    enrichedPrompt = withModelInstruction(resolveModelId(provider), systemPrompt);
  } catch {}

  // Determine the actual provider to use.
  let actualProvider: AIProvider = provider;
  if (!isNativeAvailable(provider)) {
    // No native key for this slot → serve it via OpenRouter (free model), keeping the label.
    if (orKey()) {
      try {
        const content = await callOpenRouter(OPENROUTER_MODEL[provider], enrichedPrompt, userMessage);
        return { content, provider, duration: Date.now() - startTime };
      } catch (e: any) { console.warn(`[callProvider] openrouter ${provider}:`, e.message?.slice(0, 90)); }
    }
    // Else fall back to another native provider that has a key.
    if (isNativeAvailable("gpt4")) actualProvider = "gpt4";
    else if (isNativeAvailable("deepseek")) actualProvider = "deepseek";
  }

  try {
    let content = "";

    switch (actualProvider) {
      case "claude": {
        const anthropic = createAnthropicClient();
        const result = await anthropic.messages.create({
          model: PROVIDER_CONFIGS.claude.model,
          max_tokens: 8192,
          system: systemPrompt,
          messages: [{ role: "user", content: userMessage }],
        });
        content = result.content[0].type === "text" ? result.content[0].text : "";
        break;
      }

      case "gpt4": {
        // GPT-4o via OpenAI ✅
        const res = await openaiFetch(JSON.stringify({
            model: PROVIDER_CONFIGS.gpt4.model, // gpt-4o-2024-08-06
            max_tokens: 4096,
            messages: [
              { role: "system", content: systemPrompt },
              { role: "user", content: userMessage },
            ],
          }), 60000);
        const data = await res.json() as any;
        if (!res.ok || data.error) throw new Error(`OpenAI error: ${data.error?.message || res.status}`);
        content = data.choices?.[0]?.message?.content || "";
        break;
      }

      case "gemini":
      case "geminiPro": {
        const geminiKey = process.env.GOOGLE_API_KEY3 || process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY;
        const geminiBody = JSON.stringify({
          systemInstruction: { parts: [{ text: systemPrompt }] },
          contents: [{ role: "user", parts: [{ text: userMessage }] }],
          generationConfig: { maxOutputTokens: 8192, temperature: 0.3 },
        });
        const modelsToTry = actualProvider === "geminiPro"
          ? ["gemini-2.5-pro", "gemini-2.5-flash"]
          : ["gemini-2.5-flash"];
        let geminiData: any;
        let geminiOk = false;
        let usedModel = "";
        for (const model of modelsToTry) {
          for (let retry = 0; retry < 2; retry++) {
            try {
              const res = await fetch(
                `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${geminiKey}`,
                {
                  method: "POST",
                  headers: { "Content-Type": "application/json" },
                  body: geminiBody,
                  signal: AbortSignal.timeout(60000),
                }
              );
              geminiData = await res.json() as any;
              if (res.status === 503 || res.status === 429) {
                if (retry === 0) { await new Promise(r => setTimeout(r, 4000)); continue; }
                break;
              }
              if (!res.ok || geminiData.error) {
                if (retry === 0) { await new Promise(r => setTimeout(r, 2000)); continue; }
                break;
              }
              geminiOk = true;
              usedModel = model;
              break;
            } catch { if (retry === 0) { await new Promise(r => setTimeout(r, 2000)); continue; } break; }
          }
          if (geminiOk) break;
        }
        if (!geminiOk) {
          throw new Error(`Gemini: خوادم Google مشغولة — حاول بعد قليل`);
        }
        content = geminiData.candidates?.[0]?.content?.parts?.[0]?.text || "";
        if (usedModel && usedModel !== PROVIDER_CONFIGS[actualProvider].model) {
          content = `[تم استخدام ${usedModel} بدلاً من ${PROVIDER_CONFIGS[actualProvider].model} بسبب ضغط الخوادم]\n\n${content}`;
        }
        break;
      }

      case "deepseek": {
        const res = await fetch("https://api.deepseek.com/v1/chat/completions", {
          method: "POST",
          headers: {
            "Authorization": `Bearer ${dsKey()}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            model: PROVIDER_CONFIGS.deepseek.model,
            max_tokens: 4096,
            messages: [
              { role: "system", content: systemPrompt },
              { role: "user", content: userMessage },
            ],
          }),
          signal: AbortSignal.timeout(60000),
        });
        const data = await res.json() as any;
        if (!res.ok || data.error) {
          throw new Error(`DeepSeek API error ${res.status}: ${data.error?.message || JSON.stringify(data)}`);
        }
        content = data.choices?.[0]?.message?.content || "";
        break;
      }
    }

    return {
      content,
      provider: actualProvider,
      duration: Date.now() - startTime,
    };
  } catch (error: any) {
    // Native call failed (e.g. out of credit / rate-limited) → OpenRouter free fallback for this slot.
    if (orKey()) {
      try {
        const content = await callOpenRouter(OPENROUTER_MODEL[provider], enrichedPrompt, userMessage);
        if (content) return { content, provider, duration: Date.now() - startTime };
      } catch (e: any) { console.warn(`[callProvider] openrouter fallback ${provider}:`, e.message?.slice(0, 90)); }
    }
    throw new Error(`[${actualProvider}] ${error.message}`);
  }
}

/**
 * Power AI call — uses the strongest available model for heavy tasks.
 * Priority (as of 2025): GPT-4o → DeepSeek Chat → DeepSeek Reasoner
 * (Anthropic has active, Gemini has no key)
 */
export async function callPowerAI(
  systemPrompt: string,
  userMessage: string,
  maxTokens = 8192
): Promise<{ content: string; modelUsed: string }> {
  let enrichedPrompt = systemPrompt;
  try { const { withModelInstruction } = await import("./system-prompts.js"); enrichedPrompt = withModelInstruction("gpt-4o", systemPrompt); } catch {}

  const openaiKey = openaiKeys().length > 0;
  const hasAnthropicKey = process.env.ANTHROPIC_API_KEY || (process.env.AI_INTEGRATIONS_ANTHROPIC_API_KEY && process.env.AI_INTEGRATIONS_ANTHROPIC_BASE_URL);
  const geminiKey = process.env.GOOGLE_API_KEY3 || process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY;

  // 3. GPT-4o (fallback ✅)
  if (openaiKey) {
    try {
      const res = await openaiFetch(JSON.stringify({
          model: "gpt-4o-2024-08-06",
          max_tokens: Math.min(maxTokens, 4096),
          messages: [{ role: "system", content: systemPrompt }, { role: "user", content: userMessage }],
        }), 90000);
      const data = await res.json() as any;
      if (res.ok && !data.error) {
        const content = data.choices?.[0]?.message?.content || "";
        if (content) return { content, modelUsed: "gpt-4o-2024-08-06" };
      }
      console.warn("[callPowerAI] gpt-4o failed:", data.error?.message?.slice(0, 80));
    } catch (e: any) {
      console.warn("[callPowerAI] gpt-4o error:", e.message?.slice(0, 80));
    }
  }

  // 1. Claude Opus 4.6 (PRIMARY (try if key exists — may fail due to low credits)
  if (hasAnthropicKey) {
    try {
      const anthropic = createAnthropicClient();
      const result = await anthropic.messages.create({
        model: "claude-opus-4-6",
        max_tokens: Math.min(maxTokens, 8192),
        system: systemPrompt,
        messages: [{ role: "user", content: userMessage }],
      });
      const block = result.content[0];
      return { content: block.type === "text" ? block.text : "", modelUsed: "claude-opus-4-6" };
    } catch (e: any) {
      console.warn("[callPowerAI] claude-opus-4-6 failed:", e.message?.slice(0, 80));
    }
  }

  // 4. Gemini 2.5 Flash (if key becomes available)
  if (geminiKey) {
    try {
      const res = await fetch(
        `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${geminiKey}`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            systemInstruction: { parts: [{ text: systemPrompt }] },
            contents: [{ role: "user", parts: [{ text: userMessage }] }],
            generationConfig: { maxOutputTokens: Math.min(maxTokens, 8192), temperature: 0.2 },
          }),
          signal: AbortSignal.timeout(60000),
        }
      );
      const data = await res.json() as any;
      if (res.ok && !data.error) {
        const content = data.candidates?.[0]?.content?.parts?.[0]?.text || "";
        if (content) return { content, modelUsed: "gemini-2.5-flash" };
      }
    } catch (e: any) {
      console.warn("[callPowerAI] Gemini error:", e.message?.slice(0, 80));
    }
  }

  // 2. DeepSeek Chat (SECONDARY (fast, working ✅)
  if (dsKey()) {
    try {
      const res = await fetch("https://api.deepseek.com/v1/chat/completions", {
        method: "POST",
        headers: { Authorization: `Bearer ${dsKey()}`, "Content-Type": "application/json" },
        body: JSON.stringify({
          model: "deepseek-chat",
          max_tokens: Math.min(maxTokens, 8192),
          messages: [{ role: "system", content: systemPrompt }, { role: "user", content: userMessage }],
        }),
        signal: AbortSignal.timeout(120000),
      });
      const data = await res.json() as any;
      if (res.ok && !data.error) {
        const content = data.choices?.[0]?.message?.content || "";
        if (content) return { content, modelUsed: "deepseek-chat" };
      }
      console.warn("[callPowerAI] deepseek-chat failed:", data.error?.message?.slice(0, 80));
    } catch (e: any) {
      console.warn("[callPowerAI] deepseek-chat error:", e.message?.slice(0, 80));
    }
  }

  // 5. DeepSeek Reasoner (slow but powerful ✅ — last resort)
  if (dsKey()) {
    const res = await fetch("https://api.deepseek.com/v1/chat/completions", {
      method: "POST",
      headers: { Authorization: `Bearer ${dsKey()}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "deepseek-reasoner",
        max_tokens: Math.min(maxTokens, 8192),
        messages: [{ role: "system", content: systemPrompt }, { role: "user", content: userMessage }],
      }),
      signal: AbortSignal.timeout(180000),
    });
    const data = await res.json() as any;
    if (res.ok && !data.error) return { content: data.choices?.[0]?.message?.content || "", modelUsed: "deepseek-reasoner" };
  }

  // 6. OpenRouter (free models) — last resort so heavy tasks work with no paid keys.
  if (orKey()) {
    for (const model of [OPENROUTER_MODEL.claude, OPENROUTER_MODEL.deepseek, OPENROUTER_MODEL.gpt4]) {
      try {
        const content = await callOpenRouter(model, systemPrompt, userMessage, maxTokens);
        if (content) return { content, modelUsed: `openrouter:${model}` };
      } catch (e: any) { console.warn("[callPowerAI] openrouter error:", e.message?.slice(0, 80)); }
    }
  }

  throw new Error("لا يوجد نموذج AI قوي متاح. يرجى التحقق من الإعدادات.");
}

/**
 * Fast AI call for Office Suite / quick tasks.
 * Priority: DeepSeek Chat (fast ✅) → GPT-4o (✅) → Anthropic (❌ no credits)
 * The `model` param is kept for API compatibility but DeepSeek is used first.
 */
export async function callOfficeAI(
  systemPrompt: string,
  userMessage: string,
  maxTokens = 8192,
  model: "claude-haiku-4-5" | "claude-sonnet-4-6" = "claude-haiku-4-5"
): Promise<string> {
  let enrichedPrompt = systemPrompt;
  try { const { withModelInstruction } = await import("./system-prompts.js"); enrichedPrompt = withModelInstruction("gpt-4o", systemPrompt); } catch {}

  // 1. DeepSeek Chat — fast and working ✅
  if (dsKey()) {
    try {
      const res = await fetch("https://api.deepseek.com/v1/chat/completions", {
        method: "POST",
        headers: { Authorization: `Bearer ${dsKey()}`, "Content-Type": "application/json" },
        body: JSON.stringify({
          model: "deepseek-chat",
          max_tokens: Math.min(maxTokens, 8192),
          messages: [{ role: "system", content: systemPrompt }, { role: "user", content: userMessage }],
        }),
        signal: AbortSignal.timeout(90000),
      });
      const data = await res.json() as any;
      if (res.ok && !data.error) {
        const content = data.choices?.[0]?.message?.content || "";
        if (content) return content;
      }
    } catch (e: any) {
      console.warn("[callOfficeAI] deepseek-chat error:", e.message?.slice(0, 80));
    }
  }

  // 2. GPT-4o — working ✅
  const openaiKey = openaiKeys().length > 0;
  if (openaiKey) {
    try {
      const res = await openaiFetch(JSON.stringify({
          model: "gpt-4o-2024-08-06",
          max_tokens: Math.min(maxTokens, 4096),
          messages: [{ role: "system", content: systemPrompt }, { role: "user", content: userMessage }],
        }), 60000);
      const data = await res.json() as any;
      if (res.ok && !data.error) return data.choices?.[0]?.message?.content || "";
    } catch (e: any) {
      console.warn("[callOfficeAI] gpt-4o error:", e.message?.slice(0, 80));
    }
  }

  // 3. Anthropic fallback (may fail due to low credits)
  const hasAnthropicKey = process.env.ANTHROPIC_API_KEY || (process.env.AI_INTEGRATIONS_ANTHROPIC_API_KEY && process.env.AI_INTEGRATIONS_ANTHROPIC_BASE_URL);
  if (hasAnthropicKey) {
    try {
      const anthropic = createAnthropicClient();
      const result = await anthropic.messages.create({
        model,
        max_tokens: maxTokens,
        system: systemPrompt,
        messages: [{ role: "user", content: userMessage }],
      });
      const block = result.content[0];
      return block.type === "text" ? block.text : "";
    } catch (e: any) {
      console.warn(`[callOfficeAI] ${model} failed:`, e.message?.slice(0, 80));
    }
  }

  // 4. OpenRouter (free) fallback
  if (orKey()) {
    try { return await callOpenRouter(OPENROUTER_MODEL.deepseek, systemPrompt, userMessage, maxTokens); }
    catch (e: any) { console.warn("[callOfficeAI] openrouter error:", e.message?.slice(0, 80)); }
  }

  throw new Error("لا يوجد مزود AI متاح. يرجى التحقق من الإعدادات.");
}

/**
 * Fast AI call — DeepSeek Chat first, fallback to callPowerAI.
 * Returns { content, modelUsed } like callPowerAI.
 * Used for quick validation passes where speed matters more than depth.
 */
export async function callFastAI(
  systemPrompt: string,
  userMessage: string,
  maxTokens = 8192,
): Promise<{ content: string; modelUsed: string }> {
  let enrichedPrompt = systemPrompt;
  try { const { withModelInstruction } = await import("./system-prompts.js"); enrichedPrompt = withModelInstruction("gpt-4o", systemPrompt); } catch {}

  // 1. DeepSeek Chat — fastest available
  if (dsKey()) {
    try {
      const res = await fetch("https://api.deepseek.com/v1/chat/completions", {
        method: "POST",
        headers: { Authorization: `Bearer ${dsKey()}`, "Content-Type": "application/json" },
        body: JSON.stringify({
          model: "deepseek-chat",
          max_tokens: Math.min(maxTokens, 8192),
          messages: [{ role: "system", content: systemPrompt }, { role: "user", content: userMessage }],
        }),
        signal: AbortSignal.timeout(90000),
      });
      const data = await res.json() as any;
      if (res.ok && !data.error) {
        const content = data.choices?.[0]?.message?.content || "";
        if (content) return { content, modelUsed: "deepseek-chat" };
      }
      console.warn("[callFastAI] deepseek-chat failed:", data.error?.message?.slice(0, 80));
    } catch (e: any) {
      console.warn("[callFastAI] deepseek-chat error:", e.message?.slice(0, 80));
    }
  }
  // 2. Fallback to the full power AI chain
  return callPowerAI(systemPrompt, userMessage, maxTokens);
}

// ─── Vision: text + one chart image ─────────────────────────────────────
/** Slots whose native model accepts images (DeepSeek R1 is text-only). */
export const VISION_PROVIDERS: ReadonlySet<AIProvider> = new Set<AIProvider>(["claude", "gpt4", "gemini", "geminiPro"]);

/**
 * Like callProvider, but also shows the model a PNG image. Uses the provider's
 * native vision API when its key is configured; otherwise (no key, no vision
 * support, or the vision call fails) falls back to the text-only callProvider.
 * `sawImage` tells the caller whether the model actually received the image.
 */
export async function callProviderVision(
  provider: AIProvider,
  systemPrompt: string,
  userMessage: string,
  imagePng: Buffer | null,
): Promise<{ content: string; provider: AIProvider; duration: number; sawImage: boolean }> {
  const start = Date.now();
  if (imagePng && VISION_PROVIDERS.has(provider) && isNativeAvailable(provider)) {
    const b64 = imagePng.toString("base64");
    try {
      let content = "";
      if (provider === "claude") {
        const anthropic = createAnthropicClient();
        const result = await anthropic.messages.create({
          model: PROVIDER_CONFIGS.claude.model,
          max_tokens: 4096,
          system: systemPrompt,
          messages: [{ role: "user", content: [
            { type: "image", source: { type: "base64", media_type: "image/png", data: b64 } },
            { type: "text", text: userMessage },
          ] }],
        });
        content = result.content[0]?.type === "text" ? result.content[0].text : "";
      } else if (provider === "gpt4") {
        const res = await openaiFetch(JSON.stringify({
            model: PROVIDER_CONFIGS.gpt4.model,
            max_tokens: 4096,
            messages: [
              { role: "system", content: systemPrompt },
              { role: "user", content: [
                { type: "text", text: userMessage },
                { type: "image_url", image_url: { url: `data:image/png;base64,${b64}`, detail: "high" } },
              ] },
            ],
          }), 90000);
        const data = await res.json() as any;
        if (!res.ok || data.error) throw new Error(`OpenAI vision: ${data.error?.message || res.status}`);
        content = data.choices?.[0]?.message?.content || "";
      } else {
        const geminiKey = process.env.GOOGLE_API_KEY3 || process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY;
        const model = PROVIDER_CONFIGS[provider].model;
        const res = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${geminiKey}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            systemInstruction: { parts: [{ text: systemPrompt }] },
            contents: [{ role: "user", parts: [{ inlineData: { mimeType: "image/png", data: b64 } }, { text: userMessage }] }],
            generationConfig: { maxOutputTokens: 8192, temperature: 0.3 },
          }),
          signal: AbortSignal.timeout(90000),
        });
        const data = await res.json() as any;
        if (!res.ok || data.error) throw new Error(`Gemini vision: ${data.error?.message || res.status}`);
        content = data.candidates?.[0]?.content?.parts?.map((p: any) => p.text || "").join("") || "";
      }
      if (content) return { content, provider, duration: Date.now() - start, sawImage: true };
    } catch (e: any) {
      console.warn(`[callProviderVision] ${provider} vision failed → text-only:`, e.message?.slice(0, 120));
    }
  }
  const r = await callProvider(provider, systemPrompt, userMessage);
  return { ...r, sawImage: false };
}

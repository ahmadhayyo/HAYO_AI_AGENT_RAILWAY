/**
 * HAYO AI — Headless Browser Web Analyzer v1.0
 * Real Puppeteer-based analysis: JS Runtime, Network Interception, Deep API Discovery
 */

import puppeteer, {
  type Browser,
  type Page,
  type HTTPRequest,
  type HTTPResponse,
  type ConsoleMessage,
} from "puppeteer";

// ═══════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════

export interface NetworkRequest {
  url: string;
  method: string;
  resourceType: string;
  headers: Record<string, string>;
  postData?: string;
  timestamp: number;
}

export interface NetworkResponse {
  url: string;
  status: number;
  statusText: string;
  headers: Record<string, string>;
  mimeType: string;
  size: number;
  timing: number;
  fromCache: boolean;
}

export interface APIEndpoint {
  url: string;
  method: string;
  type: "rest" | "graphql" | "websocket" | "grpc" | "sse" | "unknown";
  requestHeaders: Record<string, string>;
  requestBody?: string;
  responseStatus?: number;
  responseMimeType?: string;
  authType?: string;
  parameters: string[];
  category: string;
}

export interface JSRuntimeEvent {
  type: "console" | "error" | "warning" | "promise_rejection" | "eval" | "timer" | "storage" | "fetch_intercept";
  message: string;
  source?: string;
  timestamp: number;
  stackTrace?: string;
}

export interface DynamicResource {
  url: string;
  type: string;
  loadedBy: string;
  size: number;
  timing: number;
}

export interface WebSocketConnection {
  url: string;
  frames: Array<{ direction: "sent" | "received"; data: string; timestamp: number }>;
}

export interface StorageEntry {
  type: "localStorage" | "sessionStorage" | "cookie" | "indexedDB";
  key: string;
  value: string;
  domain: string;
}

export interface RuntimeVariable {
  name: string;
  type: string;
  value: string;
  origin: string;
}

export interface HeadlessBrowserResult {
  success: boolean;
  url: string;
  finalUrl: string;
  pageTitle: string;
  loadTime: number;
  error?: string;

  network: {
    requests: NetworkRequest[];
    responses: NetworkResponse[];
    totalRequests: number;
    totalSize: number;
    byType: Record<string, number>;
    thirdPartyDomains: string[];
    failedRequests: Array<{ url: string; error: string }>;
  };

  apis: {
    discovered: APIEndpoint[];
    totalAPIs: number;
    restEndpoints: number;
    graphqlEndpoints: number;
    websocketEndpoints: number;
    authTokensFound: string[];
    hiddenEndpoints: string[];
  };

  jsRuntime: {
    events: JSRuntimeEvent[];
    consoleMessages: number;
    errors: number;
    warnings: number;
    dynamicScripts: DynamicResource[];
    globalVariables: RuntimeVariable[];
    timers: number;
    storageAccess: StorageEntry[];
    evalCalls: number;
  };

  websockets: WebSocketConnection[];

  performance: {
    domContentLoaded: number;
    fullLoad: number;
    firstPaint: number;
    largestContentfulPaint: number;
    totalJSHeapSize: number;
    usedJSHeapSize: number;
    domNodes: number;
    jsEventListeners: number;
  };

  security: {
    mixedContent: string[];
    insecureRequests: string[];
    corsHeaders: Record<string, string>;
    cspViolations: string[];
    exposedSourceMaps: string[];
    serviceWorkers: string[];
  };

  generatedAt: string;
}

// ═══════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════

function classifyAPI(url: string, method: string, contentType?: string): APIEndpoint["type"] {
  if (/graphql/i.test(url) || contentType?.includes("application/graphql")) return "graphql";
  if (/^wss?:\/\//i.test(url)) return "websocket";
  if (/grpc|grpc-web/i.test(contentType || "")) return "grpc";
  if (/text\/event-stream/i.test(contentType || "")) return "sse";
  if (/\/api\/|\/v[0-9]+\/|\/rest\/|\/auth\/|\/graphql/i.test(url)) return "rest";
  return "unknown";
}

function detectAuthType(headers: Record<string, string>): string | undefined {
  const auth = headers["authorization"] || headers["Authorization"];
  if (!auth) return undefined;
  if (auth.startsWith("Bearer ")) return "Bearer";
  if (auth.startsWith("Basic ")) return "Basic";
  if (auth.startsWith("Token ")) return "Token";
  return "Custom";
}

function extractParams(url: string): string[] {
  try {
    const u = new URL(url);
    return [...u.searchParams.keys()];
  } catch {
    return [];
  }
}

function categorizeEndpoint(url: string): string {
  if (/auth|login|signup|register|oauth|token|session/i.test(url)) return "Authentication";
  if (/user|profile|account/i.test(url)) return "User";
  if (/payment|billing|charge|stripe|checkout/i.test(url)) return "Payment";
  if (/upload|file|media|image|asset/i.test(url)) return "Media";
  if (/search|query|filter/i.test(url)) return "Search";
  if (/analytics|track|event|metric/i.test(url)) return "Analytics";
  if (/admin|dashboard|manage/i.test(url)) return "Admin";
  if (/notification|push|webhook/i.test(url)) return "Notifications";
  if (/chat|message|socket/i.test(url)) return "Messaging";
  if (/firebase|firestore|fcm/i.test(url)) return "Firebase";
  if (/aws|s3|lambda|cognito/i.test(url)) return "AWS";
  return "General";
}

function isAPIRequest(url: string, resourceType: string, contentType?: string): boolean {
  if (resourceType === "xhr" || resourceType === "fetch") return true;
  if (/\/api\/|\/v[0-9]+\/|\/rest\/|\/graphql/i.test(url)) return true;
  if (contentType?.includes("application/json")) return true;
  if (/\.json$/i.test(url) && !/manifest\.json|package\.json/i.test(url)) return true;
  return false;
}

// ═══════════════════════════════════════════════════════════════
// MAIN ANALYZER
// ═══════════════════════════════════════════════════════════════

export async function analyzeWithHeadlessBrowser(targetUrl: string): Promise<HeadlessBrowserResult> {
  if (!targetUrl.startsWith("http")) targetUrl = "https://" + targetUrl;

  const requests: NetworkRequest[] = [];
  const responses: NetworkResponse[] = [];
  const failedRequests: Array<{ url: string; error: string }> = [];
  const jsEvents: JSRuntimeEvent[] = [];
  const dynamicScripts: DynamicResource[] = [];
  const wsConnections: WebSocketConnection[] = [];
  const apiEndpoints: APIEndpoint[] = [];
  const seenAPIs = new Set<string>();
  const mixedContent: string[] = [];
  const insecureRequests: string[] = [];
  const cspViolations: string[] = [];
  const exposedSourceMaps: string[] = [];
  const serviceWorkerUrls: string[] = [];

  let browser: Browser | null = null;
  const startTime = Date.now();

  try {
    browser = await puppeteer.launch({
      headless: true,
      args: [
        "--no-sandbox",
        "--disable-setuid-sandbox",
        "--disable-dev-shm-usage",
        "--disable-gpu",
        "--disable-extensions",
        "--disable-background-networking",
        "--window-size=1920,1080",
      ],
      timeout: 30_000,
    });

    const page = await browser.newPage();

    // Set realistic viewport and user agent
    await page.setViewport({ width: 1920, height: 1080 });
    await page.setUserAgent(
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    );

    // Extra headers for stealth
    await page.setExtraHTTPHeaders({
      "Accept-Language": "en-US,en;q=0.9",
      "sec-ch-ua": '"Chromium";v="131", "Not_A Brand";v="24"',
      "sec-ch-ua-mobile": "?0",
      "sec-ch-ua-platform": '"Windows"',
    });

    // ═══ NETWORK INTERCEPTION ═══
    await page.setRequestInterception(true);

    page.on("request", (req: HTTPRequest) => {
      const url = req.url();
      const method = req.method();
      const resourceType = req.resourceType();
      const headers = req.headers();
      const postData = req.postData();

      requests.push({
        url,
        method,
        resourceType,
        headers,
        postData: postData || undefined,
        timestamp: Date.now(),
      });

      // Track mixed content
      if (targetUrl.startsWith("https") && url.startsWith("http://") && !url.startsWith("http://localhost")) {
        mixedContent.push(url);
      }
      if (url.startsWith("http://") && !url.startsWith("http://localhost")) {
        insecureRequests.push(url);
      }

      // Track source maps
      if (/\.map$/i.test(url) || /sourceMappingURL/i.test(url)) {
        exposedSourceMaps.push(url);
      }

      // Track service workers
      if (resourceType === "other" && /service.?worker/i.test(url)) {
        serviceWorkerUrls.push(url);
      }

      // Discover API endpoints
      const contentType = headers["content-type"] || "";
      if (isAPIRequest(url, resourceType, contentType)) {
        const key = `${method}:${url.split("?")[0]}`;
        if (!seenAPIs.has(key)) {
          seenAPIs.add(key);
          apiEndpoints.push({
            url,
            method,
            type: classifyAPI(url, method, contentType),
            requestHeaders: headers,
            requestBody: postData || undefined,
            authType: detectAuthType(headers),
            parameters: extractParams(url),
            category: categorizeEndpoint(url),
          });
        }
      }

      req.continue();
    });

    page.on("response", async (resp: HTTPResponse) => {
      const url = resp.url();
      const headers: Record<string, string> = {};
      try {
        const raw = resp.headers();
        for (const [k, v] of Object.entries(raw)) headers[k] = v;
      } catch {}

      let size = 0;
      try {
        const buf = await resp.buffer();
        size = buf.length;
      } catch {}

      responses.push({
        url,
        status: resp.status(),
        statusText: resp.statusText(),
        headers,
        mimeType: headers["content-type"] || "",
        size,
        timing: Date.now() - startTime,
        fromCache: resp.fromCache(),
      });

      // Update API endpoint with response data
      const base = url.split("?")[0];
      const ep = apiEndpoints.find(a => a.url.split("?")[0] === base);
      if (ep) {
        ep.responseStatus = resp.status();
        ep.responseMimeType = headers["content-type"];
      }
    });

    page.on("requestfailed", (req: HTTPRequest) => {
      const failure = req.failure();
      failedRequests.push({
        url: req.url(),
        error: failure?.errorText || "Unknown error",
      });
    });

    // ═══ JS RUNTIME ANALYSIS ═══
    page.on("console", (msg: ConsoleMessage) => {
      const type = msg.type();
      let eventType: JSRuntimeEvent["type"] = "console";
      if (type === "error") eventType = "error";
      else if (type === "warn") eventType = "warning";

      jsEvents.push({
        type: eventType,
        message: msg.text().slice(0, 2000),
        source: msg.location()?.url,
        timestamp: Date.now(),
        stackTrace: msg.stackTrace()?.map(f => `${f.url}:${f.lineNumber}`).join("\n") || undefined,
      });
    });

    page.on("pageerror", (error: Error) => {
      jsEvents.push({
        type: "error",
        message: error.message.slice(0, 2000),
        timestamp: Date.now(),
        stackTrace: error.stack?.slice(0, 2000),
      });
    });

    // Inject runtime hooks before page loads
    await page.evaluateOnNewDocument(() => {
      // Track eval calls
      const origEval = window.eval;
      let evalCount = 0;
      (window as any).__hayo_eval_count = 0;
      window.eval = function (...args: any[]) {
        evalCount++;
        (window as any).__hayo_eval_count = evalCount;
        return origEval.apply(this, args);
      };

      // Track setTimeout/setInterval usage
      let timerCount = 0;
      (window as any).__hayo_timer_count = 0;
      const origSetTimeout = window.setTimeout;
      (window as any).setTimeout = function (...args: any[]) {
        timerCount++;
        (window as any).__hayo_timer_count = timerCount;
        return origSetTimeout.apply(window, args as any);
      };
      const origSetInterval = window.setInterval;
      (window as any).setInterval = function (...args: any[]) {
        timerCount++;
        (window as any).__hayo_timer_count = timerCount;
        return origSetInterval.apply(window, args as any);
      };

      // Track storage access
      (window as any).__hayo_storage_access = [] as Array<{
        type: string;
        action: string;
        key: string;
        value: string;
      }>;
      const origLSSetItem = Storage.prototype.setItem;
      Storage.prototype.setItem = function (key: string, value: string) {
        const type = this === localStorage ? "localStorage" : "sessionStorage";
        (window as any).__hayo_storage_access.push({ type, action: "set", key, value: String(value).slice(0, 500) });
        return origLSSetItem.call(this, key, value);
      };
      const origLSGetItem = Storage.prototype.getItem;
      Storage.prototype.getItem = function (key: string) {
        const result = origLSGetItem.call(this, key);
        const type = this === localStorage ? "localStorage" : "sessionStorage";
        (window as any).__hayo_storage_access.push({ type, action: "get", key, value: String(result || "").slice(0, 500) });
        return result;
      };

      // Track dynamically created scripts
      (window as any).__hayo_dynamic_scripts = [] as string[];
      const origCreateElement = document.createElement.bind(document);
      document.createElement = function (tagName: string, options?: ElementCreationOptions) {
        const el = origCreateElement(tagName, options);
        if (tagName.toLowerCase() === "script") {
          const origSetAttribute = el.setAttribute.bind(el);
          el.setAttribute = function (name: string, value: string) {
            if (name === "src") {
              (window as any).__hayo_dynamic_scripts.push(value);
            }
            return origSetAttribute(name, value);
          };
        }
        return el;
      };

      // Track fetch/XHR calls for API discovery
      (window as any).__hayo_fetch_calls = [] as Array<{ url: string; method: string; body?: string }>;
      const origFetch = window.fetch;
      window.fetch = function (...args: any[]) {
        let url = "";
        let method = "GET";
        let body: string | undefined;
        if (typeof args[0] === "string") {
          url = args[0];
        } else if (args[0] instanceof Request) {
          url = args[0].url;
          method = args[0].method;
        }
        if (args[1]) {
          method = args[1].method || method;
          body = typeof args[1].body === "string" ? args[1].body.slice(0, 2000) : undefined;
        }
        (window as any).__hayo_fetch_calls.push({ url, method, body });
        return origFetch.apply(this, args);
      };

      const origXHROpen = XMLHttpRequest.prototype.open;
      XMLHttpRequest.prototype.open = function (...args: any[]) {
        (window as any).__hayo_fetch_calls.push({
          url: args[1],
          method: args[0] || "GET",
        });
        return origXHROpen.apply(this, args);
      };
    });

    // ═══ NAVIGATE AND WAIT ═══
    const navResponse = await page.goto(targetUrl, {
      waitUntil: "networkidle2",
      timeout: 60_000,
    });

    // Wait extra time for dynamic JS to execute
    await new Promise(r => setTimeout(r, 3_000));

    // Scroll page to trigger lazy loading
    await page.evaluate(async () => {
      const distance = 300;
      const delay = 100;
      const maxScroll = Math.min(document.body.scrollHeight, 10000);
      for (let i = 0; i < maxScroll; i += distance) {
        window.scrollBy(0, distance);
        await new Promise(r => setTimeout(r, delay));
      }
      window.scrollTo(0, 0);
    });

    // Wait for lazy-loaded content
    await new Promise(r => setTimeout(r, 2_000));

    // ═══ COLLECT JS RUNTIME DATA ═══
    const runtimeData = await page.evaluate(() => {
      // Globals scan
      const globals: Array<{ name: string; type: string; value: string; origin: string }> = [];
      const defaultGlobals = new Set([
        "window", "self", "document", "name", "location", "customElements",
        "history", "navigation", "locationbar", "menubar", "personalbar",
        "scrollbars", "statusbar", "toolbar", "status", "closed", "frames",
        "length", "top", "opener", "parent", "frameElement", "navigator",
        "origin", "external", "screen", "visualViewport", "innerWidth",
        "innerHeight", "outerWidth", "outerHeight", "devicePixelRatio",
        "clientInformation", "screenX", "screenY", "screenLeft", "screenTop",
        "styleMedia", "onsearch", "isSecureContext", "crossOriginIsolated",
        "performance", "caches", "cookieStore", "indexedDB", "crypto",
        "sessionStorage", "localStorage",
      ]);
      for (const key of Object.keys(window)) {
        if (defaultGlobals.has(key) || key.startsWith("__hayo_") || key.startsWith("on")) continue;
        try {
          const val = (window as any)[key];
          const type = typeof val;
          let value = "";
          if (type === "string") value = val.slice(0, 500);
          else if (type === "number" || type === "boolean") value = String(val);
          else if (type === "object" && val !== null) {
            try { value = JSON.stringify(val).slice(0, 500); } catch { value = "[Object]"; }
          }
          else if (type === "function") value = "[Function]";
          else value = String(val).slice(0, 200);
          globals.push({ name: key, type, value, origin: "window" });
        } catch {}
      }

      // Collect storage
      const storage: Array<{ type: string; key: string; value: string; domain: string }> = [];
      try {
        for (let i = 0; i < localStorage.length; i++) {
          const key = localStorage.key(i) || "";
          storage.push({ type: "localStorage", key, value: (localStorage.getItem(key) || "").slice(0, 1000), domain: location.hostname });
        }
      } catch {}
      try {
        for (let i = 0; i < sessionStorage.length; i++) {
          const key = sessionStorage.key(i) || "";
          storage.push({ type: "sessionStorage", key, value: (sessionStorage.getItem(key) || "").slice(0, 1000), domain: location.hostname });
        }
      } catch {}

      // Cookies
      try {
        const cookies = document.cookie.split(";").filter(Boolean);
        for (const c of cookies) {
          const [key, ...rest] = c.trim().split("=");
          storage.push({ type: "cookie", key: key.trim(), value: rest.join("=").slice(0, 1000), domain: location.hostname });
        }
      } catch {}

      // DOM stats
      const domNodes = document.querySelectorAll("*").length;

      // Event listeners count
      let eventListenerCount = 0;
      try {
        const allElements = document.querySelectorAll("*");
        allElements.forEach((el) => {
          const events = (window as any).getEventListeners?.(el);
          if (events) {
            for (const key in events) eventListenerCount += events[key].length;
          }
        });
      } catch {
        // getEventListeners is a DevTools-only API
        eventListenerCount = -1;
      }

      return {
        title: document.title,
        url: location.href,
        evalCount: (window as any).__hayo_eval_count || 0,
        timerCount: (window as any).__hayo_timer_count || 0,
        dynamicScripts: ((window as any).__hayo_dynamic_scripts || []) as string[],
        fetchCalls: ((window as any).__hayo_fetch_calls || []) as Array<{ url: string; method: string; body?: string }>,
        storageAccess: ((window as any).__hayo_storage_access || []) as Array<{ type: string; action: string; key: string; value: string }>,
        globals: globals.slice(0, 200),
        storage,
        domNodes,
        eventListenerCount,
      };
    });

    // Track JS-initiated fetch calls as API endpoints
    for (const call of runtimeData.fetchCalls) {
      if (!call.url || call.url.startsWith("data:")) continue;
      let absoluteUrl = call.url;
      try {
        absoluteUrl = new URL(call.url, targetUrl).href;
      } catch {}
      const key = `${call.method}:${absoluteUrl.split("?")[0]}`;
      if (!seenAPIs.has(key)) {
        seenAPIs.add(key);
        apiEndpoints.push({
          url: absoluteUrl,
          method: call.method,
          type: classifyAPI(absoluteUrl, call.method),
          requestHeaders: {},
          requestBody: call.body,
          authType: undefined,
          parameters: extractParams(absoluteUrl),
          category: categorizeEndpoint(absoluteUrl),
        });
      }
    }

    // Track dynamic scripts
    for (const scriptUrl of runtimeData.dynamicScripts) {
      let absoluteUrl = scriptUrl;
      try { absoluteUrl = new URL(scriptUrl, targetUrl).href; } catch {}
      dynamicScripts.push({
        url: absoluteUrl,
        type: "script",
        loadedBy: "document.createElement",
        size: 0,
        timing: 0,
      });
    }

    // ═══ PERFORMANCE METRICS ═══
    const performanceMetrics = await page.evaluate(() => {
      const perf = performance.getEntriesByType("navigation")[0] as PerformanceNavigationTiming | undefined;
      const paint = performance.getEntriesByType("paint");
      const fpEntry = paint.find(p => p.name === "first-paint");
      const lcpEntries = performance.getEntriesByType("largest-contentful-paint");
      const lcpEntry = lcpEntries[lcpEntries.length - 1];
      return {
        domContentLoaded: perf?.domContentLoadedEventEnd || 0,
        fullLoad: perf?.loadEventEnd || 0,
        firstPaint: fpEntry?.startTime || 0,
        largestContentfulPaint: lcpEntry?.startTime || 0,
      };
    });

    const memoryMetrics = await page.metrics();

    // CORS headers from main response
    const corsHeaders: Record<string, string> = {};
    if (navResponse) {
      const mainHeaders = navResponse.headers();
      for (const key of ["access-control-allow-origin", "access-control-allow-methods", "access-control-allow-headers", "access-control-allow-credentials", "access-control-expose-headers"]) {
        if (mainHeaders[key]) corsHeaders[key] = mainHeaders[key];
      }
    }

    // ═══ HIDDEN ENDPOINT DISCOVERY ═══
    // Look for API endpoints mentioned in JS but not yet called
    const allPageContent = await page.content();
    const hiddenEndpoints: string[] = [];
    const endpointPatterns = [
      /["'`](\/api\/[a-zA-Z0-9\-_/]+)["'`]/g,
      /["'`](\/v[0-9]+\/[a-zA-Z0-9\-_/]+)["'`]/g,
      /["'`](\/graphql[a-zA-Z0-9\-_/]*)["'`]/g,
      /["'`](\/rest\/[a-zA-Z0-9\-_/]+)["'`]/g,
      /["'`](\/auth\/[a-zA-Z0-9\-_/]+)["'`]/g,
      /["'`](\/admin\/[a-zA-Z0-9\-_/]+)["'`]/g,
      /["'`](\/internal\/[a-zA-Z0-9\-_/]+)["'`]/g,
      /["'`](\/webhook[s]?\/[a-zA-Z0-9\-_/]+)["'`]/g,
      /["'`](\/socket\.io[a-zA-Z0-9\-_/]*)["'`]/g,
      /fetch\(["'`](\/[a-zA-Z0-9\-_/]+)["'`]/g,
      /\.(?:get|post|put|patch|delete)\(["'`](\/[a-zA-Z0-9\-_/]+)["'`]/g,
      /axios\.[a-z]+\(["'`](\/[a-zA-Z0-9\-_/]+)["'`]/g,
    ];

    const seenHidden = new Set<string>();
    for (const pattern of endpointPatterns) {
      pattern.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = pattern.exec(allPageContent)) !== null) {
        const ep = m[1];
        if (ep && ep.length > 2 && !seenHidden.has(ep)) {
          seenHidden.add(ep);
          // Only add if not already discovered via network
          const fullUrl = new URL(ep, targetUrl).href;
          const alreadyFound = apiEndpoints.some(a => a.url.includes(ep));
          if (!alreadyFound) {
            hiddenEndpoints.push(ep);
          }
        }
      }
    }

    // ═══ DETECT AUTH TOKENS IN STORAGE ═══
    const authTokensFound: string[] = [];
    const authPatterns = /token|auth|session|jwt|bearer|api.?key|access.?key|secret/i;
    for (const entry of runtimeData.storage) {
      if (authPatterns.test(entry.key) || authPatterns.test(entry.value.slice(0, 50))) {
        authTokensFound.push(`${entry.type}:${entry.key}`);
      }
    }
    for (const entry of runtimeData.storageAccess) {
      if (authPatterns.test(entry.key)) {
        authTokensFound.push(`${entry.type}:${entry.key}`);
      }
    }

    // ═══ AGGREGATE ═══
    const totalSize = responses.reduce((s, r) => s + r.size, 0);
    const byType: Record<string, number> = {};
    for (const req of requests) {
      byType[req.resourceType] = (byType[req.resourceType] || 0) + 1;
    }

    const thirdPartyDomains = new Set<string>();
    const mainDomain = new URL(targetUrl).hostname;
    for (const req of requests) {
      try {
        const reqDomain = new URL(req.url).hostname;
        if (reqDomain !== mainDomain && !reqDomain.endsWith("." + mainDomain)) {
          thirdPartyDomains.add(reqDomain);
        }
      } catch {}
    }

    const loadTime = Date.now() - startTime;

    return {
      success: true,
      url: targetUrl,
      finalUrl: runtimeData.url,
      pageTitle: runtimeData.title,
      loadTime,

      network: {
        requests: requests.slice(0, 500),
        responses: responses.slice(0, 500),
        totalRequests: requests.length,
        totalSize,
        byType,
        thirdPartyDomains: [...thirdPartyDomains],
        failedRequests: failedRequests.slice(0, 50),
      },

      apis: {
        discovered: apiEndpoints.slice(0, 200),
        totalAPIs: apiEndpoints.length,
        restEndpoints: apiEndpoints.filter(a => a.type === "rest").length,
        graphqlEndpoints: apiEndpoints.filter(a => a.type === "graphql").length,
        websocketEndpoints: apiEndpoints.filter(a => a.type === "websocket").length,
        authTokensFound: [...new Set(authTokensFound)],
        hiddenEndpoints: hiddenEndpoints.slice(0, 100),
      },

      jsRuntime: {
        events: jsEvents.slice(0, 200),
        consoleMessages: jsEvents.filter(e => e.type === "console").length,
        errors: jsEvents.filter(e => e.type === "error").length,
        warnings: jsEvents.filter(e => e.type === "warning").length,
        dynamicScripts,
        globalVariables: runtimeData.globals.slice(0, 100),
        timers: runtimeData.timerCount,
        storageAccess: runtimeData.storage.map(s => ({
          type: s.type as StorageEntry["type"],
          key: s.key,
          value: s.value,
          domain: s.domain,
        })),
        evalCalls: runtimeData.evalCount,
      },

      websockets: wsConnections,

      performance: {
        domContentLoaded: Math.round(performanceMetrics.domContentLoaded),
        fullLoad: Math.round(performanceMetrics.fullLoad),
        firstPaint: Math.round(performanceMetrics.firstPaint),
        largestContentfulPaint: Math.round(performanceMetrics.largestContentfulPaint),
        totalJSHeapSize: Math.round((memoryMetrics.JSHeapTotalSize || 0) / 1024),
        usedJSHeapSize: Math.round((memoryMetrics.JSHeapUsedSize || 0) / 1024),
        domNodes: runtimeData.domNodes,
        jsEventListeners: runtimeData.eventListenerCount,
      },

      security: {
        mixedContent: [...new Set(mixedContent)].slice(0, 50),
        insecureRequests: [...new Set(insecureRequests)].slice(0, 50),
        corsHeaders,
        cspViolations,
        exposedSourceMaps: [...new Set(exposedSourceMaps)].slice(0, 20),
        serviceWorkers: serviceWorkerUrls,
      },

      generatedAt: new Date().toISOString(),
    };
  } catch (error: any) {
    return {
      success: false,
      url: targetUrl,
      finalUrl: targetUrl,
      pageTitle: "",
      loadTime: Date.now() - startTime,
      error: error.message,
      network: { requests: [], responses: [], totalRequests: 0, totalSize: 0, byType: {}, thirdPartyDomains: [], failedRequests: [] },
      apis: { discovered: [], totalAPIs: 0, restEndpoints: 0, graphqlEndpoints: 0, websocketEndpoints: 0, authTokensFound: [], hiddenEndpoints: [] },
      jsRuntime: { events: [], consoleMessages: 0, errors: 0, warnings: 0, dynamicScripts: [], globalVariables: [], timers: 0, storageAccess: [], evalCalls: 0 },
      websockets: [],
      performance: { domContentLoaded: 0, fullLoad: 0, firstPaint: 0, largestContentfulPaint: 0, totalJSHeapSize: 0, usedJSHeapSize: 0, domNodes: 0, jsEventListeners: 0 },
      security: { mixedContent: [], insecureRequests: [], corsHeaders: {}, cspViolations: [], exposedSourceMaps: [], serviceWorkers: [] },
      generatedAt: new Date().toISOString(),
    };
  } finally {
    if (browser) {
      try { await browser.close(); } catch {}
    }
  }
}

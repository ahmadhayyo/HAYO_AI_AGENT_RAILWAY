import fs from "fs";
import path from "path";
import { spawnSync } from "child_process";
import { createAnthropicClient } from "../llm";

const PROJECT_ROOT = path.resolve(process.cwd(), "../..");
const HAYO_FRONTEND = path.join(PROJECT_ROOT, "artifacts/hayo-ai/src");
const HAYO_BACKEND = path.join(PROJECT_ROOT, "artifacts/api-server/src/hayo");

const IGNORED_DIRS = new Set([
  "node_modules", ".git", "dist", "build", ".next", ".cache",
  ".local", ".config", "coverage", "__pycache__", ".turbo",
]);
const ALLOWED_EXTENSIONS = new Set([
  ".ts", ".tsx", ".js", ".jsx", ".css", ".json", ".html", ".md",
]);

export interface FileOp {
  action: "create" | "edit" | "delete" | "read";
  filePath: string;
  content?: string;
  description: string;
}

export interface AgentResponse {
  message: string;
  operations: FileOp[];
  executedOps: { action: string; filePath: string; success: boolean; error?: string }[];
}

function getProjectTree(dir: string, prefix = "", depth = 0, maxDepth = 4): string {
  if (depth > maxDepth || !fs.existsSync(dir)) return "";
  let result = "";
  try {
    const entries = fs.readdirSync(dir, { withFileTypes: true })
      .filter(e => !IGNORED_DIRS.has(e.name) && !e.name.startsWith("."))
      .sort((a, b) => {
        if (a.isDirectory() && !b.isDirectory()) return -1;
        if (!a.isDirectory() && b.isDirectory()) return 1;
        return a.name.localeCompare(b.name);
      });

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        result += `${prefix}📁 ${entry.name}/\n`;
        result += getProjectTree(fullPath, prefix + "  ", depth + 1, maxDepth);
      } else if (ALLOWED_EXTENSIONS.has(path.extname(entry.name))) {
        const size = fs.statSync(fullPath).size;
        result += `${prefix}📄 ${entry.name} (${(size / 1024).toFixed(1)}KB)\n`;
      }
    }
  } catch {}
  return result;
}

function readFilesSafe(filePaths: string[]): string {
  let result = "";
  for (const fp of filePaths) {
    const abs = resolvePath(fp);
    if (!abs) { result += `\n--- ${fp} (خارج المشروع) ---\n`; continue; }
    if (!fs.existsSync(abs)) { result += `\n--- ${fp} (غير موجود) ---\n`; continue; }
    try {
      const stat = fs.statSync(abs);
      if (stat.isDirectory()) {
        const entries = fs.readdirSync(abs, { withFileTypes: true });
        const listing = entries
          .filter(e => !e.name.startsWith(".") && e.name !== "node_modules")
          .map(e => `${e.isDirectory() ? "📁" : "📄"} ${e.name}`)
          .join("\n");
        result += `\n--- ${fp} (مجلد) ---\n${listing}\n`;
        continue;
      }
      const content = fs.readFileSync(abs, "utf-8");
      const lines = content.split("\n").length;
      if (lines > 500) {
        result += `\n--- ${fp} (${lines} سطر — أول 300 سطر) ---\n${content.split("\n").slice(0, 300).join("\n")}\n...\n`;
      } else {
        result += `\n--- ${fp} ---\n${content}\n`;
      }
    } catch (e: any) {
      result += `\n--- ${fp} (خطأ: ${e.message}) ---\n`;
    }
  }
  return result;
}

function resolvePath(fp: string): string | null {
  if (fp.startsWith("/")) return null;
  let joined: string;
  if (fp.startsWith("artifacts/") || fp.startsWith("packages/")) {
    joined = path.join(PROJECT_ROOT, fp);
  } else if (fp.startsWith("src/")) {
    joined = path.join(HAYO_FRONTEND, fp.replace(/^src\//, ""));
  } else {
    joined = path.join(PROJECT_ROOT, fp);
  }
  const resolved = path.resolve(joined);
  const rel = path.relative(PROJECT_ROOT, resolved);
  if (rel.startsWith("..") || path.isAbsolute(rel)) return null;
  return resolved;
}

function executeOps(ops: FileOp[]): AgentResponse["executedOps"] {
  const results: AgentResponse["executedOps"] = [];
  for (const op of ops) {
    const abs = resolvePath(op.filePath);
    if (!abs) {
      results.push({ action: op.action, filePath: op.filePath, success: false, error: "مسار خارج المشروع" });
      continue;
    }
    try {
      switch (op.action) {
        case "create":
        case "edit": {
          const dir = path.dirname(abs);
          if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
          fs.writeFileSync(abs, op.content || "", "utf-8");
          results.push({ action: op.action, filePath: op.filePath, success: true });
          break;
        }
        case "delete": {
          if (fs.existsSync(abs)) {
            fs.unlinkSync(abs);
            results.push({ action: op.action, filePath: op.filePath, success: true });
          } else {
            results.push({ action: op.action, filePath: op.filePath, success: false, error: "الملف غير موجود" });
          }
          break;
        }
        case "read": {
          results.push({ action: op.action, filePath: op.filePath, success: true });
          break;
        }
      }
    } catch (e: any) {
      results.push({ action: op.action, filePath: op.filePath, success: false, error: e.message });
    }
  }
  return results;
}

function getRelevantContext(command: string): string {
  const contexts: string[] = [];

  if (/صفح|page|route/i.test(command)) {
    const appTsx = path.join(HAYO_FRONTEND, "App.tsx");
    if (fs.existsSync(appTsx)) contexts.push(readFilesSafe(["artifacts/hayo-ai/src/App.tsx"]));
    const pagesDir = path.join(HAYO_FRONTEND, "pages");
    if (fs.existsSync(pagesDir)) {
      const pages = fs.readdirSync(pagesDir).filter(f => f.endsWith(".tsx")).map(f => `📄 ${f}`);
      contexts.push(`\n--- الصفحات الموجودة ---\n${pages.join("\n")}`);
    }
  }

  if (/router|trpc|api|endpoint/i.test(command)) {
    contexts.push(readFilesSafe(["artifacts/api-server/src/hayo/router.ts"]));
  }

  if (/component|مكون|ui/i.test(command)) {
    const compDir = path.join(HAYO_FRONTEND, "components");
    if (fs.existsSync(compDir)) {
      const comps = fs.readdirSync(compDir, { recursive: true })
        .filter((f: any) => String(f).endsWith(".tsx"))
        .map((f: any) => `📄 ${f}`);
      contexts.push(`\n--- المكونات الموجودة ---\n${comps.join("\n")}`);
    }
  }

  if (/nav|sidebar|قائمة|dashboard/i.test(command)) {
    contexts.push(readFilesSafe([
      "artifacts/hayo-ai/src/components/DashboardLayout.tsx",
      "artifacts/hayo-ai/src/pages/Dashboard.tsx",
    ]));
  }

  return contexts.join("\n");
}

export async function executeAgentCommand(
  command: string,
  conversationHistory: { role: "user" | "assistant"; content: string }[],
  autoExecute: boolean = false,
): Promise<AgentResponse> {
  const anthropic = createAnthropicClient();

  const frontendTree = getProjectTree(HAYO_FRONTEND, "", 0, 3);
  const backendTree = getProjectTree(HAYO_BACKEND, "", 0, 3);
  const relevantContext = getRelevantContext(command);

  const systemPrompt = `أنت AI Agent تنفيذي داخل منصة HAYO AI. مهمتك تنفيذ أوامر المطور داخل المشروع مباشرة.

## بنية المشروع:
- Frontend: React + Vite + TypeScript (artifacts/hayo-ai/src/)
- Backend: Express + tRPC (artifacts/api-server/src/hayo/)
- التصميم: Tailwind CSS + shadcn/ui
- الـ Routing: wouter
- الحالة: tRPC + React Query
- اللغة الأساسية: العربية (RTL)

## شجرة Frontend:
${frontendTree}

## شجرة Backend:
${backendTree}

${relevantContext ? `## سياق إضافي:\n${relevantContext}` : ""}

## قواعد التنفيذ:
1. أنت تنفذ الأوامر مباشرة — لا تسأل أسئلة إلا إذا الأمر غامض جداً
2. عند إنشاء صفحة: أنشئ ملف .tsx + أضفها للـ router في App.tsx + أضفها للقائمة الجانبية
3. عند تعديل ملف: اقرأه أولاً ثم عدّل فقط ما يلزم
4. التزم بنمط الكود الموجود في المشروع
5. كل الواجهات بالعربية مع دعم RTL
6. استخدم Tailwind CSS + shadcn/ui components
7. استخدم lucide-react للأيقونات

## صيغة الرد:
أجب بـ JSON فقط بهذا الشكل:
{
  "message": "شرح مختصر لما سيتم تنفيذه",
  "operations": [
    {
      "action": "create" | "edit" | "delete" | "read",
      "filePath": "المسار النسبي من جذر المشروع",
      "content": "المحتوى الكامل للملف (فقط لـ create و edit)",
      "description": "وصف العملية"
    }
  ]
}

ملاحظات مهمة:
- لـ "edit": ضع المحتوى الكامل الجديد للملف بعد التعديل (وليس فقط التغيير)
- لـ "read": لا تحتاج content — سأقرأ الملف وأعرضه
- المسارات تبدأ من: artifacts/hayo-ai/src/ أو artifacts/api-server/src/hayo/
- أجب بـ JSON فقط — بدون markdown أو backticks أو شرح خارجي`;

  const messages = [
    ...conversationHistory.slice(-10),
    { role: "user" as const, content: command },
  ];

  const msg = await anthropic.messages.create({
    model: "claude-sonnet-4-6",
    max_tokens: 16384,
    system: systemPrompt,
    messages,
  });

  const rawText = (msg.content[0] as any).text || "";

  let parsed: { message: string; operations: FileOp[] };
  try {
    const jsonMatch = rawText.match(/\{[\s\S]*\}/);
    if (!jsonMatch) throw new Error("لم يتم العثور على JSON في الرد");
    parsed = JSON.parse(jsonMatch[0]);
  } catch {
    return {
      message: rawText,
      operations: [],
      executedOps: [],
    };
  }

  const ops = (parsed.operations || []).map(op => ({
    ...op,
    filePath: op.filePath.replace(/^\/+/, ""),
  }));

  const readOps = ops.filter(op => op.action === "read");
  const writeOps = ops.filter(op => op.action !== "read");
  let extraContent = "";

  if (readOps.length > 0) {
    const readPaths = readOps.map(op => op.filePath);
    extraContent = readFilesSafe(readPaths);
  }

  const readResults = readOps.map(op => ({ action: op.action, filePath: op.filePath, success: true }));
  let writeResults: AgentResponse["executedOps"] = [];

  if (autoExecute && writeOps.length > 0) {
    writeResults = executeOps(writeOps);
  }

  return {
    message: parsed.message + (extraContent ? "\n\n" + extraContent : ""),
    operations: ops,
    executedOps: [...readResults, ...writeResults],
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// ★ UPGRADE 1: Bash execution — proper PATH, env, spawnSync, stderr capture
// ─────────────────────────────────────────────────────────────────────────────

const DENIED_BASH_PATTERNS = [
  "rm -rf /", "rm -rf ~", "mkfs", ":(){:|:&};:", "shutdown", "reboot",
  "halt", "passwd", "sudo rm", "sudo dd",
];

/** Build a sane shell environment that includes pnpm/node/local binaries. */
function buildShellEnv(): NodeJS.ProcessEnv {
  const localBin = [
    path.join(PROJECT_ROOT, "node_modules/.bin"),
    path.join(PROJECT_ROOT, "artifacts/api-server/node_modules/.bin"),
    path.join(PROJECT_ROOT, "artifacts/hayo-ai/node_modules/.bin"),
  ].join(process.platform === "win32" ? ";" : ":");

  return {
    ...process.env,
    PATH: `${localBin}${process.platform === "win32" ? ";" : ":"}${process.env.PATH ?? ""}`,
    NODE_ENV: "development",
    FORCE_COLOR: "0",
  };
}

export function executeBashInProject(
  command: string,
  timeoutMs: number = 60_000,
): { stdout: string; stderr: string; exitCode: number } {
  const cmdLower = command.toLowerCase().trim();
  if (DENIED_BASH_PATTERNS.some(p => cmdLower.includes(p))) {
    return { stdout: "", stderr: `[BLOCKED] Command denied by safety policy: ${command}`, exitCode: 1 };
  }

  const shell = process.platform === "win32" ? "cmd.exe" : "/bin/sh";
  const shellFlag = process.platform === "win32" ? "/c" : "-c";

  const result = spawnSync(shell, [shellFlag, command], {
    cwd: PROJECT_ROOT,
    timeout: timeoutMs,
    encoding: "utf-8",
    env: buildShellEnv(),
    maxBuffer: 10 * 1024 * 1024, // 10 MB
  });

  const stdout = (result.stdout || "").trim().slice(0, 8000);
  const stderr = (result.stderr || "").trim().slice(0, 4000);
  const exitCode = result.status ?? (result.error ? 1 : 0);

  // spawnSync sets error on timeout or ENOENT
  if (result.error) {
    const errMsg = result.error.message || String(result.error);
    return {
      stdout,
      stderr: errMsg.includes("ETIMEDOUT") || errMsg.includes("timeout")
        ? `[TIMEOUT] Command exceeded ${timeoutMs}ms: ${command}`
        : `[ERROR] ${errMsg}`,
      exitCode: 1,
    };
  }

  return { stdout, stderr, exitCode };
}

// ─────────────────────────────────────────────────────────────────────────────
// Streaming agent — multi-turn with self-healing loop
// ─────────────────────────────────────────────────────────────────────────────

export interface AgentStreamEvent {
  type: "plan" | "thinking" | "tool_call" | "tool_result" | "terminal" | "error" | "done";
  node: "planner" | "coder" | "executor" | "reviewer" | "system";
  content: string;
  step?: number;
  totalSteps?: number;
}

// ─────────────────────────────────────────────────────────────────────────────
// ★ UPGRADE 2: tRPC router snapshot — gives agent real API knowledge
// ─────────────────────────────────────────────────────────────────────────────

function getTrpcSnapshot(): string {
  const routerPath = path.join(HAYO_BACKEND, "router.ts");
  if (!fs.existsSync(routerPath)) return "(router.ts not found)";
  try {
    const content = fs.readFileSync(routerPath, "utf-8");
    // Extract only procedure names & types (skip full implementations)
    const lines = content.split("\n");
    const snapshot: string[] = [];
    for (const line of lines) {
      // Capture procedure declarations
      if (/^\s+\w+:\s+(admin|public|protected)Procedure/.test(line) ||
          /^\s+\w+:\s+\w+Router,?$/.test(line) ||
          /export const \w+Router/.test(line)) {
        snapshot.push(line.trimEnd());
      }
    }
    return snapshot.slice(0, 120).join("\n") || "(no procedures found)";
  } catch {
    return "(failed to read router)";
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// ★ UPGRADE 3: Context compression — prevent context window overflow
// ─────────────────────────────────────────────────────────────────────────────

const COMPRESS_THRESHOLD = 16; // compress when messages exceed this count
const KEEP_RECENT = 6;         // always keep latest N messages verbatim

async function compressContext(
  messages: { role: "user" | "assistant"; content: string }[],
  anthropic: ReturnType<typeof createAnthropicClient>,
): Promise<{ role: "user" | "assistant"; content: string }[]> {
  if (messages.length <= COMPRESS_THRESHOLD) return messages;

  const toSummarise = messages.slice(0, messages.length - KEEP_RECENT);
  const recent      = messages.slice(messages.length - KEEP_RECENT);

  const summaryMsg = await anthropic.messages.create({
    model: "claude-haiku-4-5-20251001",   // cheap model for summarisation
    max_tokens: 1024,
    system: "Summarise the completed work steps below in ≤300 words. Focus on: which files were written/edited, which commands ran and their outcomes, and any errors encountered. Be concise.",
    messages: [{ role: "user", content: toSummarise.map(m => `[${m.role}]: ${m.content}`).join("\n\n") }],
  });

  const summary = (summaryMsg.content[0] as any).text || "(summary unavailable)";

  return [
    { role: "user",      content: `[COMPRESSED HISTORY — ${toSummarise.length} messages summarised]\n${summary}` },
    { role: "assistant", content: "Understood. Continuing from the summary." },
    ...recent,
  ];
}

// ─────────────────────────────────────────────────────────────────────────────
// ★ UPGRADE 4: Deterministic reviewer — exit-code + pattern based, not LLM
// ─────────────────────────────────────────────────────────────────────────────

interface ReviewVerdict {
  status: "success" | "error" | "continue";
  reason?: string;
}

function deterministicReview(
  agentMessages: { role: string; content: string }[],
  errorCount: number,
  maxErrors: number,
): ReviewVerdict {
  // Gather all bash results from the conversation
  const bashResults = agentMessages
    .filter(m => m.role === "user" && m.content.startsWith("[bash result]"))
    .map(m => m.content);

  if (bashResults.length === 0) return { status: "continue" };

  const lastBash = bashResults[bashResults.length - 1];

  // Hard failure patterns in terminal output
  const HARD_FAIL = [
    /EXIT CODE: [^0\n]/,
    /error TS\d+:/i,
    /SyntaxError:/,
    /Cannot find module/,
    /ENOENT:/,
    /Build failed/i,
    /compilation failed/i,
    /failed to compile/i,
  ];

  // Success patterns
  const SUCCESS = [
    /EXIT CODE: 0/,
    /Build complete/i,
    /Successfully compiled/i,
    /Finished in/i,
    /✓/,
  ];

  const hasHardFail = HARD_FAIL.some(p => p.test(lastBash));
  const hasSuccess  = SUCCESS.some(p => p.test(lastBash));

  if (hasHardFail) {
    if (errorCount >= maxErrors) {
      return { status: "error", reason: `تجاوز الحد الأقصى للمحاولات (${maxErrors}). آخر خطأ:\n${lastBash.slice(0, 600)}` };
    }
    return { status: "error", reason: lastBash.slice(0, 600) };
  }

  if (hasSuccess) return { status: "success" };

  return { status: "continue" };
}

// ─────────────────────────────────────────────────────────────────────────────
// ★ UPGRADE 5: File diff tracker — shows exactly what changed
// ─────────────────────────────────────────────────────────────────────────────

interface FileDiff {
  path: string;
  action: "created" | "modified" | "deleted";
  sizeBytes: number;
}

function trackFileChanges(
  snapshots: Map<string, number>,
  agentMessages: { role: string; content: string }[],
): FileDiff[] {
  const written = agentMessages
    .filter(m => m.role === "user" && m.content.startsWith("[OK] كُتب الملف:"))
    .map(m => {
      const match = m.content.match(/\[OK\] كُتب الملف: (.+?) \(/);
      return match?.[1] ?? null;
    })
    .filter(Boolean) as string[];

  const diffs: FileDiff[] = [];
  for (const fp of [...new Set(written)]) {
    const abs = resolvePath(fp);
    if (!abs) continue;
    const existed = snapshots.has(fp);
    const currentSize = fs.existsSync(abs) ? fs.statSync(abs).size : 0;
    diffs.push({
      path: fp,
      action: existed ? "modified" : "created",
      sizeBytes: currentSize,
    });
  }
  return diffs;
}

// system prompt is built dynamically inside executeAgentCommandStreaming
// (includes live tRPC snapshot, project tree, package.json scripts)

export async function* executeAgentCommandStreaming(
  command: string,
  conversationHistory: { role: "user" | "assistant"; content: string }[],
): AsyncGenerator<AgentStreamEvent> {
  const anthropic = createAnthropicClient();

  // ── ★ UPGRADE 4: Build rich system prompt with live project knowledge ──────
  const frontendTree  = getProjectTree(HAYO_FRONTEND, "", 0, 3);
  const backendTree   = getProjectTree(HAYO_BACKEND,  "", 0, 3);
  const trpcSnapshot  = getTrpcSnapshot();

  // Read package.json scripts so agent knows build/dev commands
  let pkgScripts = "(unavailable)";
  try {
    const apiPkg = JSON.parse(fs.readFileSync(path.join(PROJECT_ROOT, "artifacts/api-server/package.json"), "utf-8"));
    const fePkg  = JSON.parse(fs.readFileSync(path.join(PROJECT_ROOT, "artifacts/hayo-ai/package.json"),    "utf-8"));
    pkgScripts = [
      "api-server scripts: " + JSON.stringify(apiPkg.scripts ?? {}),
      "hayo-ai scripts:    " + JSON.stringify(fePkg.scripts  ?? {}),
    ].join("\n");
  } catch {}

  const SYSTEM = `You are an autonomous AI software engineering agent inside the HAYO platform.
Stack: TypeScript monorepo — React+Vite frontend, Express+tRPC backend, Drizzle ORM, PostgreSQL.
UI: Tailwind CSS + shadcn/ui + Lucide icons. Routing: wouter. Language: Arabic (RTL).

## Available actions — respond with ONE JSON object per turn:

Read a file:          {"action":"read","path":"<rel path>"}
Write/create a file:  {"action":"write","path":"<rel path>","content":"<FULL content — no placeholders>"}
Run a shell command:  {"action":"bash","command":"<cmd>","timeout":60000}
List a directory:     {"action":"list","path":"<rel path>"}
Search in codebase:   {"action":"search","pattern":"<text>","path":"artifacts/"}
TypeScript check:     {"action":"bash","command":"npx tsc --noEmit -p artifacts/api-server/tsconfig.json 2>&1 | head -30"}
Done signal:          {"status":"done","summary":"<what was done>","files":["list of modified files"]}
Error sig
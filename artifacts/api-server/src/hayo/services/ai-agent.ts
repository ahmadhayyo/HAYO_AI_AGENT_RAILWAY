import fs from "fs";
import path from "path";
import { execSync } from "child_process";
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
// Bash execution (used by the agentic streaming endpoint)
// ─────────────────────────────────────────────────────────────────────────────

const DENIED_BASH_PATTERNS = [
  "rm -rf /", "rm -rf ~", "mkfs", ":(){:|:&};:", "shutdown", "reboot",
  "halt", "passwd", "sudo rm", "sudo dd",
];

export function executeBashInProject(
  command: string,
  timeoutMs: number = 60_000,
): { stdout: string; stderr: string; exitCode: number } {
  const cmdLower = command.toLowerCase().trim();
  if (DENIED_BASH_PATTERNS.some(p => cmdLower.includes(p))) {
    return { stdout: "", stderr: `[BLOCKED] Command denied by safety policy: ${command}`, exitCode: 1 };
  }
  try {
    const stdout = execSync(command, {
      cwd: PROJECT_ROOT,
      timeout: timeoutMs,
      encoding: "utf-8",
      stdio: ["pipe", "pipe", "pipe"],
    }) as unknown as string;
    return { stdout: String(stdout).slice(0, 8000), stderr: "", exitCode: 0 };
  } catch (e: any) {
    return {
      stdout: String(e.stdout || "").slice(0, 4000),
      stderr: String(e.stderr || e.message || "").slice(0, 4000),
      exitCode: e.status ?? 1,
    };
  }
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

const STREAMING_SYSTEM = `You are an autonomous AI software engineering agent inside the HAYO platform.
You work on a TypeScript monorepo project (React + Vite frontend, Express + tRPC backend).

## Working rules
1. Read files before editing them — always produce COMPLETE file content when writing.
2. Use execute_bash to run build/lint/test commands and verify your work.
3. After completing all tasks respond with a JSON object:
   {"status":"done","summary":"<what was accomplished>"}
   OR if an error cannot be fixed:
   {"status":"error","reason":"<description>"}

## Available actions (respond ONLY with JSON tool calls or final status):

To read a file:
{"action":"read","path":"<relative path>"}

To write a file:
{"action":"write","path":"<relative path>","content":"<full file content>"}

To run a bash command:
{"action":"bash","command":"<shell command>","timeout":30000}

To list a directory:
{"action":"list","path":"<relative path>"}

To search in files:
{"action":"search","pattern":"<text>","glob":"*.ts,*.tsx"}

## Project layout
- Frontend: artifacts/hayo-ai/src/
- Backend:  artifacts/api-server/src/hayo/
- Shared:   shared/
`;

export async function* executeAgentCommandStreaming(
  command: string,
  conversationHistory: { role: "user" | "assistant"; content: string }[],
): AsyncGenerator<AgentStreamEvent> {
  const anthropic = createAnthropicClient();
  const frontendTree = getProjectTree(HAYO_FRONTEND, "", 0, 3);
  const backendTree  = getProjectTree(HAYO_BACKEND,  "", 0, 3);

  const system = STREAMING_SYSTEM +
    `\n\n## Project tree (frontend):\n${frontendTree}` +
    `\n\n## Project tree (backend):\n${backendTree}`;

  const messages: { role: "user" | "assistant"; content: string }[] = [
    ...conversationHistory.slice(-8),
    { role: "user", content: command },
  ];

  // ── Phase 1: planning ──────────────────────────────────────────────────────
  yield { type: "thinking", node: "planner", content: "جاري تحليل الطلب وبناء الخطة..." };

  const planMsg = await anthropic.messages.create({
    model: "claude-sonnet-4-6",
    max_tokens: 2048,
    system: `You are a planner. Analyse the user task and output ONLY a JSON array of step strings (max 8 steps). No other text.\nExample: ["Read App.tsx","Create NewPage.tsx","Add route"]`,
    messages: [{ role: "user", content: command }],
  });

  let plan: string[] = [`تنفيذ: ${command}`];
  try {
    const raw = ((planMsg.content[0] as any).text || "").trim()
      .replace(/^```json/, "").replace(/^```/, "").replace(/```$/, "").trim();
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) plan = parsed;
  } catch {}

  yield { type: "plan", node: "planner", content: JSON.stringify(plan), totalSteps: plan.length };

  // ── Phase 2: agentic execution with self-healing ───────────────────────────
  const MAX_ROUNDS = 20;
  const MAX_ERRORS = 5;
  let errorCount = 0;
  let lastError = "";

  const agentMessages = [...messages];

  for (let round = 0; round < MAX_ROUNDS; round++) {
    // Build context injection with last error if any
    const userContent = round === 0
      ? command
      : (lastError
          ? `Previous error (attempt ${errorCount}/${MAX_ERRORS}):\n${lastError}\n\nAnalyse and fix it.`
          : "Continue with the next step.");

    if (round > 0) {
      agentMessages.push({ role: "user", content: userContent });
    }

    yield { type: "thinking", node: "coder", content: `جولة التنفيذ ${round + 1}...` };

    const response = await anthropic.messages.create({
      model: "claude-sonnet-4-6",
      max_tokens: 8192,
      system,
      messages: agentMessages,
    });

    const rawText = ((response.content[0] as any).text || "").trim();
    agentMessages.push({ role: "assistant", content: rawText });

    // ── Check for final status ───────────────────────────────────────────────
    const finalMatch = rawText.match(/\{[\s\S]*?"status"\s*:\s*"(done|error)"[\s\S]*?\}/);
    if (finalMatch) {
      try {
        const final = JSON.parse(finalMatch[0]);
        if (final.status === "done") {
          yield { type: "done", node: "reviewer", content: final.summary || "اكتملت المهمة بنجاح." };
          return;
        }
        if (final.status === "error") {
          yield { type: "error", node: "reviewer", content: final.reason || "فشلت المهمة." };
          return;
        }
      } catch {}
    }

    // ── Parse and execute tool calls ─────────────────────────────────────────
    const actionMatches = [...rawText.matchAll(/\{[\s\S]*?"action"\s*:\s*"[^"]+?"[\s\S]*?\}/g)];

    if (actionMatches.length === 0) {
      // Model produced plain text — treat as thinking/commentary
      if (rawText.length > 0) {
        yield { type: "thinking", node: "coder", content: rawText.slice(0, 400) };
      }
      continue;
    }

    let roundHadError = false;

    for (const match of actionMatches) {
      let action: any;
      try { action = JSON.parse(match[0]); } catch { continue; }

      switch (action.action) {
        case "read": {
          yield { type: "tool_call", node: "coder", content: `📖 قراءة: ${action.path}` };
          const content = readFilesSafe([action.path]);
          yield { type: "tool_result", node: "coder", content: content.slice(0, 3000) };
          agentMessages.push({ role: "user", content: `[read result]\n${content.slice(0, 6000)}` });
          break;
        }
        case "write": {
          yield { type: "tool_call", node: "coder", content: `✍️ كتابة: ${action.path}` };
          const abs = resolvePath(action.path);
          if (!abs) {
            const err = `[ERROR] مسار خارج المشروع: ${action.path}`;
            yield { type: "error", node: "coder", content: err };
            agentMessages.push({ role: "user", content: err });
            roundHadError = true;
          } else {
            try {
              const dir = path.dirname(abs);
              if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
              fs.writeFileSync(abs, action.content || "", "utf-8");
              const ok = `[OK] كُتب الملف: ${action.path} (${(action.content?.length || 0).toLocaleString()} حرف)`;
              yield { type: "tool_result", node: "coder", content: ok };
              agentMessages.push({ role: "user", content: ok });
            } catch (e: any) {
              const err = `[ERROR] فشل الكتابة: ${e.message}`;
              yield { type: "error", node: "coder", content: err };
              agentMessages.push({ role: "user", content: err });
              roundHadError = true;
            }
          }
          break;
        }
        case "bash": {
          const cmd = action.command || "";
          yield { type: "tool_call", node: "executor", content: `⚡ bash: ${cmd}` };
          const result = executeBashInProject(cmd, action.timeout || 60_000);
          const output = [
            `EXIT CODE: ${result.exitCode}`,
            result.stdout ? `STDOUT:\n${result.stdout}` : "",
            result.stderr ? `STDERR:\n${result.stderr}` : "",
          ].filter(Boolean).join("\n");
          yield { type: "terminal", node: "executor", content: output };
          agentMessages.push({ role: "user", content: `[bash result]\n${output}` });
          if (result.exitCode !== 0) {
            roundHadError = true;
            lastError = output;
            errorCount++;
          }
          break;
        }
        case "list": {
          yield { type: "tool_call", node: "coder", content: `📁 قائمة: ${action.path}` };
          const tree = getProjectTree(
            path.join(PROJECT_ROOT, action.path || "."), "", 0, 3,
          );
          yield { type: "tool_result", node: "coder", content: tree.slice(0, 2000) };
          agentMessages.push({ role: "user", content: `[list result]\n${tree.slice(0, 3000)}` });
          break;
        }
        case "search": {
          yield { type: "tool_call", node: "coder", content: `🔍 بحث: "${action.pattern}"` };
          // Simple grep across project
          try {
            const grepResult = execSync(
              `grep -r --include="*.ts" --include="*.tsx" --include="*.js" -n "${action.pattern}" artifacts/ 2>/dev/null | head -40`,
              { cwd: PROJECT_ROOT, encoding: "utf-8", timeout: 10_000 },
            ) as unknown as string;
            yield { type: "tool_result", node: "coder", content: String(grepResult).slice(0, 2000) };
            agentMessages.push({ role: "user", content: `[search result]\n${String(grepResult).slice(0, 3000)}` });
          } catch (e: any) {
            const r = String(e.stdout || "لا نتائج").slice(0, 500);
            yield { type: "tool_result", node: "coder", content: r };
            agentMessages.push({ role: "user", content: `[search result]\n${r}` });
          }
          break;
        }
      }
    }

    // ── Self-healing gate ────────────────────────────────────────────────────
    if (roundHadError && errorCount >= MAX_ERRORS) {
      yield {
        type: "error",
        node: "reviewer",
        content: `تجاوز الحد الأقصى للمحاولات (${MAX_ERRORS}). آخر خطأ:\n${lastError}`,
      };
      return;
    }
  }

  yield { type: "done", node: "reviewer", content: "اكتملت جميع جولات التنفيذ." };
}

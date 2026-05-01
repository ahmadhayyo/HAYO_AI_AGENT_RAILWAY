import { useState, useRef, useEffect, useCallback } from "react";
import { useAuth } from "@/_core/hooks/useAuth";
import { getLoginUrl } from "@/const";
import { Button } from "@/components/ui/button";
import { Link } from "wouter";
import { toast } from "sonner";
import { motion, AnimatePresence } from "framer-motion";
import {
  Bot, Send, Loader2, Home, CheckCircle2, XCircle,
  FileCode, FilePlus, Trash2, Eye, Terminal, ChevronDown,
  ChevronUp, Copy, RotateCcw, Zap, ListChecks, Search,
  Play, AlertTriangle, Brain, Wrench, ShieldCheck,
} from "lucide-react";

// ─── Types ────────────────────────────────────────────────────────────────────

type NodeType = "planner" | "coder" | "executor" | "reviewer" | "system";
type EventType = "plan" | "thinking" | "tool_call" | "tool_result" | "terminal" | "error" | "done";

interface AgentStreamEvent {
  type: EventType;
  node: NodeType;
  content: string;
  step?: number;
  totalSteps?: number;
}

interface StreamMessage {
  id: string;
  role: "user" | "assistant";
  content: string;
  events: AgentStreamEvent[];
  plan?: string[];
  done: boolean;
  error: boolean;
  timestamp: Date;
}

// ─── Constants ────────────────────────────────────────────────────────────────

const NODE_LABELS: Record<NodeType, string> = {
  planner:  "المخطط",
  coder:    "المبرمج",
  executor: "المنفذ",
  reviewer: "المراجع",
  system:   "النظام",
};

const NODE_COLORS: Record<NodeType, string> = {
  planner:  "text-blue-400 border-blue-500/40 bg-blue-500/10",
  coder:    "text-violet-400 border-violet-500/40 bg-violet-500/10",
  executor: "text-cyan-400 border-cyan-500/40 bg-cyan-500/10",
  reviewer: "text-amber-400 border-amber-500/40 bg-amber-500/10",
  system:   "text-gray-400 border-gray-500/40 bg-gray-500/10",
};

const NODE_ICONS: Record<NodeType, React.ComponentType<{ className?: string }>> = {
  planner:  ListChecks,
  coder:    FileCode,
  executor: Play,
  reviewer: ShieldCheck,
  system:   Wrench,
};

const EVENT_ICONS: Record<EventType, React.ComponentType<{ className?: string }>> = {
  plan:        ListChecks,
  thinking:    Brain,
  tool_call:   Wrench,
  tool_result: Eye,
  terminal:    Terminal,
  error:       AlertTriangle,
  done:        CheckCircle2,
};

const EXAMPLES = [
  "أنشئ صفحة إحصائيات جديدة مع رسوم بيانية وأضفها للقائمة الجانبية",
  "اقرأ ملف App.tsx وأخبرني بكل المسارات المسجلة",
  "أضف endpoint جديد في tRPC router لجلب بيانات المستخدم",
  "شغّل pnpm build وأصلح أي أخطاء TypeScript تظهر",
  "أنشئ مكون StatCard يعرض رقماً وعنواناً وأيقونة مع تأثير hover",
];

// ─── EventLine component ──────────────────────────────────────────────────────

function EventLine({ event }: { event: AgentStreamEvent }) {
  const [expanded, setExpanded] = useState(event.type === "error" || event.type === "done");
  const Icon = EVENT_ICONS[event.type] || Wrench;
  const nodeColor = NODE_COLORS[event.node];
  const isLong = event.content.length > 200;

  const content = expanded || !isLong
    ? event.content
    : event.content.slice(0, 200) + "…";

  return (
    <motion.div
      initial={{ opacity: 0, x: -8 }}
      animate={{ opacity: 1, x: 0 }}
      className={`rounded-lg border p-2.5 text-xs ${
        event.type === "error"
          ? "bg-red-500/10 border-red-500/30 text-red-300"
          : event.type === "done"
          ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-300"
          : event.type === "terminal"
          ? "bg-black/40 border-white/10 text-green-300"
          : "bg-white/5 border-white/10 text-white/70"
      }`}
    >
      <div className="flex items-center gap-2 mb-1">
        <span className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-semibold border ${nodeColor}`}>
          <Icon className="w-3 h-3" />
          {NODE_LABELS[event.node]}
        </span>
        <span className="opacity-50 capitalize">{event.type.replace("_", " ")}</span>
      </div>

      {event.type === "terminal" ? (
        <pre className="font-mono text-[10px] leading-relaxed whitespace-pre-wrap break-all overflow-x-auto max-h-48" dir="ltr">
          {content}
        </pre>
      ) : (
        <p className="leading-relaxed whitespace-pre-wrap break-words">{content}</p>
      )}

      {isLong && (
        <button
          onClick={() => setExpanded(!expanded)}
          className="mt-1 flex items-center gap-1 text-[10px] text-white/40 hover:text-white/70"
        >
          {expanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
          {expanded ? "طيّ" : "توسعة"}
        </button>
      )}
    </motion.div>
  );
}

// ─── PlanBadges component ─────────────────────────────────────────────────────

function PlanBadges({ plan }: { plan: string[] }) {
  return (
    <div className="space-y-1">
      <p className="text-[10px] text-white/40 font-semibold uppercase tracking-wider">خطة التنفيذ</p>
      {plan.map((step, i) => (
        <div key={i} className="flex items-start gap-2 text-xs text-white/60">
          <span className="shrink-0 w-5 h-5 rounded-full bg-blue-500/20 text-blue-400 flex items-center justify-center text-[10px] font-bold">
            {i + 1}
          </span>
          <span className="leading-relaxed">{step}</span>
        </div>
      ))}
    </div>
  );
}

// ─── StreamMessage component ──────────────────────────────────────────────────

function StreamMessageCard({ msg }: { msg: StreamMessage }) {
  const [showEvents, setShowEvents] = useState(true);

  if (msg.role === "user") {
    return (
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        className="flex justify-end"
      >
        <div className="max-w-[80%] bg-gradient-to-br from-violet-600 to-blue-600 rounded-2xl rounded-tr-md px-4 py-3 text-sm text-white shadow-lg">
          {msg.content}
        </div>
      </motion.div>
    );
  }

  const finalEvent = msg.events.find(e => e.type === "done");
  const errorEvent = msg.events.find(e => e.type === "error" && e.node === "reviewer");

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      className="flex gap-3"
    >
      {/* Avatar */}
      <div className="shrink-0 w-8 h-8 rounded-xl bg-gradient-to-br from-violet-500 to-blue-500 flex items-center justify-center shadow">
        <Bot className="w-4 h-4 text-white" />
      </div>

      <div className="flex-1 min-w-0 space-y-3">
        {/* Plan */}
        {msg.plan && msg.plan.length > 0 && (
          <div className="bg-blue-500/5 border border-blue-500/20 rounded-xl p-3">
            <PlanBadges plan={msg.plan} />
          </div>
        )}

        {/* Events toggle */}
        {msg.events.length > 0 && (
          <div className="space-y-1.5">
            <button
              onClick={() => setShowEvents(!showEvents)}
              className="flex items-center gap-2 text-[11px] text-white/40 hover:text-white/70 transition-colors"
            >
              {showEvents ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
              {showEvents ? "إخفاء" : "عرض"} تفاصيل التنفيذ ({msg.events.length} حدث)
            </button>

            <AnimatePresence>
              {showEvents && (
                <motion.div
                  initial={{ height: 0, opacity: 0 }}
                  animate={{ height: "auto", opacity: 1 }}
                  exit={{ height: 0, opacity: 0 }}
                  className="overflow-hidden space-y-1.5"
                >
                  {msg.events.map((ev, i) => (
                    <EventLine key={i} event={ev} />
                  ))}
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        )}

        {/* Final result */}
        {!msg.done && !msg.error && (
          <div className="flex items-center gap-2 text-xs text-white/40">
            <Loader2 className="w-3.5 h-3.5 animate-spin" />
            <span>الوكيل يعمل…</span>
          </div>
        )}

        {finalEvent && (
          <div className="bg-emerald-500/10 border border-emerald-500/30 rounded-xl px-4 py-3 text-sm text-emerald-300">
            <div className="flex items-center gap-2 mb-1">
              <CheckCircle2 className="w-4 h-4 shrink-0" />
              <span className="font-semibold">اكتملت المهمة</span>
            </div>
            <p className="text-xs leading-relaxed opacity-80">{finalEvent.content}</p>
          </div>
        )}

        {errorEvent && (
          <div className="bg-red-500/10 border border-red-500/30 rounded-xl px-4 py-3 text-sm text-red-300">
            <div className="flex items-center gap-2 mb-1">
              <XCircle className="w-4 h-4 shrink-0" />
              <span className="font-semibold">فشلت المهمة</span>
            </div>
            <p className="text-xs leading-relaxed opacity-80">{errorEvent.content}</p>
          </div>
        )}
      </div>
    </motion.div>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────

export default function AIAgent() {
  const { isAuthenticated, user, loading: authLoading } = useAuth();
  const [input, setInput] = useState("");
  const [messages, setMessages] = useState<StreamMessage[]>([]);
  const [isStreaming, setIsStreaming] = useState(false);
  const [currentNode, setCurrentNode] = useState<NodeType | null>(null);
  const chatEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const abortRef = useRef<AbortController | null>(null);

  // Auto-scroll
  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const appendEvent = useCallback((msgId: string, event: AgentStreamEvent) => {
    setMessages(prev =>
      prev.map(m =>
        m.id === msgId
          ? { ...m, events: [...m.events, event] }
          : m
      )
    );
  }, []);

  const handleSend = useCallback(async () => {
    const text = input.trim();
    if (!text || isStreaming) return;
    setInput("");

    // Add user message
    const userMsgId = crypto.randomUUID();
    const userMsg: StreamMessage = {
      id: userMsgId,
      role: "user",
      content: text,
      events: [],
      done: true,
      error: false,
      timestamp: new Date(),
    };

    // Add empty assistant message
    const asstMsgId = crypto.randomUUID();
    const asstMsg: StreamMessage = {
      id: asstMsgId,
      role: "assistant",
      content: "",
      events: [],
      done: false,
      error: false,
      timestamp: new Date(),
    };

    setMessages(prev => [...prev, userMsg, asstMsg]);
    setIsStreaming(true);
    setCurrentNode("planner");

    // Build history from previous messages
    const history = messages
      .filter(m => m.done)
      .map(m => ({ role: m.role as "user" | "assistant", content: m.content || m.events.find(e => e.type === "done")?.content || "" }))
      .slice(-10);

    abortRef.current = new AbortController();

    try {
      const response = await fetch("/api/agent/stream", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ command: text, history }),
        signal: abortRef.current.signal,
      });

      if (!response.ok || !response.body) {
        throw new Error(`HTTP ${response.status}`);
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() || "";

        for (const line of lines) {
          if (line.startsWith("event: agent_event")) continue;
          if (line.startsWith("event: agent_done")) {
            setMessages(prev =>
              prev.map(m => m.id === asstMsgId ? { ...m, done: true } : m)
            );
            continue;
          }
          if (line.startsWith("event: agent_error")) continue;
          if (!line.startsWith("data: ")) continue;

          const raw = line.slice(6).trim();
          if (!raw) continue;

          try {
            const event: AgentStreamEvent = JSON.parse(raw);
            setCurrentNode(event.node);

            // Extract plan
            if (event.type === "plan") {
              try {
                const plan: string[] = JSON.parse(event.content);
                setMessages(prev =>
                  prev.map(m => m.id === asstMsgId ? { ...m, plan } : m)
                );
              } catch {}
            }

            // Mark done / error
            if (event.type === "done") {
              setMessages(prev =>
                prev.map(m =>
                  m.id === asstMsgId
                    ? { ...m, done: true, events: [...m.events, event] }
                    : m
                )
              );
            } else if (event.type === "error" && event.node === "reviewer") {
              setMessages(prev =>
                prev.map(m =>
                  m.id === asstMsgId
                    ? { ...m, done: true, error: true, events: [...m.events, event] }
                    : m
                )
              );
            } else {
              appendEvent(asstMsgId, event);
            }
          } catch {}
        }
      }
    } catch (err: any) {
      if (err.name !== "AbortError") {
        toast.error(`خطأ في الاتصال: ${err.message}`);
        setMessages(prev =>
          prev.map(m =>
            m.id === asstMsgId
              ? {
                  ...m, done: true, error: true,
                  events: [...m.events, {
                    type: "error" as EventType,
                    node: "system" as NodeType,
                    content: err.message,
                  }],
                }
              : m
          )
        );
      }
    } finally {
      setIsStreaming(false);
      setCurrentNode(null);
      abortRef.current = null;
    }
  }, [input, isStreaming, messages, appendEvent]);

  const handleStop = () => {
    abortRef.current?.abort();
    setIsStreaming(false);
    setCurrentNode(null);
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  // Loading / unauthenticated guards
  if (authLoading) {
    return (
      <div className="min-h-screen bg-[#0a0a0f] flex items-center justify-center">
        <Loader2 className="w-8 h-8 animate-spin text-violet-500" />
      </div>
    );
  }

  if (!isAuthenticated) {
    return (
      <div className="min-h-screen bg-[#0a0a0f] flex items-center justify-center p-6">
        <div className="text-center space-y-4">
          <Bot className="w-16 h-16 text-violet-400 mx-auto" />
          <h2 className="text-2xl font-bold text-white">وكيل البرمجة الذكي</h2>
          <p className="text-white/50">يجب تسجيل الدخول لاستخدام هذه الميزة</p>
          <Link href={getLoginUrl()}>
            <Button className="bg-violet-600 hover:bg-violet-700 text-white">تسجيل الدخول</Button>
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-screen bg-[#0a0a0f] text-white overflow-hidden">

      {/* ── Header ── */}
      <div className="shrink-0 border-b border-white/10 px-4 py-3 flex items-center justify-between bg-black/30 backdrop-blur-sm">
        <div className="flex items-center gap-3">
          <Link href="/">
            <Button variant="ghost" size="icon" className="w-8 h-8 text-white/50 hover:text-white">
              <Home className="w-4 h-4" />
            </Button>
          </Link>
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-xl bg-gradient-to-br from-violet-500 to-blue-500 flex items-center justify-center shadow">
              <Bot className="w-4 h-4 text-white" />
            </div>
            <div>
              <h1 className="text-sm font-bold text-white">وكيل البرمجة الذكي</h1>
              <p className="text-[10px] text-white/40">Claude Sonnet 4.6 • LangGraph</p>
            </div>
          </div>
        </div>

        {/* Status indicator */}
        <div className="flex items-center gap-3">
          {isStreaming && currentNode && (
            <motion.div
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full border text-xs font-medium ${NODE_COLORS[currentNode]}`}
            >
              <Loader2 className="w-3 h-3 animate-spin" />
              {NODE_LABELS[currentNode]}
            </motion.div>
          )}

          {isStreaming ? (
            <Button
              variant="ghost"
              size="icon"
              onClick={handleStop}
              className="w-8 h-8 text-red-400 hover:text-red-300 hover:bg-red-500/10"
              title="إيقاف"
            >
              <XCircle className="w-4 h-4" />
            </Button>
          ) : (
            <Button
              variant="ghost"
              size="icon"
              onClick={() => setMessages([])}
              className="w-8 h-8 text-white/30 hover:text-white/60"
              title="مسح المحادثة"
              disabled={messages.length === 0}
            >
              <Trash2 className="w-4 h-4" />
            </Button>
          )}
        </div>
      </div>

      {/* ── Chat Area ── */}
      <div className="flex-1 overflow-y-auto px-4 py-6 space-y-6">
        {messages.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full gap-6 text-center">
            <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-violet-500 to-blue-500 flex items-center justify-center shadow-xl">
              <Bot className="w-8 h-8 text-white" />
            </div>
            <div className="space-y-2">
              <h2 className="text-xl font-bold text-white">وكيل البرمجة الذكي</h2>
              <p className="text-white/40 text-sm max-w-sm">
                أعطني أي مهمة برمجية وسأقوم بتحليلها وتنفيذها خطوة بخطوة باستخدام Claude Sonnet 4.6
              </p>
            </div>
            <div className="grid grid-cols-1 gap-2 w-full max-w-lg">
              {EXAMPLES.map((ex, i) => (
                <button
                  key={i}
                  onClick={() => { setInput(ex); inputRef.current?.focus(); }}
                  className="text-right text-xs text-white/50 hover:text-white/80 bg-white/5 hover:bg-white/10 border border-white/10 hover:border-white/20 rounded-xl px-4 py-2.5 transition-all"
                >
                  {ex}
                </button>
              ))}
            </div>
          </div>
        ) : (
          <>
            {messages.map(msg => (
              <StreamMessageCard key={msg.id} msg={msg} />
            ))}
            <div ref={chatEndRef} />
          </>
        )}
      </div>

      {/* ── Input Area ── */}
      <div className="shrink-0 border-t border-white/10 px-4 py-3 bg-black/30 backdrop-blur-sm">
        <div className="flex items-end gap-2 max-w-4xl mx-auto">
          <div className="flex-1 relative">
            <textarea
              ref={inputRef}
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="اكتب مهمتك البرمجية هنا… (Enter للإرسال، Shift+Enter لسطر جديد)"
              rows={1}
              disabled={isStreaming}
              className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-sm text-white placeholder:text-white/30 resize-none focus:outline-none focus:border-violet-500/50 focus:ring-1 focus:ring-violet-500/30 disabled:opacity-50 transition-all"
              style={{ minHeight: "48px", maxHeight: "160px" }}
              onInput={e => {
                const el = e.currentTarget;
                el.style.height = "auto";
                el.style.height = Math.min(el.scrollHeight, 160) + "px";
              }}
              dir="rtl"
            />
          </div>
          <Button
            onClick={handleSend}
            disabled={isStreaming || !input.trim()}
            className="shrink-0 w-11 h-11 bg-gradient-to-br from-violet-600 to-blue-600 hover:from-violet-500 hover:to-blue-500 text-white rounded-xl shadow-lg disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {isStreaming ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Send className="w-4 h-4" />
            )}
          </Button>
        </div>
        <p className="text-center text-[10px] text-white/20 mt-2">
          وكيل ذكي يعمل بـ Claude Sonnet 4.6 • LangGraph • متعدد المراحل
        </p>
      </div>
    </div>
  );
}

              
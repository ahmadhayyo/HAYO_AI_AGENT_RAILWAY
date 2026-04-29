# HAYO AI Coding Agent

وكيل برمجة ذاتي مبني على **LangGraph** + **Claude Sonnet 4.6**، مشابه لـ Replit Agent وDevin.

## الهيكل

```
code-agent/
├── core/
│   └── state.py          ← AgentState (TypedDict) + ثوابت
├── tools/
│   ├── filesystem.py     ← read_file, write_file, list_directory, search_in_files
│   └── terminal.py       ← execute_bash_command (subprocess + timeout)
├── agent/
│   ├── nodes.py          ← PlannerNode, CoderNode, ExecutorNode, ReviewerNode
│   └── graph.py          ← StateGraph + MemorySaver checkpointer
├── main.py               ← CLI تفاعلي مع Rich UI
└── requirements.txt
```

## دورة العمل

```
[User Task]
     │
     ▼
 PlannerNode  ← يحلل الطلب ويصنع خطة مرتبة (JSON array)
     │
     ▼
  CoderNode   ← ينفذ الخطة: يقرأ الملفات، يكتب الكود، يشغل أوامر bash
     │
     ▼
ExecutorNode  ← يشغل build/lint/tests للتحقق
     │
     ▼
ReviewerNode  ← يحكم: نجح؟ → END | خطأ؟ → CoderNode (self-healing)
     ▲              │
     └──────────────┘
       (حتى 5 محاولات)
```

## التثبيت

```bash
cd artifacts/code-agent
pip install -r requirements.txt
```

## التشغيل

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
python main.py --working-dir /path/to/HAYO_AI_AGENT_RAILWAY
```

## أمثلة

```
You> أنشئ صفحة جديدة "الإحصائيات" وأضفها للقائمة الجانبية
You> أصلح خطأ TypeScript في ملف artifacts/api-server/src/routes/health.ts
You> أضف endpoint جديد في tRPC router لجلب إحصائيات المستخدمين
You> شغل pnpm build وأصلح أي أخطاء تظهر
```

## الميزات

- ✅ **Self-healing loop** — يصلح أخطاءه تلقائياً حتى 5 محاولات
- ✅ **أدوات filesystem** — قراءة/كتابة/بحث في الملفات مع sandbox
- ✅ **تنفيذ bash** — مع timeout وحماية من الأوامر الخطرة
- ✅ **Rich UI** — واجهة طرفية جميلة مع spinners وpanels
- ✅ **Persistent state** — MemorySaver checkpointer بين الطلبات
- ✅ **Claude Sonnet 4.6** — أسرع وأرخص من Opus مع نفس الكفاءة

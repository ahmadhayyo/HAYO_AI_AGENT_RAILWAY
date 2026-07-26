# HAYO Cipher-7 — دليل التطوير والتعميق (HOW_TO_EXTEND)

هذا الدليل يشرح **أين تُطوّر لتحصل على قفزات قوية**، و**كيف تصل نتائج تطويرك إلى التقرير**
(العقود الهندسية للمنظومة)، و**كيف تتحقّق من نجاح عملك** قبل الاعتماد. الفلسفة:
لديك حرية كاملة للتعمّق والعدوانية في «مناطق الابتكار»، وما عليك سوى احترام «ناقل
الرسائل» (message bus) الذي يوصل عملك إلى التقرير حتى لا يضيع بصمت.

---

## 1) معمارية المنظومة وتدفّق البيانات

```
static_engine.py ──(secrets/endpoints/manifest)──▶ IntelStore (المخزن/blackboard)
                                                        │
warroom_brain.ingest_static_findings  ◀── يُدمج قبل الديناميكي (توجيه آنيّ)
                                                        │
scripts/instrument_deep.js  ──(Frida findings عبر send)──▶ dynamic_engine._on_message
        + payloads/*.js                                    │
ai_explorer  ──(يقود الواجهة، يقرأ store.brain_context)──▶ brain.decide_action (LLM)
                                                        │
secret_hunter.hunt() ──(device data + logcat + evidence)──▶ يُدمج في findings
                                                        │
brain.triage/summarize ──▶ تقرير loot/deep_*.md + .json
                                                        │
hayo_pipeline (تكيّفي) ──▶ يكرّر ديناميكي→عقل حتى النجاح ثم سحابة→استغلال→تقرير
```

القاعدة الحاكمة: **العمق يُضاف عند الأطراف (hooks/patterns/prompts)، ويتدفّق عبر
ناقل رسائل ثابت الصيغة إلى المخزن ثم التقرير.**

---

## 2) 🟢 مناطق الابتكار — تعمّق هنا بأقصى قوة

### أ) `scripts/instrument_deep.js` — أقوى محرّك للعمق الديناميكي
أضف خطافات Frida جديدة بلا حدود: مكتبات شبكة إضافية، طبقات تشفير أصلية (JNI/BoringSSL)،
قواعد بيانات مشفّرة، KeyStore، WebView bridges، تدفّقات Flutter/Cronet/gRPC، منطق
الاشتراكات، فكّ التعتيم وقت التشغيل، التقاط المفاتيح لحظة الاستخدام.

**العقد الوحيد (ناقل الرسائل):** كل اكتشاف يُرسَل بهذه الصيغة حرفياً — وهي التي
تجعله يظهر في التقرير:
```js
send({ type: "message", payload: {
  kind: "finding",
  type: "اسم_وصفي_للنوع",     // مثل crypto_key, network_secret, pref_value
  severity: "critical|high|medium",  // اختياري (يُستنتج تلقائياً إن غاب)
  detail: "وصف قصير + القيمة",
  evidence: [ "القيمة_الخام", "سياق" ]
}});
```
لِف كل خطاف بـ `try { … } catch(e) {}` حتى لا يُسقط خطاف واحد بقيّة الخطافات.
عند الجاهزية أرسل مرّة: `send({ type:"message", payload:{ kind:"ready" }});`

### ب) `secret_hunter.py` — بطارية اكتشاف الأسرار
لكل نوع مفتاح جديد أضف سطراً في قاموس `HIGH_CONFIDENCE` (نمط regex دقيق). لأنماط
تحتاج سياقاً استخدم `CONTEXTUAL`. **حافظ على مرشّحات المصداقية** `_plausible`،
`_looks_wordy`، `_looks_identifier` — فهي التي تمنع النتائج الكاذبة (أسماء الأصناف،
كائنات Java، ميزات الـ SDK). التعميق هنا = تغطية أوسع بلا ضجيج.

### ج) `payloads/*.js` — أوضاع المنسق (Full/Cloud/Token Assault)
`payload_network_ultra.js`, `payload_crypto_deep.js`, `payload_firebase_steal.js`,
`payload_billing_hook.js`, `payload_storage_leak.js` — أضف خطافات كما في (أ).

### د) `static_engine.py` — العمق الساكن
طوّر قاموس `SECRET_PATTERNS` وقائمة `CLOUD_DOMAINS` في أعلى الملف (أنماط/نطاقات جديدة).

### هـ) `warroom_brain.py` (نصوص التوجيه فقط) — ذكاء أعمق للـ AI
حسّن نصوص الـ prompts داخل `triage`، `summarize`، `decide_action` لقرارات أذكى
واستكشاف أعمق. **أبقِ أسماء الدوال وبنية القيمة المُعادة كما هي** (هي عقد مع المحرك).

---

## 3) 🔵 نقاط التكامل — اعمل هنا بحذر ووعي بالعقد

هذه ليست ممنوعة، لكنها «مقابس» يعتمد عليها غيرها؛ حافظ على العقود التالية:

- **`intel_store.py`** — واجهة المخزن. العقد: `add(kind, value, source, note)` يُعيد
  `True` عند الجديد؛ `add_finding(dict)`؛ `brain_context(n)`. أضف دوالّ جديدة بحرية،
  لكن لا تغيّر توقيع/سلوك هذه.
- **`dynamic_engine.py::_on_message`** — يفكّ ناقل الرسائل. إن أضفت `kind` جديداً
  عالِجه هنا؛ لا تكسر فرعي `finding`/`ready`.
- **`ai_explorer.py`** — حلقة الاستكشاف التقارُبية (goal/stagnation/foreground-guard).
  طوّر الاستدلال والأهداف، وأبقِ حارس المقدّمة ومنطق التقارب سليمين.
- **`hayo_pipeline.py`** — تسلسل المراحل و`_goal_reached` (يعتمد نتائج وقت-التشغيل).
- **`llm_brain.py`** — سلسلة المزوّدات (OpenAI→DeepSeek→…). أضف مزوّداً بنفس النمط.

---

## 4) ⚙️ مقابض آمنة (قيَم فقط)
`config.json` (النموذج/المفاتيح) · `max_steps` و`stagnation_limit` (عمق الاستكشاف) ·
نصوص `goal` · قوائم الأنماط/النطاقات.

---

## 5) 🛡️ تعريف «تمّ بنجاح» (تحقّق ذاتي بعد كل تعديل)

1. الترجمة نظيفة:
   ```bash
   python -m py_compile <الملف_المعدّل>.py
   ```
2. تشغيل حيّ قصير يؤكّد الالتقاط والتقرير بلا انهيار:
   ```bash
   python dynamic_engine.py --package <الحزمة> --device emulator-5554 --duration 60
   ```
   المطلوب: تظهر خطافاتك، تُسجَّل نتائج، يُكتب تقرير في `loot/deep_*.md` بلا استثناء.
3. نسخة احتياطية قبل تعديل ملف مهم:
   ```bash
   cp scripts/instrument_deep.js scripts/instrument_deep.BACKUP.js
   ```

---

## 6) 🧠 البرومبت الهندسي الجاهز (انسخه إلى وكيلك المحلي)

> انسخ ما بين السطرين وأرسله لوكيلك، مع إضافة جملة هدفك في النهاية.

```
أنت مهندس أمن هجومي خبير تعمل على تعميق «محرّك HAYO Cipher-7 الديناميكي» على سطح
المكتب (Python + Frida، جهاز/محاكي Android متصل عبر adb، مجلد العمل هو مجلد الوكيل).
مهمتك: توسيع القدرات إلى أقصى عمق وعدوانية ممكنة (التقاط أعمق للمفاتيح/الأسرار/الرموز
بكل أنواعها، تغطية مكتبات وبروتوكولات أكثر، ذكاء استكشاف أعلى). لديك حرية إبداعية كاملة
في «مناطق الابتكار». مبدأ النجاح الوحيد: اجعل عملك العميق يصل فعلياً إلى التقرير، وذلك
باحترام «ناقل الرسائل» وواجهات المنظومة الموصوفة أدناه — فهذه ليست قيوداً بل هي
الأنابيب التي توصل نتائجك حتى لا تضيع بصمت.

معمارية التدفّق:
static_engine → IntelStore → (يُدمج في العقل قبل الديناميكي) → instrument_deep.js +
payloads/*.js (خطافات Frida ترسل عبر send) → dynamic_engine._on_message → secret_hunter
(يمسح بيانات الجهاز + logcat + الأدلة) → brain.triage/summarize → تقرير loot/deep_*.md.
hayo_pipeline يدير حلقة تكيّفية (ديناميكي→عقل) حتى النجاح ثم سحابة→استغلال→تقرير.

مناطق الابتكار (طوّر هنا بأقصى قوة):
- scripts/instrument_deep.js و payloads/*.js: أضف خطافات Frida جديدة بلا سقف.
- secret_hunter.py: أضف أنماط مفاتيح إلى HIGH_CONFIDENCE / CONTEXTUAL، مع الحفاظ على
  مرشّحات المصداقية (_plausible/_looks_wordy/_looks_identifier) لمنع الإيجابيات الكاذبة.
- static_engine.py: وسّع SECRET_PATTERNS و CLOUD_DOMAINS.
- warroom_brain.py: حسّن نصوص التوجيه (prompts) في triage/decide_action/summarize فقط.

عقد ناقل الرسائل (إلزامي ليظهر أي اكتشاف في التقرير):
كل نتيجة من أي سكربت Frida تُرسَل حرفياً هكذا:
  send({ type:"message", payload:{ kind:"finding", type:"<نوع>", severity:"critical|high|medium",
         detail:"<وصف+قيمة>", evidence:[<القيم الخام>] }});
وعند جاهزية الخطافات أرسل مرة: send({ type:"message", payload:{ kind:"ready" }});
لِف كل خطاف بـ try/catch. أي صيغة أخرى ستُهمَل بصمت.

عقود الواجهات (حافظ عليها كما هي، وأضف فوقها بحرية):
- IntelStore: add(kind,value,source,note)→True عند الجديد؛ add_finding(dict)؛ brain_context(n).
- warroom_brain: أسماء وتوقيعات triage/summarize/decide_action/ingest_* وبنية قيمها المُعادة.
- dynamic_engine._on_message: أفرع kind = finding/ready؛ لا تكسرها (أضف أفرعاً جديدة إن لزم).
- ai_explorer: أبقِ حارس المقدّمة (عدم النقر خارج التطبيق) ومنطق التقارب (goal/stagnation) سليمين.

اشتغل بحذر واعٍ (لا تعيد كتابتها، عدّل بدقّة جراحية): intel_store.py القلب،
dynamic_engine حلقة run/التفكيك، hayo_pipeline التسلسل و_goal_reached، llm_brain سلسلة
المزوّدات، وملفات .bat و HAYO-GUI.pyw (أسلاك الأزرار) — تعديلها الخاطئ يكسر مسارات كثيرة.

تعريف «تمّ»: بعد كل تعديل نفّذ python -m py_compile على الملف، ثم تشغيلاً حيّاً قصيراً
python dynamic_engine.py --package <الحزمة> --device emulator-5554 --duration 60 وتأكّد
من ظهور خطافاتك وتسجيل نتائج وكتابة تقرير بلا انهيار. خذ نسخة احتياطية للملف قبل تعديله.
سلّم تغييرات دقيقة ومركّزة مع شرح موجز لما أضفته وكيف تحقّقت منه.

هدفي هذه المرة: [اكتب هنا التطوير المطلوب بدقّة].
```

---

*ملاحظة: مجلد الوكيل المكتبي غير متتبّع في git؛ خذ نسخاً احتياطية يدوية للملفات المهمة
قبل التطوير الكبير. المحرّك المنشور على Railway منفصل تماماً ولا تلمسه هذه التطويرات.*

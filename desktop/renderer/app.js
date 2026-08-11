// =====================================================================
//  HAYO Cipher-7 — renderer
// =====================================================================
const H = window.hayo;
let CFG = null;

// ---------- Matrix rain background ----------
(function matrix() {
  const canvas = document.getElementById("matrix");
  const ctx = canvas.getContext("2d");
  const glyphs = "アカサタナ0123456789ABCDEFｦｱｳｴｵﾘﾂﾃﾅﾆﾇHAYOCIPHER7</>{}#$".split("");
  let cols, drops, fs = 15;
  function resize() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    cols = Math.floor(canvas.width / fs);
    drops = Array(cols).fill(0).map(() => Math.random() * -50);
  }
  resize();
  window.addEventListener("resize", resize);
  function draw() {
    ctx.fillStyle = "rgba(5, 7, 15, 0.09)";
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.font = fs + "px Consolas, monospace";
    for (let i = 0; i < cols; i++) {
      const ch = glyphs[(Math.random() * glyphs.length) | 0];
      const x = i * fs, y = drops[i] * fs;
      ctx.fillStyle = Math.random() > 0.975 ? "#eafff6" : "#00e6a8";
      ctx.fillText(ch, x, y);
      if (y > canvas.height && Math.random() > 0.975) drops[i] = 0;
      drops[i] += 0.5;
    }
  }
  setInterval(draw, 55);
})();

// ---------- Log ----------
const logEl = document.getElementById("log");
function logLine(t) {
  logEl.textContent += t + "\n";
  logEl.scrollTop = logEl.scrollHeight;
}
H.onLog(logLine);
H.onPhase((p) => {
  document.getElementById("phase").textContent = "⏳ المرحلة " + p;
  setStatus("المرحلة " + p);
});
H.onPipelineDone((code) => {
  document.getElementById("btn-pipeline").disabled = false;
  document.getElementById("btn-pipeline").textContent = "🤖 تشغيل المسار الكامل";
  document.getElementById("btn-pipeline-stop").disabled = true;
  setStatus(code === 0 ? "اكتمل المسار ✓" : "توقف المسار (" + code + ")");
});
function setStatus(t) { document.getElementById("footer-status").textContent = t; }

// ---------- Target helpers ----------
const pkgInput = document.getElementById("pkg-input");
const deviceSelect = document.getElementById("device-select");
function getPkg() {
  const p = pkgInput.value.trim();
  if (!p) { logLine("⚠ اكتب اسم الحزمة أولًا أو اخترها من القائمة."); setStatus("لا يوجد هدف"); }
  return p;
}
pkgInput.addEventListener("input", () => {
  document.getElementById("hero-pkg").textContent = pkgInput.value.trim() || "لم يُحدَّد";
});
deviceSelect.addEventListener("change", async () => {
  CFG = await H.setConfig({ device: deviceSelect.value });
  document.getElementById("hero-device").textContent = CFG.device;
});

async function pickApk() {
  const f = await H.pickApk();
  if (!f) logLine("… أُلغي اختيار الملف.");
  return f;
}
const bat = (b, a) => H.launchBat(b, a);
const py = (s, a, envPatch) => H.launchPy(s, a, envPatch);
const batPkg = (b) => async () => { const p = getPkg(); if (p) bat(b, p); };
const batNone = (b) => () => bat(b);

// ---------- Action model (mirrors HAYO-GUI.pyw) ----------
function getWebUrl() {
  const el = document.getElementById("web-url-input");
  const u = el ? el.value.trim() : "";
  if (!u) { logLine("⚠ اكتب رابط الموقع المستهدف أولًا."); setStatus("لا يوجد رابط هدف"); }
  return u;
}
// كل سكربتات الويب تستخدم --url؛ هذا المُساعد يضمن الصيغة الصحيحة
function webRun(script, extra) {
  const u = getWebUrl();
  if (!u) return;
  py(script, `--url "${u}"` + (extra ? " " + extra : ""));
  logLine(`▶ web: ${script} → ${u}`);
  setStatus("تشغيل ويب: " + script);
}
// بعض محركات الويب المتخصصة (SSRF/GraphQL/WebSocket/API) تقرأ الرابط كوسيط
// موضعي (sys.argv[1]) لا عبر --url
function webRunPositional(script) {
  const u = getWebUrl();
  if (!u) return;
  py(script, `"${u}"`);
  logLine(`▶ web: ${script} → ${u}`);
  setStatus("تشغيل ويب: " + script);
}

// مدة فتح الصفحة — حدّ أدنى 60 ثانية دائمًا (يُصحَّح تلقائيًا إن أُدخل أقل)
function getWebDuration() {
  const el = document.getElementById("web-duration-input");
  let n = parseInt(el ? el.value : "", 10);
  if (!Number.isFinite(n) || n < 60) {
    n = 60;
    if (el) el.value = "60";
  }
  return n;
}

// بيانات تسجيل الدخول الحيّ — تُستخدم مع المحركات المعتمدة على متصفح Chromium
// مرئي (web_engine.py / web_premium.py) ليملأ المحرّك الحقول فعليًا في الصفحة.
function getWebLogin() {
  const user = (document.getElementById("web-login-user")?.value || "").trim();
  const pass = document.getElementById("web-login-pass")?.value || "";
  const url = (document.getElementById("web-login-url")?.value || "").trim();
  return { user, pass, url };
}

// محركات المتصفح الحيّ (Chromium مرئي): تمرّر --duration (≥60s) وبيانات الدخول
// إن وُجدت. كلمة المرور تُمرَّر عبر متغيّر بيئة HAYO_WEB_PASS فقط — أبدًا كوسيط
// نصّي — كي لا تظهر في السجلّ أو قائمة العمليات.
function webRunBrowser(script, extraFlags) {
  const u = getWebUrl();
  if (!u) return;
  const dur = getWebDuration();
  const { user, pass, url: loginUrl } = getWebLogin();
  let args = `--url "${u}" --headful --duration ${dur}`;
  if (extraFlags) args += " " + extraFlags;
  if (user) args += ` --login-user "${user}"`;
  if (loginUrl) args += ` --login-url "${loginUrl}"`;
  const envPatch = pass ? { HAYO_WEB_PASS: pass } : {};
  py(script, args, envPatch);
  logLine(`▶ web(browser): ${script} → ${u} | duration=${dur}s` + (user ? ` | login=${user}` : ""));
  setStatus("تشغيل متصفح حيّ: " + script);
}

const TABS = {
  web: [
    { title: "الاستكشاف والفحص الساكن (Recon & Static)", items: [
      { e: "🕷️", t: "الزاحف والفحص الساكن للموقع", s: "web_static_engine.py", run: () => webRun("web_static_engine.py") },
      { e: "🏗️", t: "فحص البنية التحتية العميقة", s: "web_deep_infrastructure_engine.py", run: () => webRun("web_deep_infrastructure_engine.py") },
      { e: "📊", t: "محرك DAST (تتبّع المسارات الديناميكي)", s: "dast/dast_engine.py", run: () => webRun("dast/dast_engine.py") },
    ]},
    { title: "الفحص النشط للثغرات (Active Scanning)", items: [
      { e: "⚡", t: "محرك الهجوم النشط (Active Assault)", s: "web_active_engine.py", danger: true, run: () => webRun("web_active_engine.py", "--aggressive") },
      { e: "🧠", t: "الفحص المتقدّم (Advanced)", s: "web_advanced.py", run: () => webRun("web_advanced.py", "--aggressive") },
      { e: "🔀", t: "تهريب طلبات HTTP (Smuggling)", s: "web_smuggling.py", run: () => webRun("web_smuggling.py") },
      { e: "🧪", t: "ثغرات البروتوكول وGraphQL", s: "web_proto.py", run: () => webRun("web_proto.py") },
      { e: "🔓", t: "التسلسل الضار (Deserialization)", s: "web_deserial.py", danger: true, run: () => webRun("web_deserial.py") },
    ]},
    { title: "محركات متخصّصة (SSRF / GraphQL / WebSocket / API)", items: [
      { e: "🎯", t: "اختبار SSRF (تزوير الطلبات من الخادم)", s: "web_ssrf_engine.py", danger: true, run: () => webRunPositional("web_ssrf_engine.py") },
      { e: "🕸️", t: "فحص GraphQL (استبطان وIDOR)", s: "web_graphql_engine.py", run: () => webRunPositional("web_graphql_engine.py") },
      { e: "🔌", t: "فحص WebSocket", s: "web_websocket_engine.py", run: () => webRunPositional("web_websocket_engine.py") },
      { e: "📡", t: "فحص واجهات API (Mass Assignment)", s: "web_api_engine.py", run: () => webRunPositional("web_api_engine.py") },
    ]},
    { title: "المزايا المدفوعة على الويب (Web Premium)", items: [
      { e: "🧬", t: "اختبار مزايا/اشتراك الويب", s: "web_premium.py", run: () => webRunBrowser("web_premium.py") },
    ]},
    { title: "أدوات مساندة", items: [
      { e: "📞", t: "تشغيل خادم OAST (التقاط التفاعلات خارج النطاق)", s: "web_oast.py", run: () => { py("web_oast.py", ""); logLine("▶ web: web_oast.py (خادم استماع محلي)"); setStatus("تشغيل خادم OAST"); } },
    ]},
  ],

  static: [
    { title: "تحليل واستخراج + بناء", items: [
      { e: "🔎", t: "حلّل واستخرج المفاتيح", s: "HAYO-AUTO.bat", run: async () => { const f = await pickApk(); if (f) bat("HAYO-AUTO.bat", `"${f}" --test-keys`); } },
      { e: "🔓", t: "بناء APK موقّع (Premium)", s: "RUN-MODIFY-APK.bat", run: async () => { const f = await pickApk(); if (f) bat("RUN-MODIFY-APK.bat", `"${f}" --root`); } },
      { e: "📲", t: "تثبيت ذكي على المحاكي", s: "RUN-INSTALL.bat", run: async () => { let f = await H.pickApk(); if (!f) f = await H.pickPath("dir"); if (f) bat("RUN-INSTALL.bat", `"${f}"`); } },
      { e: "🩺", t: "فحص وإصلاح البيئة", s: "SETUP-CHECK.bat", run: batNone("SETUP-CHECK.bat") },
    ]},
  ],
  engines: [
    { title: "المحرّك الذكي (AI)", items: [
      { e: "🚀", t: "المسار المبسّط (DeepSeek 3 مراحل)", s: "deepseek_pipeline.py", run: async () => { const p = getPkg(); const f = p && await pickApk(); if (p && f) py("deepseek_pipeline.py", `"${f}" --package ${p} --device ${CFG.device} --aggressive`); } },
      { e: "⚡", t: "DeepSeek Core (استخراج + فكّ + فتح تلقائي)", s: "RUN-DEEPSEEK-CORE.bat", run: batPkg("RUN-DEEPSEEK-CORE.bat") },
      { e: "🧠", t: "المحرّك الديناميكي الموحّد", s: "RUN-DEEP.bat", run: batPkg("RUN-DEEP.bat") },
    ]},
    { title: "الهجوم الشامل والاعتراض", items: [
      { e: "🔥", t: "هجوم شامل (Full Assault)", s: "RUN-FULL-ASSAULT.bat", danger: true, run: batPkg("RUN-FULL-ASSAULT.bat") },
      { e: "☁️", t: "اختراق السحابة (Cloud Assault)", s: "RUN-CLOUD-ASSAULT.bat", run: batPkg("RUN-CLOUD-ASSAULT.bat") },
      { e: "💰", t: "حقن الرموز (Token Heist)", s: "RUN-TOKEN-HEIST.bat", run: batPkg("RUN-TOKEN-HEIST.bat") },
      { e: "🌩️", t: "محرك اختراق السحابة المباشر", s: "cloud_breach_engine.py", run: async () => { const p = getPkg(); if (p) py("cloud_breach_engine.py", `--package ${p} --device ${CFG.device}`); } },
    ]},
    { title: "الاعتراض والتصنّت", items: [
      { e: "🌐", t: "اعتراض حركة المرور (Universal)", s: "RUN-CAPTURE-ALL.bat", run: batPkg("RUN-CAPTURE-ALL.bat") },
      { e: "🔬", t: "اعتراض TLS الأصلي (Native)", s: "RUN-CAPTURE-NATIVE.bat", run: batPkg("RUN-CAPTURE-NATIVE.bat") },
      { e: "🕵️", t: "اعتراض عميق (Deep Hijack)", s: "RUN-HIJACK.bat", run: batPkg("RUN-HIJACK.bat") },
      { e: "📡", t: "مراقبة الواجهات الحساسة", s: "RUN-MONITOR.bat", run: batPkg("RUN-MONITOR.bat") },
    ]},
    { title: "فتح المزايا المدفوعة", items: [
      { e: "🔓", t: "فتح Premium (محلي)", s: "RUN-UNLOCK.bat", run: batPkg("RUN-UNLOCK.bat") },
      { e: "🔓", t: "فتح Premium (سحابي)", s: "RUN-UNLOCK-CLOUD.bat", run: batPkg("RUN-UNLOCK-CLOUD.bat") },
      { e: "🔓", t: "Hijack Premium", s: "RUN-HIJACK-PREMIUM.bat", run: batPkg("RUN-HIJACK-PREMIUM.bat") },
      { e: "☁️", t: "Hijack Cloud", s: "RUN-HIJACK-CLOUD.bat", run: batPkg("RUN-HIJACK-CLOUD.bat") },
    ]},
    { title: "أدوات ملحقة", items: [
      { e: "🎥", t: "تسجيل الشاشة و Logcat", s: "RUN-SCREEN-REC.bat", run: batNone("RUN-SCREEN-REC.bat") },
    ]},
  ],
  advanced: [
    { title: "حقن وتنصّت متقدّم", items: [
      { e: "🪝", t: "Mass Hook (كل العمليات)", s: "RUN-MASS-HOOK.bat", run: batNone("RUN-MASS-HOOK.bat") },
      { e: "🧠", t: "فحص الذاكرة (Memory Scanner)", s: "RUN-MEMORY-SCAN.bat", run: batPkg("RUN-MEMORY-SCAN.bat") },
      { e: "🥷", t: "تجاوز الكشف (Evasion)", s: "RUN-EVASION.bat", run: batPkg("RUN-EVASION.bat") },
    ]},
    { title: "استخراج وتحكم عن بُعد", items: [
      { e: "🗂️", t: "استنساخ بيانات التطبيق (Data Clone)", s: "RUN-DATA-CLONE.bat", run: batPkg("RUN-DATA-CLONE.bat") },
      { e: "🖥️", t: "Reverse Shell", s: "RUN-REVERSE-SHELL.bat", danger: true, run: batPkg("RUN-REVERSE-SHELL.bat") },
      { e: "📟", t: "خادم C2", s: "RUN-C2-SERVER.bat", run: batNone("RUN-C2-SERVER.bat") },
      { e: "🎛️", t: "المنسّق التفاعلي (Orchestrator)", s: "RUN-ORCHESTRATOR.bat", run: batPkg("RUN-ORCHESTRATOR.bat") },
    ]},
  ],
};

// ============================================================
// أدوات سحابية/تشفيرية متقدّمة — تتطلّب مدخلات محدّدة (JWT/تجزئة/ملف/رقم
// مشروع) لا تناسب زر بنقرة واحدة. كل أداة: حقولها الفعلية مطابقة تمامًا
// لصيغة argparse الحقيقية في السكربت (لا تخمين).
// ============================================================
const CLOUD_TOOLS = [
  {
    id: "firebase_exploiter", script: "firebase_exploiter.py", emoji: "🔥",
    title: "استغلال Firebase", desc: "استغلال مشروع Firebase عبر JWT مُستخرَج (تصعيد صلاحيات، وصول لقاعدة البيانات).",
    cmd: "firebase_exploiter.py --token <JWT> --project <رقم> [--api-key <مفتاح>]",
    fields: [
      { id: "token", label: "JWT Token (مطلوب)", placeholder: "eyJhbGciOi...", required: true },
      { id: "project", label: "رقم مشروع Firebase", placeholder: "38530841164", value: "38530841164" },
      { id: "apikey", label: "مفتاح Google API (اختياري)", placeholder: "AIzaSy…" },
    ],
    build: (v) => {
      if (!v.token) return null;
      let a = `--token "${v.token}" --project "${v.project || "38530841164"}"`;
      if (v.apikey) a += ` --api-key "${v.apikey}"`;
      return a;
    },
  },
  {
    id: "intelligent_cloud", script: "intelligent_cloud_exploiter.py", emoji: "🧠",
    title: "المستغِل السحابي الذكي", desc: "يحلّل تقريري الفحص الساكن والديناميكي (JSON من loot/) بقيادة AI ليقترح مسار استغلال سحابي.",
    cmd: "intelligent_cloud_exploiter.py --static <ملف.json> --dynamic <ملف.json>",
    fields: [
      { id: "static", label: "ملف نتائج الفحص الساكن (JSON، مطلوب)", placeholder: "loot/static_*.json", browse: true, required: true },
      { id: "dynamic", label: "ملف نتائج الفحص الديناميكي (JSON، مطلوب)", placeholder: "loot/shadow_*.json", browse: true, required: true },
    ],
    build: (v) => {
      if (!v.static || !v.dynamic) return null;
      return `--static "${v.static}" --dynamic "${v.dynamic}"`;
    },
  },
  {
    id: "jwt_forge", script: "jwt_forge.py", emoji: "🔑",
    title: "تزوير/فكّ JWT", desc: "فكّ رمز JWT، أو تزوير رمز بقلب المطالبات، أو توليد رمز جديد بالكامل.",
    cmd: "jwt_forge.py [--token] [--decode] [--new] [--sub] [--mode] [--secret]",
    fields: [
      { id: "token", label: "رمز لتزوير مطالباته (اختياري)", placeholder: "eyJhbGciOi..." },
      { id: "decode", label: "رمز لفكّه فقط (اختياري)", placeholder: "eyJhbGciOi..." },
      { id: "sub", label: "Subject لرمز جديد", placeholder: "hayo-user", value: "hayo-user" },
      { id: "mode", label: "وضع التوقيع", select: ["keep", "none", "hs256"], value: "keep" },
      { id: "secret", label: "سرّ HMAC (لوضع hs256)", placeholder: "" },
      { id: "newFlag", label: "توليد رمز جديد؟", select: ["لا", "نعم"], value: "لا" },
    ],
    build: (v) => {
      let parts = [];
      if (v.token) parts.push(`--token "${v.token}"`);
      if (v.decode) parts.push(`--decode "${v.decode}"`);
      if (v.newFlag === "نعم") parts.push("--new");
      if (v.sub) parts.push(`--sub "${v.sub}"`);
      if (v.mode) parts.push(`--mode ${v.mode}`);
      if (v.secret) parts.push(`--secret "${v.secret}"`);
      if (!parts.length) return null;
      return parts.join(" ");
    },
  },
  {
    id: "bruteforce", script: "bruteforce.py", emoji: "🧨", danger: true,
    title: "كسر التجزئة/PIN (كلمات ضعيفة فقط)", desc: "يحاول كسر تجزئة أو PIN أو bcrypt عبر قائمة كلمات أو نطاق أرقام — لا يستخدم إلا مع أسرار ضعيفة مصرَّح باختبارها.",
    cmd: "bruteforce.py <hash|pin|bcrypt> --value <القيمة> [خيارات]",
    fields: [
      { id: "cmd", label: "نوع الهجوم", select: ["hash", "pin", "bcrypt"], value: "hash" },
      { id: "value", label: "القيمة/التجزئة الهدف (مطلوب)", placeholder: "5f4dcc3b5aa765d61d8327deb882cf99", required: true },
      { id: "algo", label: "خوارزمية التجزئة (اختياري)", placeholder: "md5 / sha256 …" },
      { id: "wordlist", label: "ملف قائمة كلمات (اختياري)", browse: true },
      { id: "pins", label: "أقصى طول PIN (لأمر hash)", placeholder: "0", value: "0" },
      { id: "min", label: "أدنى طول PIN (لأمر pin)", placeholder: "4", value: "4" },
      { id: "max", label: "أقصى طول PIN (لأمر pin)", placeholder: "6", value: "6" },
    ],
    build: (v) => {
      if (!v.value) return null;
      const cmd = v.cmd || "hash";
      let a = `${cmd} --value "${v.value}"`;
      if (v.algo) a += ` --algo ${v.algo}`;
      if (v.wordlist) a += ` --wordlist "${v.wordlist}"`;
      if (cmd === "hash" && v.pins) a += ` --pins ${v.pins}`;
      if (cmd === "pin") { if (v.min) a += ` --min ${v.min}`; if (v.max) a += ` --max ${v.max}`; }
      return a;
    },
  },
  {
    id: "cloud_bypass", script: "cloud_bypass.py", emoji: "☁️",
    title: "تجاوز خدمات السحابة", desc: "يحاول تجاوز/استغلال خدمات سحابية (Firebase, Google API…) من مفاتيح مُستخرَجة في تقرير سابق أو متغيّرات البيئة.",
    cmd: "cloud_bypass.py [--report <ملف.json>] [--services <قائمة>]",
    fields: [
      { id: "report", label: "ملف تقرير JSON (اختياري)", browse: true },
      { id: "services", label: "الخدمات المستهدفة", placeholder: "firebase,google_api", value: "firebase,google_api" },
    ],
    build: (v) => {
      let a = "";
      if (v.report) a += `--report "${v.report}"`;
      if (v.services) a += ` --services "${v.services}"`;
      return a.trim() || "";
    },
  },
  {
    id: "cloud_exfiltrator", script: "cloud_exfiltrator.py", emoji: "📤",
    title: "استخراج بيانات السحابة", desc: "يستخرج بيانات سحابية مرتبطة بحزمة أندرويد (يستخدم الحزمة/الجهاز المُختارَين في تبويب «الهدف والجهاز»).",
    cmd: "cloud_exfiltrator.py --package <حزمة> --device <جهاز> [--output <مجلد>]",
    fields: [
      { id: "output", label: "مجلد الحفظ (اختياري)", placeholder: "loot/cloud", value: "loot/cloud" },
    ],
    build: (v) => {
      const p = getPkg();
      if (!p) return null;
      let a = `--package "${p}" --device "${CFG.device}"`;
      if (v.output) a += ` --output "${v.output}"`;
      return a;
    },
  },
  {
    id: "firebase_rules_probe", script: "firebase_rules_probe.py", emoji: "🗄️",
    title: "فحص قواعد Firebase", desc: "يفحص قواعد أمان Firestore/Storage بحثًا عن صلاحيات قراءة/كتابة مفتوحة.",
    cmd: "firebase_rules_probe.py [--project] [--api-key] [--bucket] [--google-services]",
    fields: [
      { id: "project", label: "رقم/معرّف المشروع", placeholder: "my-project-id" },
      { id: "apikey", label: "مفتاح API", placeholder: "AIzaSy…" },
      { id: "bucket", label: "اسم Storage Bucket", placeholder: "my-project.appspot.com" },
      { id: "gservices", label: "ملف google-services.json (اختياري)", browse: true },
    ],
    build: (v) => {
      let parts = [];
      if (v.project) parts.push(`--project "${v.project}"`);
      if (v.apikey) parts.push(`--api-key "${v.apikey}"`);
      if (v.bucket) parts.push(`--bucket "${v.bucket}"`);
      if (v.gservices) parts.push(`--google-services "${v.gservices}"`);
      return parts.join(" ");
    },
  },
  {
    id: "cloud_chain", script: "cloud_chain_exploiter.py", emoji: "🔗", demo: true,
    title: "محرك سلاسل الاستغلال السحابي (عرض توضيحي)",
    desc: "⚠ هذا الملف حاليًا سكربت عرض داخلي بلا مدخلات سطر أوامر حقيقية — يبني رسمًا بيانيًا تجريبيًا بثغرات وهمية لإظهار آلية عمل المحرّك. لا يختبر هدفك الفعلي؛ يُستخدم عبر الاستيراد البرمجي (Python) لا كأداة مستقلة.",
    cmd: "cloud_chain_exploiter.py   (يشغّل عرضًا داخليًا فقط — بلا مدخلات)",
    fields: [],
    build: () => "",
  },
];

function buildGrid(gridId, blocks) {
  const grid = document.getElementById(gridId);
  grid.innerHTML = "";
  for (const block of blocks) {
    const wrap = document.createElement("div");
    wrap.className = "secblock";
    wrap.innerHTML = `<h3 class="secblock__title">${block.title}</h3>`;
    const actions = document.createElement("div");
    actions.className = "actions";
    for (const it of block.items) {
      const b = document.createElement("button");
      b.className = "action" + (it.danger ? " action--danger" : "");
      b.innerHTML = `<span class="action__emoji">${it.e}</span>
        <span class="action__body"><span class="action__title">${it.t}</span><span class="action__sub">${it.s}</span></span>`;
      b.addEventListener("click", () => { it.run(); setStatus("تشغيل: " + it.s); });
      actions.appendChild(b);
    }
    wrap.appendChild(actions);
    grid.appendChild(wrap);
  }
}

// ---------- Cloud tools (bespoke forms) ----------
function buildCloudTools() {
  const list = document.getElementById("cloud-tools-list");
  if (!list) return;
  list.innerHTML = "";
  for (const tool of CLOUD_TOOLS) {
    const card = document.createElement("div");
    card.className = "toolcard" + (tool.danger ? " toolcard--danger" : "");
    const fieldsHtml = tool.fields.map((f) => {
      const fid = `ct-${tool.id}-${f.id}`;
      let control;
      if (f.select) {
        control = `<select id="${fid}" class="input mono">${f.select.map((o) => `<option value="${o}"${o === f.value ? " selected" : ""}>${o}</option>`).join("")}</select>`;
      } else if (f.browse) {
        control = `<div class="row"><input id="${fid}" class="input mono" placeholder="${f.placeholder || ""}" /><button class="btn btn--ghost btn--sm" data-ct-browse="${fid}">📁</button></div>`;
      } else {
        control = `<input id="${fid}" class="input mono" placeholder="${f.placeholder || ""}" value="${f.value || ""}" />`;
      }
      return `<div class="toolcard__field"><label>${f.label}</label>${control}</div>`;
    }).join("");
    card.innerHTML = `
      <div class="toolcard__head">
        <span class="toolcard__emoji">${tool.emoji}</span>
        <div>
          <h4 class="toolcard__title">${tool.title}</h4>
          <p class="toolcard__desc">${tool.desc}</p>
          <p class="toolcard__cmd">${tool.cmd}</p>
        </div>
      </div>
      ${tool.demo ? "" : `<div class="toolcard__fields">${fieldsHtml}</div>`}
      <button class="btn ${tool.danger ? "btn--danger" : "btn--primary"} btn--sm" data-ct-run="${tool.id}">
        ${tool.demo ? "▶ تشغيل العرض التوضيحي" : "▶ تشغيل " + tool.script}
      </button>`;
    list.appendChild(card);
  }

  list.querySelectorAll("[data-ct-browse]").forEach((btn) =>
    btn.addEventListener("click", async () => {
      const f = await H.pickPath("file");
      if (f) document.getElementById(btn.dataset.ctBrowse).value = f;
    })
  );

  list.querySelectorAll("[data-ct-run]").forEach((btn) =>
    btn.addEventListener("click", () => {
      const tool = CLOUD_TOOLS.find((t) => t.id === btn.dataset.ctRun);
      if (!tool) return;
      const vals = {};
      for (const f of tool.fields) {
        const el = document.getElementById(`ct-${tool.id}-${f.id}`);
        vals[f.id] = el ? el.value.trim() : "";
      }
      const missing = tool.fields.filter((f) => f.required && !vals[f.id]);
      if (missing.length) {
        logLine(`⚠ ${tool.title}: يلزم ملء — ${missing.map((f) => f.label).join("، ")}`);
        setStatus("حقول ناقصة");
        return;
      }
      const args = tool.build(vals);
      if (args === null) {
        logLine(`⚠ ${tool.title}: تعذّر بناء الأمر — تحقّق من الحقول المطلوبة.`);
        return;
      }
      py(tool.script, args);
      logLine(`▶ cloud-tool: ${tool.script} ${args}`.trim());
      setStatus("تشغيل: " + tool.script);
    })
  );
}

// ---------- Tabs ----------
document.getElementById("tabs").addEventListener("click", (e) => {
  const tab = e.target.closest(".tab");
  if (!tab) return;
  document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("is-active", t === tab));
  document.querySelectorAll(".panel").forEach((p) => p.classList.toggle("is-active", p.dataset.panel === tab.dataset.tab));
});

// ---------- Devices & packages ----------
document.getElementById("btn-refresh-devices").addEventListener("click", async () => {
  setStatus("فحص الأجهزة…");
  const r = await H.adbDevices();
  deviceSelect.innerHTML = "";
  for (const d of r.devices) {
    const o = document.createElement("option");
    o.value = o.textContent = d;
    deviceSelect.appendChild(o);
  }
  if (r.preferred) deviceSelect.value = r.preferred;
  CFG = await H.setConfig({ device: deviceSelect.value });
  document.getElementById("hero-device").textContent = CFG.device;
  logLine(`✓ الأجهزة: ${r.devices.join(", ")}` + (r.error ? ` (تحذير: ${r.error})` : ""));
  setStatus("جاهز");
});

let ALL_PKGS = [];
const pkgListEl = document.getElementById("pkg-list");
document.getElementById("btn-refresh-pkgs").addEventListener("click", async () => {
  setStatus("جلب التطبيقات…");
  pkgListEl.innerHTML = '<li class="pkglist__hint">…جارٍ الجلب</li>';
  const r = await H.adbPackages(deviceSelect.value || CFG.device);
  ALL_PKGS = r.packages || [];
  renderPkgs(ALL_PKGS);
  if (r.error) logLine("خطأ adb: " + r.error);
  setStatus(ALL_PKGS.length ? `${ALL_PKGS.length} تطبيق` : "لا تطبيقات");
});
function renderPkgs(list) {
  pkgListEl.innerHTML = "";
  if (!list.length) { pkgListEl.innerHTML = '<li class="pkglist__hint">لا توجد تطبيقات.</li>'; return; }
  for (const name of list) {
    const li = document.createElement("li");
    li.textContent = name;
    li.addEventListener("click", () => {
      pkgInput.value = name;
      document.getElementById("hero-pkg").textContent = name;
      pkgListEl.querySelectorAll("li").forEach((x) => x.classList.remove("is-sel"));
      li.classList.add("is-sel");
      setStatus("الهدف: " + name);
    });
    pkgListEl.appendChild(li);
  }
}
document.getElementById("pkg-filter").addEventListener("input", (e) => {
  const q = e.target.value.trim().toLowerCase();
  renderPkgs(q ? ALL_PKGS.filter((p) => p.toLowerCase().includes(q)) : ALL_PKGS);
});

// ---------- Pipeline ----------
document.getElementById("btn-pipeline").addEventListener("click", async () => {
  const p = getPkg();
  if (!p) return;
  const dur = document.getElementById("dur-input").value.trim() || "180";
  const r = await H.pipelineStart(p, dur);
  if (r.ok) {
    document.getElementById("btn-pipeline").disabled = true;
    document.getElementById("btn-pipeline").textContent = "⏳ المسار قيد التشغيل…";
    document.getElementById("btn-pipeline-stop").disabled = false;
    setStatus("المسار يعمل…");
  } else if (r.error === "running") {
    logLine("المسار قيد التشغيل بالفعل.");
  }
});
document.getElementById("btn-pipeline-stop").addEventListener("click", () => H.pipelineStop());

// ---------- Settings ----------
document.getElementById("btn-save-cfg").addEventListener("click", async () => {
  CFG = await H.setConfig({
    agentDir: document.getElementById("cfg-agent").value.trim(),
    adbPath: document.getElementById("cfg-adb").value.trim(),
    pyPath: document.getElementById("cfg-py").value.trim(),
  });
  const s = document.getElementById("cfg-saved");
  s.hidden = false;
  setTimeout(() => (s.hidden = true), 2000);
  logLine("💾 حُفظت الإعدادات.");
});
document.querySelectorAll("[data-browse]").forEach((btn) =>
  btn.addEventListener("click", async () => {
    const kind = btn.dataset.browse;
    const f = await H.pickPath(kind === "agent" ? "dir" : "file");
    if (!f) return;
    if (kind === "agent") document.getElementById("cfg-agent").value = f;
    if (kind === "adb") document.getElementById("cfg-adb").value = f;
    if (kind === "py") document.getElementById("cfg-py").value = f;
  })
);
document.getElementById("btn-open-web").addEventListener("click", () => H.openExternal(CFG.webUrl));
document.getElementById("btn-clear-log").addEventListener("click", () => (logEl.textContent = ""));

// ---------- Key & URL Tester ----------
document.getElementById("btn-kt-single").addEventListener("click", () => {
  const value = document.getElementById("kt-value").value.trim();
  if (!value) { logLine("⚠ اكتب مفتاحًا أو رابطًا أولًا."); return; }
  const type = document.getElementById("kt-type").value;
  const secondary = document.getElementById("kt-secondary").value.trim();
  const baseUrl = document.getElementById("kt-baseurl").value.trim();
  let args = `--value "${value}"`;
  if (type) args += ` --type ${type}`;
  if (secondary) args += ` --secondary "${secondary}"`;
  if (baseUrl) args += ` --base-url "${baseUrl}"`;
  py("key_url_tester.py", args);
  logLine(`▶ فحص مفتاح/رابط فردي… (النتيجة في نافذة منفصلة)`);
  setStatus("فحص مفتاح/رابط…");
});

document.getElementById("btn-kt-bulk").addEventListener("click", async () => {
  const data = document.getElementById("kt-bulk-data").value;
  const instructions = document.getElementById("kt-bulk-instructions").value;
  if (!data.trim()) { logLine("⚠ الصق مستخرجات الفحص أولًا في الحقل الأول."); return; }
  const dataPath = await H.writeTempFile("bulk_data.txt", data);
  const instrPath = await H.writeTempFile("bulk_instructions.txt", instructions);
  py("key_url_tester.py", `--bulk-file "${dataPath}" --instructions-file "${instrPath}"`);
  logLine(`▶ فحص جماعي بقيادة العقل… (النتيجة والملخّص في نافذة منفصلة)`);
  setStatus("الفحص الجماعي الذكي يعمل…");
});

// ---------- Window controls ----------
document.getElementById("btn-min").addEventListener("click", () => H.win.minimize());
document.getElementById("btn-max").addEventListener("click", () => H.win.toggleMaximize());
document.getElementById("btn-close").addEventListener("click", () => H.win.close());

// ---------- Init ----------
(async function init() {
  buildGrid("grid-static", TABS.static);
  buildGrid("grid-engines", TABS.engines);
  buildGrid("grid-advanced", TABS.advanced);
  buildGrid("grid-web", TABS.web);
  buildCloudTools();

  const state = await H.getState();
  CFG = state.config;
  document.getElementById("app-version").textContent = "v" + state.version;
  document.getElementById("cfg-agent").value = CFG.agentDir;
  document.getElementById("cfg-adb").value = CFG.adbPath;
  document.getElementById("cfg-py").value = CFG.pyPath;

  const o = document.createElement("option");
  o.value = o.textContent = CFG.device;
  deviceSelect.appendChild(o);
  document.getElementById("hero-device").textContent = CFG.device;

  
  const btnWebScan = document.getElementById("btn-run-full-web-scan");
  if (btnWebScan) {
    btnWebScan.addEventListener("click", () => {
      logLine("🌐 فحص ويب شامل بقيادة AI…");
      webRunBrowser("web_engine.py", "--aggressive");
    });
  }

  logLine("HAYO Cipher-7 جاهز.");
  logLine("ADB: " + CFG.adbPath);
  logLine("Python: " + CFG.pyPath);
  logLine("المحرّك: " + CFG.agentDir);
  logLine("اذهب إلى «الهدف والجهاز» → تحديث الأجهزة، ثم تحديث القائمة لاختيار التطبيق.");
})();

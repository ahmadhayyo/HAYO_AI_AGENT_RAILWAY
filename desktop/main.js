const { app, BrowserWindow, ipcMain, shell, dialog } = require("electron");
const path = require("node:path");
const fs = require("node:fs");
const { spawn, execFile } = require("node:child_process");

// ===== Defaults (mirrors HAYO-GUI.pyw) =====
const DEFAULT_AGENT = "C:\\Users\\PT\\Desktop\\HAYO\\HAYO_AI_AGENT_RAILWAY\\artifacts\\hayo ai-agent";
const ADB_CANDIDATES = [
  "C:\\Users\\PT\\Downloads\\platform-tools\\adb.exe",
  "D:\\LDPlayer\\LDPlayer9\\adb.exe",
];
const DEFAULT_PY = "C:\\Users\\PT\\AppData\\Local\\Programs\\Python\\Python312\\python.exe";
const DEFAULT_DEV = "emulator-5554";

const DEFAULTS = {
  agentDir: DEFAULT_AGENT,
  adbPath: ADB_CANDIDATES.find((p) => fs.existsSync(p)) || ADB_CANDIDATES[0],
  pyPath: DEFAULT_PY,
  device: DEFAULT_DEV,
  webUrl: "https://hayo-ai.com",
};

const CONFIG_PATH = () => path.join(app.getPath("userData"), "config.json");
function loadConfig() {
  try {
    return { ...DEFAULTS, ...JSON.parse(fs.readFileSync(CONFIG_PATH(), "utf8")) };
  } catch {
    return { ...DEFAULTS };
  }
}
function saveConfig(cfg) {
  try {
    fs.writeFileSync(CONFIG_PATH(), JSON.stringify(cfg, null, 2), "utf8");
  } catch (e) {
    console.error("saveConfig", e);
  }
}

let mainWindow = null;
let pipelineProc = null;

function createMainWindow() {
  const iconPath = path.join(__dirname, "build", "icon.ico");
  mainWindow = new BrowserWindow({
    width: 1220,
    height: 860,
    minWidth: 980,
    minHeight: 660,
    show: false,
    frame: false,
    backgroundColor: "#05070f",
    title: "HAYO Cipher-7",
    icon: fs.existsSync(iconPath) ? iconPath : undefined,
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
    },
  });
  mainWindow.loadFile(path.join(__dirname, "renderer", "index.html"));
  mainWindow.once("ready-to-show", () => mainWindow.show());
  mainWindow.on("closed", () => (mainWindow = null));
  const sendMax = () => mainWindow?.webContents.send("window:maximized", mainWindow.isMaximized());
  mainWindow.on("maximize", sendMax);
  mainWindow.on("unmaximize", sendMax);
}

function log(line) {
  mainWindow?.webContents.send("log:line", line);
}

// ===== adb helpers =====
function runAdb(args, timeoutMs = 30000) {
  const cfg = loadConfig();
  return new Promise((resolve) => {
    execFile(cfg.adbPath, args, { timeout: timeoutMs, windowsHide: true }, (err, stdout) => {
      resolve({ ok: !err, out: stdout || "", err: err ? String(err.message || err) : "" });
    });
  });
}

ipcMain.handle("adb:devices", async () => {
  const cfg = loadConfig();
  const res = await runAdb(["devices"], 15000);
  if (!res.ok) return { devices: [DEFAULT_DEV], error: res.err };
  const devices = [];
  for (const raw of res.out.split(/\r?\n/).slice(1)) {
    const line = raw.trim();
    if (!line || !line.includes("\t")) continue;
    const [name, state] = line.split("\t");
    if (state.trim() === "device") devices.push(name.trim());
  }
  if (!devices.length) devices.push(DEFAULT_DEV);
  const preferred = devices.find((d) => d.startsWith("emulator-")) || devices[0];
  const next = { ...cfg, device: preferred };
  saveConfig(next);
  return { devices, preferred };
});

ipcMain.handle("adb:packages", async (_e, device) => {
  const res = await runAdb(["-s", device, "shell", "pm", "list", "packages", "-3"], 30000);
  if (!res.ok) return { packages: [], error: res.err };
  const pkgs = res.out
    .split(/\r?\n/)
    .map((l) => l.replace("package:", "").trim())
    .filter(Boolean)
    .sort();
  return { packages: pkgs };
});

// ===== config / state =====
ipcMain.handle("app:getState", () => ({ config: loadConfig(), version: app.getVersion() }));
ipcMain.handle("app:setConfig", (_e, patch) => {
  const cfg = { ...loadConfig(), ...patch };
  saveConfig(cfg);
  return cfg;
});
ipcMain.handle("app:pickApk", async () => {
  const r = await dialog.showOpenDialog(mainWindow, {
    title: "اختر ملف APK",
    properties: ["openFile"],
    filters: [{ name: "APK / bundle", extensions: ["apk", "xapk", "apks", "apkm"] }, { name: "All", extensions: ["*"] }],
  });
  return r.canceled ? null : r.filePaths[0];
});
ipcMain.handle("app:pickPath", async (_e, kind) => {
  const r = await dialog.showOpenDialog(mainWindow, {
    properties: [kind === "dir" ? "openDirectory" : "openFile"],
  });
  return r.canceled ? null : r.filePaths[0];
});
ipcMain.handle("app:openExternal", (_e, url) => shell.openExternal(url));

// نص طويل متعدد الأسطر (مستخرجات/تعليمات) غير آمن للدمج داخل نص أمر cmd —
// يُكتب لملف مؤقّت في userData ويُمرَّر مساره كوسيط بدلًا من محتواه.
ipcMain.handle("app:writeTempFile", (_e, filename, content) => {
  const dir = path.join(app.getPath("userData"), "tmp");
  fs.mkdirSync(dir, { recursive: true });
  const safe = filename.replace(/[^a-zA-Z0-9._-]/g, "_");
  const p = path.join(dir, `${Date.now()}_${safe}`);
  fs.writeFileSync(p, content ?? "", "utf-8");
  return p;
});

// ===== launchers (open a console window, like the .pyw) =====
function agentFile(cfg, name) {
  return path.join(cfg.agentDir, name);
}

ipcMain.handle("launch:bat", (_e, batfile, arg = "") => {
  const cfg = loadConfig();
  const p = agentFile(cfg, batfile);
  if (!fs.existsSync(p)) {
    log(`✗ الملف غير موجود: ${batfile}`);
    return { ok: false, error: "missing" };
  }
  const title = "HAYO Cipher-7";
  // start "<title>" cmd /k ""<path>" <arg>"
  const cmdStr = `start "${title}" cmd /k ""${p}" ${arg}"`;
  const child = spawn(cmdStr, {
    cwd: cfg.agentDir,
    shell: true,
    detached: true,
    windowsHide: false,
    env: { ...process.env, HAYO_DEV: cfg.device },
  });
  child.on("error", (er) => log(`✗ تعذّر التشغيل: ${er.message}`));
  child.unref();
  log(`▶ launched ${batfile} ${arg} [DEV=${cfg.device}]`.trim());
  return { ok: true };
});

ipcMain.handle("launch:py", (_e, script, arg = "", envPatch = {}) => {
  const cfg = loadConfig();
  const p = agentFile(cfg, script);
  if (!fs.existsSync(p)) {
    log(`✗ السكربت غير موجود: ${script}`);
    return { ok: false, error: "missing" };
  }
  const cmdStr = `start "DeepSeek Core" cmd /k ""${cfg.pyPath}" "${p}" ${arg}"`;
  const child = spawn(cmdStr, {
    cwd: cfg.agentDir,
    shell: true,
    detached: true,
    windowsHide: false,
    // envPatch يحمل أسرارًا حساسة (مثل كلمة مرور الدخول) بمعزل عن نص الأمر
    // المرئي، مطابقةً لتوقّع السكربتات التي تقرأ الكلمة من env فقط لا من --arg
    env: { ...process.env, HAYO_DEV: cfg.device, PYTHONIOENCODING: "utf-8", ...envPatch },
  });
  child.on("error", (er) => log(`✗ تعذّر التشغيل: ${er.message}`));
  child.unref();
  log(`▶ launched ${script} ${arg} [DEV=${cfg.device}]`.trim());
  return { ok: true };
});

// ===== integrated AI pipeline (streamed) =====
const ANSI_RE = /\x1b\[[0-9;]*m/g;

ipcMain.handle("pipeline:start", (_e, pkg, duration) => {
  if (pipelineProc) return { ok: false, error: "running" };
  const cfg = loadConfig();
  const script = agentFile(cfg, "hayo_pipeline.py");
  if (!fs.existsSync(script)) {
    log("✗ hayo_pipeline.py غير موجود.");
    return { ok: false, error: "missing" };
  }
  const dur = String(duration || "180");
  const args = [script, "--package", pkg, "--device", cfg.device, "--duration", dur, "--adaptive", "--max-rounds", "3"];
  log("=".repeat(56));
  log(`🤖 بدء المسار الكامل | الهدف: ${pkg} | الجهاز: ${cfg.device} | المدة: ${dur}s`);
  log("=".repeat(56));
  try {
    pipelineProc = spawn(cfg.pyPath, args, {
      cwd: cfg.agentDir,
      windowsHide: true,
      env: { ...process.env, HAYO_DEV: cfg.device, PYTHONIOENCODING: "utf-8", PYTHONUNBUFFERED: "1" },
    });
  } catch (er) {
    pipelineProc = null;
    log(`✗ تعذّر بدء المسار: ${er.message}`);
    return { ok: false, error: String(er.message) };
  }
  const onData = (buf) => {
    for (const l of buf.toString("utf8").split(/\r?\n/)) {
      if (l.length) {
        const clean = l.replace(ANSI_RE, "");
        log(clean);
        const m = clean.match(/المرحلة\s*(\d+)\s*[:：]\s*(.+)/);
        if (m) mainWindow?.webContents.send("pipeline:phase", `${m[1]}: ${m[2].trim().slice(0, 48)}`);
      }
    }
  };
  pipelineProc.stdout.on("data", onData);
  pipelineProc.stderr.on("data", onData);
  pipelineProc.on("close", (code) => {
    pipelineProc = null;
    mainWindow?.webContents.send("pipeline:done", code);
    if (code === 0) log("✅ اكتمل المسار الكامل بنجاح. التقارير في مجلد loot/");
    else log(`⚠ انتهى المسار برمز خروج ${code}`);
  });
  return { ok: true };
});

ipcMain.handle("pipeline:stop", () => {
  if (!pipelineProc) return { ok: false };
  try {
    pipelineProc.kill();
    log("⏹ تم إرسال إيقاف المسار...");
  } catch (e) {
    log(`تعذّر الإيقاف: ${e.message}`);
  }
  return { ok: true };
});

// ===== window controls =====
ipcMain.on("win:minimize", () => mainWindow?.minimize());
ipcMain.on("win:toggleMaximize", () => {
  if (!mainWindow) return;
  mainWindow.isMaximized() ? mainWindow.unmaximize() : mainWindow.maximize();
});
ipcMain.on("win:close", () => mainWindow?.close());

app.whenReady().then(() => {
  createMainWindow();
  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createMainWindow();
  });
});
app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});

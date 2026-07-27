#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HAYO Cipher-7 — Graphical Control Panel (HAYO-GUI.pyw)
Updated to include DeepSeek Core v5 One-Click Pipeline.
"""
import os
import re
import queue
import threading
import subprocess
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext, simpledialog

AGENT = os.path.dirname(os.path.abspath(__file__))
ADB_CANDIDATES = [
    r"C:\Users\PT\Downloads\platform-tools\adb.exe",
    r"D:\LDPlayer\LDPlayer9\adb.exe",
]
ADB = next((p for p in ADB_CANDIDATES if os.path.isfile(p)), ADB_CANDIDATES[0])
PY = r"C:\Users\PT\AppData\Local\Programs\Python\Python312\python.exe"
DEFAULT_DEV = "emulator-5554"

BG, FG, ACC, BTN, BTN2, BTN_RED = "#0b1020", "#d6f5e3", "#00e6a8", "#122040", "#1b2d52", "#4a0e0e"
RUN_BTN_TEXT = "🤖  المسار الكامل بقيادة الذكاء الاصطناعي (مباشر داخل اللوحة)"
# الهدف/التعليمات الافتراضية للعقل المدبّر إن ترك المستخدم الحقل فارغاً.
DEFAULT_GOAL = "reach login, premium/subscription and cloud-sync screens"
# Python 3.12+ يمنع إنشاء متغيّرات tkinter قبل وجود نافذة جذر → ننشئ الجذر أولاً.
root = tk.Tk()
USE_PIPELINE_VAR = tk.BooleanVar(value=False)
USE_ULTIMATE_HOOKS_VAR = tk.BooleanVar(value=True)

def get_directive():
    """التعليمات التنفيذية التي كتبها المستخدم للعقل المدبّر (أو الهدف الافتراضي).
    تُمرَّر إلى المحرّك عبر متغيّر البيئة HAYO_GOAL و/أو الوسيط --goal."""
    try:
        t = directive_text.get("1.0", "end").strip()
    except Exception:
        t = ""
    return t or DEFAULT_GOAL

def launch(batfile, arg=""):
    path = os.path.join(AGENT, batfile)
    if not os.path.isfile(path):
        # Fallback to direct python launch if .bat is missing
        if batfile.endswith(".bat"):
            py_script = batfile.replace("RUN-", "").replace(".bat", ".py").lower()
            if os.path.isfile(os.path.join(AGENT, py_script)):
                launch_py(py_script, arg)
                return
        messagebox.showerror("HAYO", f"Missing: {batfile}"); return
    env = os.environ.copy()
    env["HAYO_DEV"] = current_dev()
    env["HAYO_GOAL"] = get_directive()   # يصل الهدف حتى لمسارات .bat (dynamic_engine يقرأه)
    subprocess.Popen(f'start "HAYO Cipher-7" cmd /k ""{path}" {arg}"', shell=True, env=env)
    log_line(f"▶ launched {batfile} {arg} [DEV={env['HAYO_DEV']}]".strip())

def launch_py(script, arg=""):
    path = os.path.join(AGENT, script)
    env = os.environ.copy()
    env["HAYO_DEV"] = current_dev()
    env["HAYO_ADB"] = ADB
    env["HAYO_GOAL"] = get_directive()
    env["PYTHONIOENCODING"] = "utf-8"
    subprocess.Popen(f'start "DeepSeek Core v5" cmd /k "chcp 65001>nul & {PY} {q(path)} {arg}"', shell=True, env=env)
    log_line(f"▶ launched {script} {arg} [DEV={env['HAYO_DEV']}]".strip())

def log_line(text):
    log.insert(tk.END, text + "\n")
    log.see(tk.END)

# ================================================================
#  Integrated in-panel pipeline runner (AI-driven, live streaming)
# ----------------------------------------------------------------
#  Runs hayo_pipeline.py as a child process bound to the selected
#  emulator, and streams its phase-by-phase output straight into
#  the GUI log — no separate cmd window. The AI mastermind drives
#  all 6 phases (static -> dynamic -> brain -> cloud -> exploit -> report).
# ================================================================
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")          # strip color codes
_PHASE_RE = re.compile(r"المرحلة\s*(\d+)\s*[:：]\s*(.+)")

pipeline_proc = None          # currently running subprocess.Popen
pipeline_queue = queue.Queue()  # lines from the reader thread


def _reader_thread(proc):
    """Background: read child stdout line-by-line into the queue."""
    try:
        for raw in proc.stdout:
            pipeline_queue.put(("line", _ANSI_RE.sub("", raw.rstrip("\n"))))
    except Exception as e:
        pipeline_queue.put(("line", f"[reader error] {e}"))
    finally:
        proc.wait()
        pipeline_queue.put(("done", proc.returncode))


def _pump_pipeline():
    """Main-thread: drain the queue into the log widget (Tk-safe)."""
    global pipeline_proc
    try:
        while True:
            kind, payload = pipeline_queue.get_nowait()
            if kind == "line":
                log.insert(tk.END, payload + "\n")
                log.see(tk.END)
                m = _PHASE_RE.search(payload)
                if m:
                    status.config(text=f"⏳ المرحلة {m.group(1)}: {m.group(2).strip()[:48]}")
            elif kind == "done":
                rc = payload
                pipeline_proc = None
                run_pipeline_btn.config(state="normal", text=RUN_BTN_TEXT)
                stop_pipeline_btn.config(state="disabled")
                if rc == 0:
                    status.config(text="✅ اكتمل المسار الكامل — التقارير في مجلد loot/")
                    log_line("✅ اكتمل المسار الكامل بنجاح. التقارير محفوظة في loot/")
                else:
                    status.config(text=f"⚠ توقف المسار (رمز {rc})")
                    log_line(f"⚠ انتهى المسار برمز خروج {rc}")
                return
    except queue.Empty:
        pass
    if pipeline_proc is not None:
        root.after(150, _pump_pipeline)


def on_full_ai_pipeline():
    """Launch the unified AI pipeline inside the panel, bound to the emulator."""
    global pipeline_proc
    if pipeline_proc is not None:
        messagebox.showinfo("HAYO", "المسار قيد التشغيل بالفعل.")
        return
    p = pkg()
    if not p:
        return
    dev = current_dev()
    dur = dur_var.get().strip() or "180"
    
    # Check if using new pipeline orchestrator
    use_pipeline = USE_PIPELINE_VAR.get()
    use_ultimate = USE_ULTIMATE_HOOKS_VAR.get()
    
    # Use dynamic_engine.py with new options
    script = os.path.join(AGENT, "dynamic_engine.py")
    if not os.path.isfile(script):
        messagebox.showerror("HAYO", "dynamic_engine.py غير موجود."); return
    
    directive = get_directive()
    cmd = [PY, script, "--package", p, "--device", dev, "--duration", str(dur),
           "--goal", directive]

    if use_pipeline:
        cmd.append("--use-pipeline")

    if not use_ultimate:
        # If not using ultimate hooks, will fall back to instrument_deep.js or instrument.js
        pass

    env = os.environ.copy()
    env["HAYO_DEV"] = dev
    env["HAYO_ADB"] = ADB
    env["HAYO_GOAL"] = directive
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUNBUFFERED"] = "1"
    
    try:
        pipeline_proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace",
            bufsize=1, cwd=AGENT, env=env,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except Exception as e:
        pipeline_proc = None
        messagebox.showerror("HAYO", f"تعذّر بدء المسار: {e}"); return
    
    pipeline_mode = "جديد (8 مراحل)" if use_pipeline else "تقليدي"
    hooks_mode = "Ultimate (100+ hooks)" if use_ultimate else "Deep (40+ hooks)"
    
    log_line("=" * 60)
    log_line(f"🤖 بدء المسار الكامل بقيادة AI")
    log_line(f"   الهدف: {p} | الجهاز: {dev} | المدة: {dur}s")
    log_line(f"   البايبلاين: {pipeline_mode}")
    log_line(f"   الخطافات: {hooks_mode}")
    log_line(f"🎯 التعليمات للعقل: {directive[:120]}{'…' if len(directive) > 120 else ''}")
    log_line("=" * 60)
    status.config(text="⏳ بدء المسار الكامل...")
    run_pipeline_btn.config(state="disabled", text="⏳ المسار قيد التشغيل...")
    stop_pipeline_btn.config(state="normal")
    threading.Thread(target=_reader_thread, args=(pipeline_proc,), daemon=True).start()
    root.after(150, _pump_pipeline)


def on_stop_pipeline():
    global pipeline_proc
    if pipeline_proc is None:
        return
    try:
        pipeline_proc.terminate()
        log_line("⏹ تم إرسال إيقاف المسار...")
    except Exception as e:
        log_line(f"تعذّر الإيقاف: {e}")

def pick_apk():
    return filedialog.askopenfilename(title="اختر ملف APK",
                                      filetypes=[("APK / bundle", "*.apk *.xapk *.apks *.apkm"), ("All", "*.*")])

def q(p): return f'"{p}"'

def current_dev():
    return dev_var.get().strip() or DEFAULT_DEV

def pkg():
    p = pkg_entry.get().strip()
    if not p: messagebox.showwarning("HAYO", "اكتب اسم الحزمة أولًا أو اخترها من القائمة.")
    return p

# ---------------------------------------------------------------- ① static
def on_analyze():
    f = pick_apk()
    if f: launch("HAYO-AUTO.bat", q(f) + " --test-keys")

def on_deepseek_pipeline():
    f = pick_apk()
    p = pkg()
    if f and p:
        launch_py("deepseek_pipeline.py", f"{q(f)} --package {p} --device {current_dev()} --aggressive")
    else:
        messagebox.showwarning("DeepSeek", "يرجى اختيار ملف APK واسم الحزمة أولاً.")

def on_unlock_build():
    f = pick_apk()
    if f: launch("RUN-MODIFY-APK.bat", q(f) + " --root")

def on_install():
    f = filedialog.askopenfilename(title="اختر APK المعدّل", filetypes=[("APK/bundle", "*.apk *.xapk *.apks *.apkm"), ("All", "*.*")])
    if not f: f = filedialog.askdirectory(title="اختر مجلد الأجزاء (splits)")
    if f: launch("RUN-INSTALL.bat", q(f))

def on_setup_check():
    launch("SETUP-CHECK.bat")

# ---------------------------------------------------------------- ② target / devices
def refresh_devices():
    try:
        out = subprocess.run([ADB, "devices"], capture_output=True, text=True, timeout=15).stdout
        devs = []
        for line in out.splitlines()[1:]:
            line = line.strip()
            if not line or "\t" not in line:
                continue
            name, state = line.split("\t")
            if state.strip() == "device":
                devs.append(name.strip())
        if not devs:
            devs = [DEFAULT_DEV]
        dev_combo["values"] = devs
        preferred = next((d for d in devs if d.startswith("emulator-")), devs[0])
        dev_var.set(preferred)
        status.config(text=f"✓ الأجهزة المتصلة: {', '.join(devs)}")
    except Exception as e:
        dev_combo["values"] = [DEFAULT_DEV]
        dev_var.set(DEFAULT_DEV)
        status.config(text=f"خطأ adb: {e}")

def on_list_packages():
    try:
        out = subprocess.run([ADB, "-s", current_dev(), "shell", "pm", "list", "packages", "-3"],
                             capture_output=True, text=True, timeout=30).stdout
        pkgs = sorted(l.replace("package:", "").strip() for l in out.splitlines() if l.strip())
        pkg_list.delete(0, tk.END)
        if not pkgs: pkg_list.insert(tk.END, "لا توجد تطبيقات")
        for p in pkgs: pkg_list.insert(tk.END, p)
        status.config(text="👇 انقر على اسم التطبيق في القائمة")
    except Exception as e:
        status.config(text=f"خطأ adb: {e}")

def on_pick_pkg(event=None):
    sel = pkg_list.curselection()
    if not sel: return
    name = pkg_list.get(sel[0]).strip()
    if "." in name:
        pkg_entry.delete(0, tk.END)
        pkg_entry.insert(0, name)
        status.config(text=f"✓ تم اختيار: {name}")

# ---------------------------------------------------------------- ③ dynamic engines
def on_deep_engine():
    p = pkg()
    if p: launch("RUN-DEEP.bat", p)

def on_deepseek_core():
    p = pkg()
    if p: launch("RUN-DEEPSEEK-CORE.bat", p)

def on_capture():
    p = pkg()
    if p: launch("RUN-CAPTURE-ALL.bat", p)

def on_capture_native():
    p = pkg()
    if p: launch("RUN-CAPTURE-NATIVE.bat", p)

def on_hijack_deep():
    p = pkg()
    if p: launch("RUN-HIJACK.bat", p)

def on_unlock_local():
    p = pkg()
    if p: launch("RUN-UNLOCK.bat", p)

def on_unlock_cloud():
    p = pkg()
    if p: launch("RUN-UNLOCK-CLOUD.bat", p)

def on_hijack_premium():
    p = pkg()
    if p: launch("RUN-HIJACK-PREMIUM.bat", p)

def on_hijack_cloud():
    p = pkg()
    if p: launch("RUN-HIJACK-CLOUD.bat", p)

def on_auto_premium():
    """فتح اشتراك تلقائي شامل — يحقن premium_master.js بكل طبقاته ويجرّب كل
    السيناريوهات (اشتراك/مدى الحياة/نقاط/كوين/VIP/تحقّق خادمي) على الحزمة المحددة،
    أو يكتشف تطبيق المقدّمة تلقائياً إن لم تُحدَّد حزمة. يبلّغ بما نجح فعلاً."""
    p = pkg_entry.get().strip()          # اختياري — بدونه يُكتشف تلقائياً
    dev = current_dev()
    script = os.path.join(AGENT, "premium_auto.py")
    if not os.path.isfile(script):
        messagebox.showerror("HAYO", "premium_auto.py غير موجود."); return
    arg = f"--device {dev} --duration 45"
    if p:
        arg += f" --package {p}"
    log_line("🧪 فتح تلقائي شامل — تجربة كل الحيل" + (f" على {p}" if p else " (اكتشاف تلقائي)"))
    launch_py("premium_auto.py", arg)

def on_auto_premium_assist():
    """الوضع المُساعَد: الخطافات حيّة، وأنت تسجّل الدخول وتتنقّل يدوياً؛ تُلتقط
    استدعاءات الاشتراك لحظة حدوثها (أفضل بكثير للتطبيقات المربوطة بحساب)."""
    p = pkg_entry.get().strip()
    dev = current_dev()
    script = os.path.join(AGENT, "premium_auto.py")
    if not os.path.isfile(script):
        messagebox.showerror("HAYO", "premium_auto.py غير موجود."); return
    messagebox.showinfo("HAYO — الوضع المُساعَد",
        "سيُفتح التطبيق والخطافات حيّة.\nاقبل الشروط ← سجّل الدخول ← افتح شاشة الاشتراك.\n"
        "النافذة ~3 دقائق. النتائج تظهر في النافذة.")
    arg = f"--device {dev} --assist" + (f" --package {p}" if p else "")
    log_line("🧑‍💻 وضع مُساعَد — سجّل دخولك أثناء التشغيل" + (f" على {p}" if p else " (اكتشاف تلقائي)"))
    launch_py("premium_auto.py", arg)

def on_static_patch():
    """ترقيع ساكن دائم: يعدّل دوال القرار في APK (isPremium→true) ويعيد التوقيع."""
    f = filedialog.askopenfilename(title="اختر APK للترقيع الدائم",
                                   filetypes=[("APK", "*.apk"), ("All", "*.*")])
    if not f:
        return
    script = os.path.join(AGENT, "premium_patch.py")
    if not os.path.isfile(script):
        messagebox.showerror("HAYO", "premium_patch.py غير موجود."); return
    do_install = messagebox.askyesno("HAYO", "تثبيت النسخة المُرقّعة على المحاكي بعد التوقيع؟")
    arg = q(f) + (f" --install --device {current_dev()}" if do_install else "")
    log_line(f"🩹 ترقيع ساكن دائم: {os.path.basename(f)}")
    launch_py("premium_patch.py", arg)

def on_jwt_forge():
    """تزوير/قلب رمز JWT لمنح صلاحيات مميّزة."""
    script = os.path.join(AGENT, "jwt_forge.py")
    if not os.path.isfile(script):
        messagebox.showerror("HAYO", "jwt_forge.py غير موجود."); return
    tok = simpledialog.askstring("HAYO — JWT Forge",
        "الصق رمز JWT لقلب مطالباته (اتركه فارغاً لتوليد رمز مميّز جديد):")
    if tok is None:
        return
    tok = tok.strip()
    if tok:
        arg = f'--token "{tok}" --mode keep'
        log_line("🔑 قلب مطالبات JWT (mode=keep)")
    else:
        arg = "--new --mode none"
        log_line("🔑 توليد رمز JWT مميّز جديد (alg=none)")
    launch_py("jwt_forge.py", arg)

def on_monitor():
    p = pkg()
    if p: launch("RUN-MONITOR.bat", p)

def on_cloud_assault():
    p = pkg()
    if p: launch("RUN-CLOUD-ASSAULT.bat", p)

def on_token_heist():
    p = pkg()
    if p: launch("RUN-TOKEN-HEIST.bat", p)

def on_full_assault():
    p = pkg()
    if p: launch("RUN-FULL-ASSAULT.bat", p)

def on_screen_rec():
    launch("RUN-SCREEN-REC.bat")

# ---------------------------------------------------------------- ④ advanced utilities
def on_mass_hook():
    launch("RUN-MASS-HOOK.bat")

def on_memory_scan():
    p = pkg()
    if p: launch("RUN-MEMORY-SCAN.bat", p)

def on_evasion():
    p = pkg()
    if p: launch("RUN-EVASION.bat", p)

def on_data_clone():
    p = pkg()
    if p: launch("RUN-DATA-CLONE.bat", p)

def on_reverse_shell():
    p = pkg()
    if p: launch("RUN-REVERSE-SHELL.bat", p)

def on_c2_server():
    launch("RUN-C2-SERVER.bat")

def on_orchestrator():
    p = pkg()
    if p: launch("RUN-ORCHESTRATOR.bat", p)

# ---------------------------------------------------------------- ⑤ new advanced components
def on_deep_engine_with_pipeline():
    """Run dynamic engine with new pipeline orchestrator"""
    p = pkg()
    if not p:
        return
    dev = current_dev()
    dur = dur_var.get().strip() or "180"
    script = os.path.join(AGENT, "dynamic_engine.py")
    if not os.path.isfile(script):
        messagebox.showerror("HAYO", "dynamic_engine.py غير موجود."); return
    directive = get_directive().replace("\n", " ").replace('"', "'").strip()
    launch_py("dynamic_engine.py",
              f'--package {p} --device {dev} --duration {dur} --use-pipeline --goal "{directive}"')

def on_phase_manager():
    """Run phase manager brain standalone"""
    p = pkg()
    if not p:
        return
    dev = current_dev()
    script = os.path.join(AGENT, "phase_manager_brain.py")
    if not os.path.isfile(script):
        messagebox.showerror("HAYO", "phase_manager_brain.py غير موجود."); return
    launch_py("phase_manager_brain.py", f"--package {p} --device {dev}")

def on_decision_engine():
    """Run real-time decision engine standalone"""
    p = pkg()
    if not p:
        return
    dev = current_dev()
    script = os.path.join(AGENT, "realtime_decision_engine.py")
    if not os.path.isfile(script):
        messagebox.showerror("HAYO", "realtime_decision_engine.py غير موجود."); return
    launch_py("realtime_decision_engine.py", f"--package {p} --device {dev}")

def on_data_extraction():
    """Run live data extraction standalone"""
    p = pkg()
    if not p:
        return
    dev = current_dev()
    script = os.path.join(AGENT, "live_data_extractor.py")
    if not os.path.isfile(script):
        messagebox.showerror("HAYO", "live_data_extractor.py غير موجود."); return
    launch_py("live_data_extractor.py", f"--package {p} --device {dev}")

def on_adaptive_exploit():
    """Run adaptive exploitation engine standalone"""
    p = pkg()
    if not p:
        return
    dev = current_dev()
    script = os.path.join(AGENT, "adaptive_exploitation_engine.py")
    if not os.path.isfile(script):
        messagebox.showerror("HAYO", "adaptive_exploitation_engine.py غير موجود."); return
    launch_py("adaptive_exploitation_engine.py", f"--package {p} --device {dev}")

def on_feedback_loop():
    """Run feedback loop standalone"""
    p = pkg()
    if not p:
        return
    dev = current_dev()
    script = os.path.join(AGENT, "feedback_loop.py")
    if not os.path.isfile(script):
        messagebox.showerror("HAYO", "feedback_loop.py غير موجود."); return
    launch_py("feedback_loop.py", f"--package {p} --device {dev}")

def on_pipeline_orchestrator():
    """Run pipeline orchestrator standalone"""
    p = pkg()
    if not p:
        return
    dev = current_dev()
    script = os.path.join(AGENT, "pipeline_orchestrator.py")
    if not os.path.isfile(script):
        messagebox.showerror("HAYO", "pipeline_orchestrator.py غير موجود."); return
    launch_py("pipeline_orchestrator.py", f"--package {p} --device {dev}")

def on_working_memory():
    """Run working memory standalone"""
    p = pkg()
    if not p:
        return
    dev = current_dev()
    script = os.path.join(AGENT, "working_memory.py")
    if not os.path.isfile(script):
        messagebox.showerror("HAYO", "working_memory.py غير موجود."); return
    launch_py("working_memory.py", f"--package {p} --device {dev}")

def on_full_pipeline():
    """Run full pipeline (static + dynamic + AI + exploitation) in one click"""
    p = pkg()
    if not p:
        messagebox.showwarning("HAYO", "يرجى تحديد اسم الحزمة أولاً.")
        return
    
    # Ask for APK path for static analysis
    apk_path = filedialog.askopenfilename(
        title="اختر ملف APK للتحليل الساكنة (اختياري)",
        filetypes=[("APK / bundle", "*.apk *.xapk *.apks *.apkm"), ("All", "*.*")]
    )
    
    dev = current_dev()
    dur = dur_var.get().strip() or "180"
    use_pipeline = USE_PIPELINE_VAR.get()
    use_ultimate = USE_ULTIMATE_HOOKS_VAR.get()
    
    script = os.path.join(AGENT, "full_pipeline.py")
    if not os.path.isfile(script):
        messagebox.showerror("HAYO", "full_pipeline.py غير موجود."); return
    
    cmd = [PY, script, "--package", p, "--device", dev, "--duration", str(dur), "--adb", ADB]
    
    if use_pipeline:
        cmd.append("--use-pipeline")
    
    if use_ultimate:
        cmd.append("--use-ultimate-hooks")
    
    if apk_path:
        cmd.extend(["--apk", apk_path])
    
    log_line("=" * 60)
    log_line("⚡ بدء المسار الكامل الشامل")
    log_line(f"   الهدف: {p} | الجهاز: {dev} | المدة: {dur}s")
    log_line(f"   التحليل الساكنة: {'نعم' if apk_path else 'لا'}")
    log_line(f"   البايبلاين: {'جديد' if use_pipeline else 'تقليدي'}")
    log_line(f"   الخطافات: {'Ultimate (100+)' if use_ultimate else 'Deep (40+)'}")
    log_line("=" * 60)
    
    launch_py("full_pipeline.py", f"--package {p} --device {dev} --duration {dur} --adb {ADB}" +
              (f" --use-pipeline" if use_pipeline else "") +
              (f" --use-ultimate-hooks" if use_ultimate else "") +
              (f" --apk {apk_path}" if apk_path else ""))

# ---------------------------------------------------------------- window
root.title("HAYO Cipher-7 — لوحة التحكم الموحدة")
root.configure(bg=BG)
root.geometry("760x850")
root.minsize(700, 600)

tk.Label(root, text="HAYO Cipher-7", bg=BG, fg=ACC, font=("Consolas", 24, "bold")).pack(pady=(14, 0))
tk.Label(root, text="محرك الاختبار الديناميكي الشامل", bg=BG, fg=FG, font=("Segoe UI", 11)).pack()

style = ttk.Style()
style.theme_use("default")
style.configure("HAYO.TNotebook", background=BG, borderwidth=0)
style.configure("HAYO.TNotebook.Tab", background=BTN2, foreground=FG, padding=(14, 8), font=("Segoe UI", 10, "bold"))
style.map("HAYO.TNotebook.Tab", background=[("selected", ACC)], foreground=[("selected", BG)])
style.configure("HAYO.TCombobox", fieldbackground="#0a1730", background="#0a1730", foreground=ACC)

nb = ttk.Notebook(root, style="HAYO.TNotebook")
nb.pack(fill="both", expand=True, padx=14, pady=(12, 6))

tab_static = tk.Frame(nb, bg=BG)
tab_target = tk.Frame(nb, bg=BG)
tab_engines = tk.Frame(nb, bg=BG)
tab_advanced = tk.Frame(nb, bg=BG)
nb.add(tab_static, text="① التحليل الساكن")
nb.add(tab_target, text="② الهدف والجهاز")
nb.add(tab_engines, text="③ المحركات الديناميكية")
nb.add(tab_advanced, text="④ أدوات متقدمة")

def button(parent, text, cmd, color=BTN):
    b = tk.Button(parent, text=text, command=cmd, bg=color, fg=FG, activebackground=ACC,
                  activeforeground=BG, font=("Segoe UI", 11, "bold"), relief="flat", bd=0,
                  padx=10, pady=8, cursor="hand2")
    b.pack(fill="x", padx=16, pady=3)
    return b

def section(parent, title):
    tk.Label(parent, text=title, bg=BG, fg=ACC, font=("Segoe UI", 11, "bold")).pack(anchor="e", padx=16, pady=(12, 4))

# ---- tab ①
section(tab_static, "تحليل واستخراج + بناء")
button(tab_static, "🔎  حلّل واستخرج المفاتيح", on_analyze)
button(tab_static, "🔓  بناء APK موقّع (Premium)", on_unlock_build, BTN2)
button(tab_static, "🩹  ترقيع ساكن دائم (smali → isPremium=true)", on_static_patch, BTN_RED)
button(tab_static, "📲  تثبيت ذكي على المحاكي", on_install)
button(tab_static, "🩺  فحص وإصلاح البيئة (Setup Check)", on_setup_check, BTN2)

# ---- tab ②
section(tab_target, "الجهاز (Emulator / Device)")
dfrm = tk.Frame(tab_target, bg=BG); dfrm.pack(fill="x", padx=16)
dev_var = tk.StringVar(value=DEFAULT_DEV)
dev_combo = ttk.Combobox(dfrm, textvariable=dev_var, style="HAYO.TCombobox",
                          font=("Consolas", 11), state="readonly", values=[DEFAULT_DEV])
dev_combo.pack(side="left", fill="x", expand=True, ipady=4)
tk.Button(dfrm, text="تحديث الأجهزة", command=refresh_devices, bg=BTN2, fg=FG,
          relief="flat", font=("Segoe UI", 9, "bold"), cursor="hand2").pack(side="right", padx=(6, 0))

section(tab_target, "التطبيق المستهدف")
frm = tk.Frame(tab_target, bg=BG); frm.pack(fill="x", padx=16)
pkg_entry = tk.Entry(frm, font=("Consolas", 11), bg="#0a1730", fg=ACC, insertbackground=ACC, relief="flat")
pkg_entry.pack(side="left", fill="x", expand=True, ipady=6)
tk.Button(frm, text="تحديث القائمة", command=on_list_packages, bg=BTN2, fg=FG,
          relief="flat", font=("Segoe UI", 9, "bold"), cursor="hand2").pack(side="right", padx=(6, 0))

pkg_list = tk.Listbox(tab_target, height=10, bg="#0a1730", fg=ACC, font=("Consolas", 10),
                      selectbackground=ACC, selectforeground=BG, relief="flat", cursor="hand2")
pkg_list.pack(fill="both", expand=True, padx=16, pady=(5, 2))
pkg_list.bind("<<ListboxSelect>>", on_pick_pkg)
status = tk.Label(tab_target, text="", bg=BG, fg=ACC, font=("Segoe UI", 9, "bold"), anchor="e")
status.pack(fill="x", padx=16, pady=(0, 8))

# ---- tab ③
section(tab_engines, "المسار الموحد بقيادة AI (مباشر داخل اللوحة)")

# options row for the integrated pipeline
optfrm = tk.Frame(tab_engines, bg=BG); optfrm.pack(fill="x", padx=16, pady=(0, 2))
tk.Checkbutton(optfrm, text="🔬 البايبلاين الجديد (8 مراحل ذكية)", variable=USE_PIPELINE_VAR, 
                bg=BG, fg=ACC, selectcolor=BTN, activebackground=BG, activeforeground=ACC,
                font=("Segoe UI", 9, "bold"), cursor="hand2").pack(side="left")
tk.Checkbutton(optfrm, text="🪝 100+ Hooks (Ultimate)", variable=USE_ULTIMATE_HOOKS_VAR,
                bg=BG, fg=ACC, selectcolor=BTN, activebackground=BG, activeforeground=ACC,
                font=("Segoe UI", 9, "bold"), cursor="hand2").pack(side="right")

# duration row for the integrated pipeline
durfrm = tk.Frame(tab_engines, bg=BG); durfrm.pack(fill="x", padx=16, pady=(0, 2))
tk.Label(durfrm, text="مدة المرحلة الديناميكية (ثانية):", bg=BG, fg=FG,
         font=("Segoe UI", 9, "bold")).pack(side="right")
dur_var = tk.StringVar(value="180")
tk.Entry(durfrm, textvariable=dur_var, width=8, font=("Consolas", 11), bg="#0a1730",
         fg=ACC, insertbackground=ACC, relief="flat", justify="center").pack(side="right", padx=(0, 8), ipady=3)

run_pipeline_btn = button(tab_engines, RUN_BTN_TEXT, on_full_ai_pipeline, BTN_RED)
stop_pipeline_btn = button(tab_engines, "⏹  إيقاف المسار", on_stop_pipeline, BTN2)
stop_pipeline_btn.config(state="disabled")
tk.Label(tab_engines, text="يشغّل المحرك الساكن + الديناميكي + العقل المدبر + السحابة + الاستغلال ثم التقرير. "
         "البايبلاين الجديد يضيف: Pipeline Orchestrator, Working Memory, Real-time Decision, "
         "Live Data Extraction, Phase Manager Brain, Adaptive Exploitation, Feedback Loop. "
         "التقدّم يظهر في سجل الأسفل.",
         bg=BG, fg="#7fa8c9", font=("Segoe UI", 8), wraplength=680, justify="right").pack(anchor="e", padx=16, pady=(0, 4))

button(tab_engines, "🚀  المسار المبسّط في نافذة منفصلة (DeepSeek 3 مراحل)", on_deepseek_pipeline, BTN2)
button(tab_engines, "⚡  المسار الكامل الشامل (ساكنة + ديناميكية + AI + استغلال)", on_full_pipeline, BTN_RED)

section(tab_engines, "المحرّك الذكي (AI) - مع المكونات الجديدة")
button(tab_engines, "⚡  DeepSeek Core (استخراج + فكّ تشفير + فتح Premium تلقائي)", on_deepseek_core, BTN2)
button(tab_engines, "🧠  المحرّك الديناميكي الموحّد (DeepSeek يقود التطبيق)", on_deep_engine, BTN2)
button(tab_engines, "🔬  المحرّك الديناميكي (مع البايبلاين الجديد)", on_deep_engine_with_pipeline, BTN2)
button(tab_engines, "🧠  Phase Manager Brain (إدارة المراحل الذكية)", on_phase_manager, BTN2)
button(tab_engines, "⚡  Real-time Decision Engine (قرارات حية)", on_decision_engine, BTN2)
button(tab_engines, "🔍  Live Data Extraction (استخلاص حي)", on_data_extraction, BTN2)
button(tab_engines, "🎯  Adaptive Exploitation (استغلال تكيفي)", on_adaptive_exploit, BTN2)
button(tab_engines, "🔄  Feedback Loop (تحسين مستمر)", on_feedback_loop, BTN2)
section(tab_engines, "الهجوم الشامل والاعتراض")
button(tab_engines, "🔥  هجوم شامل (Full Assault)", on_full_assault, BTN_RED)
button(tab_engines, "☁️  اختراق السحابة (Cloud Assault)", on_cloud_assault, BTN2)
button(tab_engines, "💰  حقن الرموز (Token Heist)", on_token_heist, BTN2)
section(tab_engines, "الاعتراض والتصنت")
button(tab_engines, "🌐  اعتراض حركة المرور (Universal)", on_capture)
button(tab_engines, "🔬  اعتراض TLS الأصلي (Native)", on_capture_native)
button(tab_engines, "🕵️  اعتراض عميق (Deep Hijack)", on_hijack_deep)
button(tab_engines, "📡  مراقبة الواجهات الحساسة (Monitor)", on_monitor)
section(tab_engines, "فتح المزايا المدفوعة")
button(tab_engines, "🧪  فتح تلقائي شامل — جرّب كل الحيل (Auto)", on_auto_premium, BTN_RED)
button(tab_engines, "🧑‍💻  فتح مُساعَد — سجّل دخولك أثناء التشغيل (Live-Assisted)", on_auto_premium_assist, BTN_RED)
button(tab_engines, "🔑  تزوير/قلب رمز JWT (صلاحيات مميّزة)", on_jwt_forge, BTN2)
button(tab_engines, "🔓  فتح Premium (محلي)", on_unlock_local)
button(tab_engines, "🔓  فتح Premium (سحابي)", on_unlock_cloud)
button(tab_engines, "🔓  Hijack Premium", on_hijack_premium)
button(tab_engines, "☁️  Hijack Cloud", on_hijack_cloud)
section(tab_engines, "أدوات ملحقة")
button(tab_engines, "🎥  تسجيل الشاشة و Logcat", on_screen_rec)

# ---- tab ④
section(tab_advanced, "حقن وتنصت متقدم")
button(tab_advanced, "🪝  Mass Hook (كل العمليات)", on_mass_hook)
button(tab_advanced, "🧠  فحص الذاكرة (Memory Scanner)", on_memory_scan)
button(tab_advanced, "🥷  تجاوز الكشف (Evasion)", on_evasion, BTN2)
section(tab_advanced, "استخراج وتحكم عن بعد")
button(tab_advanced, "🗂️  استنساخ بيانات التطبيق (Data Clone)", on_data_clone)
button(tab_advanced, "🖥️  Reverse Shell", on_reverse_shell, BTN_RED)
button(tab_advanced, "📟  خادم C2", on_c2_server, BTN2)
button(tab_advanced, "🎛️  المنسق التفاعلي (Orchestrator)", on_orchestrator, BTN2)
button(tab_advanced, "🧠  Pipeline Orchestrator (منسق التسلسل)", on_pipeline_orchestrator, BTN2)
button(tab_advanced, "💾  Working Memory (الذاكرة المؤقتة)", on_working_memory, BTN2)

# ── حقل التعليمات التنفيذية للعقل المدبّر (يُطبّق على كل أزرار المحرّك) ──
dir_head = tk.Frame(root, bg=BG); dir_head.pack(fill="x", padx=14, pady=(2, 0))
tk.Label(dir_head, text="🎯 التعليمات التنفيذية للعقل (الهدف النهائي — ينفّذها بدقة):",
         bg=BG, fg=ACC, font=("Segoe UI", 9, "bold")).pack(side="right")
tk.Button(dir_head, text="استعادة الافتراضي", command=lambda: (directive_text.delete("1.0", tk.END),
          directive_text.insert("1.0", DEFAULT_GOAL)), bg=BTN2, fg=FG, relief="flat",
          font=("Segoe UI", 8, "bold"), cursor="hand2").pack(side="left")
directive_text = scrolledtext.ScrolledText(root, height=3, bg="#0a1730", fg=ACC,
         insertbackground=ACC, font=("Consolas", 10), relief="flat", wrap="word")
directive_text.pack(fill="x", padx=14, pady=(2, 6))
directive_text.insert("1.0", DEFAULT_GOAL)

log = scrolledtext.ScrolledText(root, height=6, bg="#060c1c", fg=FG, font=("Consolas", 9), relief="flat")
log.pack(fill="both", expand=False, padx=14, pady=(4, 14))
log.insert(tk.END, f"ADB: {ADB}\nPython: {PY}\nجارٍ فحص الأجهزة المتصلة...\n")

root.after(200, refresh_devices)
root.mainloop()

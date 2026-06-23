# HAYO — وكيل التحليل الديناميكي المرافق (Frida)

التحليل الديناميكي الحقيقي (تجاوز SSL pinning، استخراج المفاتيح والتوكنات وقت التشغيل،
رصد طلبات الشبكة) يحتاج جهازاً/محاكياً حقيقياً — وهذا **لا يعمل على الخادم السحابي**.
لذلك يعمل هذا الوكيل **على جهازك أنت** ضد **محاكيك**، ثم يُرسل النتائج للمنصة حيث
تُدمج مع التحليل الساكن في نفس الجلسة → تقرير هجين (ساكن + ديناميكي).

> ⚠️ **استخدام أخلاقي فقط:** اختبر تطبيقاتك أو تطبيقات فوّضك مالكها رسمياً باختبارها.

## كيف يعمل (الصورة الكاملة)
```
المنصة (سحابي)                         جهازك (محلي)
─────────────                          ────────────
1. ترفع APK → فكّ → sessionId
2. تفحص ساكناً (scanAndroid)
3. زر "بدء التحليل الديناميكي"
   → يصدر token + أمر التشغيل  ───────►  4. تشغّل agent.py على المحاكي
                                            (Frida يحقن الخطافات)
                                         5. تتفاعل مع التطبيق
   6. الوكيل يرسل النتائج  ◄───────────────  (POST /api/pentest/dynamic/<token>)
7. تُدمج وتظهر في التقرير
```

## ⚠️ ملاحظات حاسمة (تجنّبك ساعات من الأخطاء)
- **استخدم Frida 16 على Python 3.11/3.12** — Frida 17 أزال الكائن العام `Java` الذي يعتمد عليه السكربت، و Frida 16 لا توفّر عجلات لـ Python 3.14. على ويندوز:
  ```powershell
  py -3.12 -m pip install -r requirements.txt
  py -3.12 agent.py ...        # شغّل الوكيل بـ py -3.12 لا python
  ```
- **frida-server على الجهاز يجب أن يطابق إصدار frida** (16.7.19) **ومعماريته** (x86_64 لـ LDPlayer).
- يجب أن يعمل **frida-server بصلاحية الروت** (`su -c`)، وإلا يظهر خطأ «need Gadget / jailed».
- **تطبيقات ARM على LDPlayer (x86_64):** لا يمكن لـ frida-server x86_64 حقن تطبيق ARM يعمل عبر طبقة الترجمة (خطأ `gadget-android-arm64`). إن كان تطبيق الهدف ARM-only، استخدم محاكياً بمعمارية ARM (Android Studio AVD ARM / Genymotion ARM) أو جهازاً حقيقياً.

## المتطلبات (مرة واحدة)
1. **محاكي أندرويد** يعمل (LDPlayer مثلاً)، الرووت مُفعّل، و `adb devices` يُظهره.
2. ثبّت الأدوات و frida-server:
   ```powershell
   py -3.12 -m pip install -r requirements.txt
   py -3.12 -c "import frida; print(frida.__version__)"      # 16.7.19
   # نزّل frida-server-16.7.19-android-x86_64.xz من إصدارات Frida على GitHub وفكّ ضغطه
   adb push frida-server-16.7.19-android-x86_64 /sdcard/fs
   adb shell "su -c 'cp /sdcard/fs /data/local/tmp/frida-server && chmod 755 /data/local/tmp/frida-server'"
   adb shell "su -c '/data/local/tmp/frida-server'"          # اتركه يعمل (نافذة منفصلة)
   ```
3. ثبّت التطبيق الهدف على المحاكي.

## التشغيل
انسخ الأمر من زر **«بدء التحليل الديناميكي»** في المنصة (يحوي الرمز والخادم)، أو:
```powershell
py -3.12 agent.py --server https://your-app-url `
                  --token dyn_XXXXXXXXXXXX `
                  --package com.target.app `
                  --device emulator-5554 `
                  --spawn --duration 60
```
- `--device` مفيد عند وجود أكثر من جهاز (مثل هاتف حقيقي + محاكي)؛ يستهدف المحاكي بمعرّفه.
- `--spawn` يُطلق التطبيق من جديد (أفضل لالتقاط الإقلاع)؛ بدونها يُرفق بعملية قائمة.
- بعد ظهور «الخطافات نشطة» — **تفاعل مع التطبيق** (سجّل دخول، افتح الشاشات) ليُرصد أكبر قدر.
- عند الانتهاء تُرسَل النتائج تلقائياً وتُدمج في جلستك على المنصة.

## ما يرصده الوكيل وقت التشغيل
| النوع | ماذا يكشف |
|------|-----------|
| `ssl_pinning_bypassed` | تجاوز/ضعف تثبيت الشهادات (SSLContext / OkHttp CertificatePinner) |
| `ecb_at_runtime` / `weak_hash_runtime` | استخدام ECB أو MD5/SHA1 فعلياً وقت التشغيل |
| `static_key_runtime` | **مفتاح التشفير الفعلي** المُستخدَم (يُلتقط من الذاكرة) |
| `secret_captured` | توكنات/رؤوس Authorization مُرسَلة فعلياً |
| `cleartext_request` | طلب HTTP غير مشفّر فعلي |
| `webview_js_bridge` | استدعاء addJavascriptInterface فعلياً |
| `insecure_logging` | كتابة بيانات حسّاسة في SharedPreferences/Logcat |
| `dynamic_code_load` | تحميل شيفرة ديناميكي وقت التشغيل |

> ميزة الديناميكي على الساكن: يكشف الأسرار **حتى لو كان التطبيق مُعتّماً ومشفّراً**،
> لأنه يلتقط القيم الحقيقية في الذاكرة لحظة استخدامها.

## استكشاف الأخطاء
- *Failed to attach*: تأكّد أن frida-server يعمل (`adb shell ps | grep frida`) والتطبيق مفتوح.
- *عدم تطابق الإصدار*: frida (pip) و frida-server يجب أن يكونا بنفس الإصدار.
- *الرمز منتهٍ*: الرمز صالح ساعة واحدة — أنشئ رمزاً جديداً من المنصة.

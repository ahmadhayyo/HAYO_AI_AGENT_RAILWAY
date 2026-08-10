# HAYO AI — تطبيق أندرويد (WebView)

تطبيق أندرويد بسيط يفتح مباشرة على صفحة الأسواق المالية:
`https://hayoaiagentrailway-production.up.railway.app/trading`

- يفتح على الصفحة كتطبيق كامل الشاشة (بلا شريط متصفح).
- تسجيل الدخول (بريد/كلمة مرور) يعمل داخل التطبيق، والجلسة تُحفظ.
- زر الرجوع يتنقّل داخل التطبيق؛ الروابط الخارجية تُفتح في المتصفح.
- شارت TradingView يعمل داخل التطبيق.

## كيف تحصل على ملف APK (بلا برامج على جهازك)
1. ادفع هذا المجلد إلى GitHub (تم تلقائياً).
2. افتح **GitHub → تبويب Actions → "Build HAYO AI Android APK"**.
3. اضغط **Run workflow** (أو ينطلق تلقائياً عند تغيير `android-app/`).
4. بعد اكتماله، من صفحة التشغيل نزّل **Artifacts → `HAYO-AI-apk`** — بداخله `HAYO-AI.apk`.

## تثبيته على الجوال
1. انقل `HAYO-AI.apk` إلى الجوال (أو نزّله عليه مباشرة).
2. فعّل «تثبيت من مصادر غير معروفة» للمتصفح/مدير الملفات.
3. افتح الملف وثبّته. ستظهر أيقونة **HAYO AI**.

> هذا إصدار **debug موقّع بمفتاح التصحيح** — مناسب للتثبيت الشخصي/الإهداء (Sideload).
> للتوزيع على Google Play لاحقاً نحتاج توقيع **release** بمفتاحك الخاص (keystore) — أخبرني وأضيف خطوة التوقيع في الـWorkflow.

## البناء محلياً (اختياري)
يتطلب Android SDK + JDK 17:
```bash
cd android-app
gradle wrapper --gradle-version 8.7
./gradlew :app:assembleDebug
# الناتج: app/build/outputs/apk/debug/app-debug.apk
```

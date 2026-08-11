# HAYO Cipher-7 — تطبيق ويندوز (Desktop)

واجهة قيادة عصرية لسطح المكتب لمنصة HAYO Cipher-7، مبنية على Electron. تفتح شاشة تحكم فيها
شرح وأزرار لكل وحدة من وحدات المنصة، مع مؤشر حالة الخادم وتبديل بين بيئة الإنتاج والبيئة المحلية.

## المتطلبات
- Node.js 18+ و npm

## التشغيل أثناء التطوير
```bash
cd desktop
npm install
npm run icons   # توليد الأيقونة من assets/logo.svg
npm start
```

## بناء ملف exe لويندوز
```bash
cd desktop
npm install
npm run dist
```
الناتج في مجلد `desktop/release/`:
- **HAYO Cipher-7 Setup <version>.exe** — مثبِّت (NSIS) مع اختصار سطح المكتب وقائمة ابدأ.
- **HAYO-Cipher-7-Portable-<version>.exe** — نسخة محمولة تعمل بدون تثبيت.

## الأيقونة والشعار
الشعار المصدر في `assets/logo.svg`. سكربت `npm run icons` يولّد
`build/icon.ico` و `build/icon.png` تلقائيًا ويستخدمها المثبِّت وملف exe.

## البيئات
- **الإنتاج:** https://hayo-ai.com
- **محلي:** http://localhost:5173 (يمكن تعديله)

يُحفظ الاختيار في ملف إعدادات المستخدم. كل زر يفتح المسار المقابل من المنصة داخل نافذة التطبيق.

# مهمة تطوير ثورية — تعميق الالتقاط الديناميكي في HAYO Cipher-7

> **للوكيل المحلي:** اضبط الـ workspace على مجلد المحرك:
> `C:\Users\PT\Desktop\HAYO\HAYO_AI_AGENT_RAILWAY\artifacts\hayo ai-agent`
> ثم نفّذ هذه المهمة بأقصى عمق وإبداع.

---

## دورك ومهمتك

أنت مهندس أمن هجومي خبير في التحليل الديناميكي (Frida/Android). مهمتك: رفع محرّك
HAYO إلى مستوى **ثوري** في التقاط المفاتيح/الأسرار/الرموز **لحظة استخدامها في الذاكرة**،
بحيث يهزم التعتيم والتشفير وتثبيت الشهادات والتخزين المشفّر. لديك حرية كاملة للإبداع
والتوسّع أبعد من القائمة أدناه. النتائج تصل إلى التقرير تلقائياً ما دمت تحترم «عقد
ناقل الرسائل» — وهو الأنبوب الذي يوصل عملك، لا قيد عليك.

**ملفات العمل الأساسية:** `scripts/instrument_deep.js` (الأهم)، و`payloads/*.js`،
و`secret_hunter.py` (أنماط جديدة). لا تُعِد كتابة الملفات؛ أضف خطافات جديدة بدقّة.

---

## عقد ناقل الرسائل (إلزامي ليظهر أي اكتشاف)

كل اكتشاف من أي سكربت Frida يُرسَل حرفياً بهذه الصيغة:
```js
function emit(type, data){ try{ send({ type:"message", payload:
  Object.assign({ kind:"finding", type:type, ts:Date.now() }, data) }); }catch(e){} }
// استخدم: emit("crypto_key", { algo:"AES", key_b64:"…", key_hex:"…" });
```
- ضع `severity` اختيارياً (`critical`/`high`/`medium`)؛ يُستنتج تلقائياً من `type` إن غاب.
- ضع القيمة الخام في `evidence:[...]` أو حقول واضحة (key/token/url/value) — الصيّاد
  يمسحها لاحقاً.
- لِف **كل خطاف** بـ `try{…}catch(e){}` منفصل (خطاف فاشل لا يُسقط الباقي).
- استخدم `Java.perform(function(){ … })` للأصناف، و`Interceptor.attach` للأصلي.

---

## ترسانة الخطافات المطلوبة (نفّذها كلها + وسّع)

### 1) التشفير الأصلي (BoringSSL/OpenSSL) — الأهم لهزيمة إخفاء المفاتيح في C/C++
- حُلّ الدوال **لكل وحدة** (Android يمنع `Module.findExportByName(null, …)` بسبب
  linker namespaces): مرّ على `Process.enumerateModules()` وابحث في `libcrypto.so`/
  `libssl.so`/`libnative*.so`.
- خطافات: `EVP_EncryptInit_ex` / `EVP_DecryptInit_ex` (التقط key+IV من الوسائط)،
  `EVP_CipherUpdate` (نص صريح/مشفّر)، `AES_set_encrypt_key`، `RSA_private_decrypt`،
  `HMAC_Init_ex`، `PKCS5_PBKDF2_HMAC` (كلمات المرور المشتقّة).

### 2) Android KeyStore وطبقة التشفير Java
- `javax.crypto.Cipher.init` و`doFinal` (key.getEncoded + النص)، `SecretKeySpec.$init`
  (المادة الخام)، `IvParameterSpec`، `Mac.init`، `KeyGenParameterSpec$Builder`،
  `KeyStore.load/getKey/getEntry`، `SecretKeyFactory.generateSecret`، `PBEKeySpec`.

### 3) هزيمة التعتيم (فكّ السلاسل وقت التشغيل)
- `new String([B)` و`new String([B, java.nio.charset.Charset)` (السلاسل المفكوكة)،
  `java.util.Base64$Decoder.decode`، `android.util.Base64.decode/encode`،
  `java.lang.reflect.Method.invoke` (رشّح النتائج التي تشبه مفاتيح/URLs).

### 4) الشبكة بعرض كامل (بعد فكّ TLS)
- OkHttp: `Interceptor.intercept` (Request+Response)، `Response.body().string()`،
  `RealCall.execute`. Retrofit، Volley (`com.android.volley`)، Ktor (`io.ktor.*`)،
  Apache `HttpClient`، `HttpsURLConnection` (getRequestProperty/getHeaderFields/بايتات
  الـ stream). التقط ترويسات `Authorization`/`Cookie`/`X-Api-Key` + الأجسام.
- WebSocket frames (`WebSocketListener.onMessage`)، وgRPC metadata إن وُجد.

### 5) التخزين بعرض كامل
- `SharedPreferences.getString/putString` و**EncryptedSharedPreferences** (بعد الفكّ)،
  Jetpack `DataStore`، `SQLiteDatabase.rawQuery/execSQL`، **SQLCipher**
  (`openOrCreateDatabase` وسيط المفتاح)، Realm `encryptionKey`، قراءة ملفات
  `getFilesDir()`.

### 6) رموز السحابة وFirebase
- `FirebaseAuth.getAccessToken`/`getIdToken`، `GetTokenResult.getToken`،
  `FirebaseInstallations.getToken`، `FirebaseRemoteConfig.getString`،
  `GoogleSignInAccount.getIdToken/getServerAuthCode`، `AccountManager.getAuthToken`.

### 7) تجاوز عالمي لتثبيت الشهادات ومكافحة العبث (ليصل عملك للحركة المحمية)
- `X509TrustManager.checkServerTrusted` (no-op)، OkHttp `CertificatePinner.check`
  (no-op)، `com.android.org.conscrypt.TrustManagerImpl.verifyChain`، وأصلياً
  `SSL_CTX_set_custom_verify`/`SSL_set_verify`. وتجاوز فحوص الجذر الشائعة لإبقاء
  التطبيق يعمل. **أبلغ عن كل تجاوز كـ finding (type: `ssl_unpin`/`root_bypass`).**

### 8) قنوات التسريب
- Clipboard (`ClipboardManager.setPrimaryClip/getPrimaryClip`)، `Intent` extras،
  `ContentResolver.query`، `android.util.Log.*` (أسرار مُسجَّلة)،
  `WebView.evaluateJavascript/addJavascriptInterface`.

### 9) ماسح الذاكرة v2 (مفاتيح مُصادَق عليها فقط)
- مسح دوري لكومة Java عن سلاسل تطابق `AIza…`/`AKIA…`/`sk_live_…`/`eyJ…`/PEM/
  `firebase`/`.supabase.co` — **استخرج القيمة المطابقة فقط**، لا أسماء الأصناف
  (تفادَ ضجيج `*_class` — لا تُصدره أبداً كـ finding).

### 10) أنماط الصيّاد (`secret_hunter.py`)
- لأي نوع مزوّد جديد تكتشفه: أضف سطر regex في قاموس `HIGH_CONFIDENCE` فقط، مع
  الحفاظ على مرشّحات `_plausible`/`_looks_wordy` (درع المصداقية ضد الإيجابيات الكاذبة).

---

## تعريف «تمّ بنجاح» (تحقّق ذاتي)

1. `python -m py_compile secret_hunter.py` (وأي .py عدّلته) — بلا أخطاء.
2. تشغيل حيّ قصير يؤكّد أن خطافاتك تُطلق نتائج ويُكتب تقرير بلا انهيار:
   ```
   python dynamic_engine.py --package <حزمة_مثبتة> --device emulator-5554 --duration 60
   ```
   يجب أن ترى `[+] [severity] <type> …` لأنواعك الجديدة، وسطر `[ready]`، وتقريراً في
   `loot/deep_*.md`. لا نتائج بصيغة غير العقد (وإلا تُهمَل بصمت).
3. لا إيجابيات كاذبة: تأكّد أن أسماء الأصناف/كائنات Java/ميزات الـ SDK لا تظهر كأسرار.
4. خذ نسخة احتياطية قبل التعديل: `cp scripts/instrument_deep.js scripts/instrument_deep.BACKUP.js`.

---

## ما يجب أن يعمل بحذر جراحي (عدّل بدقّة، لا تُعِد كتابة)

`intel_store.py` (قلب المخزن)، `dynamic_engine.py::_on_message` وحلقة `run`،
`hayo_pipeline.py` و`_goal_reached`، `llm_brain.py` (سلسلة المزوّدات)، وملفات `.bat`
و`HAYO-GUI.pyw` (أسلاك الأزرار). أضف فوقها بحرية، ولا تكسر عقودها.

**سلّم:** تغييرات مركّزة + قائمة بالأنواع الجديدة التي أضفتها + نتيجة التحقّق الذاتي.

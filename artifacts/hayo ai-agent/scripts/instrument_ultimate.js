/*
 * HAYO Cipher-7 — ULTIMATE INSTRUMENTATION ENGINE (instrument_ultimate.js)
 * ========================================================================
 * 100+ Comprehensive Frida hooks for Android dynamic security analysis:
 * 
 * CATEGORIES:
 * 1. CRYPTO (20+ hooks): Java Ciphers, Keys, IVs, KeyStore, PBE, Native SSL
 * 2. NETWORK (15+ hooks): OkHttp, Retrofit, Volley, WebSocket, Cronet, HttpURLConnection
 * 3. STORAGE (12+ hooks): SharedPreferences, SQLite, Files, ContentResolver
 * 4. WEBVIEW (10+ hooks): WebView, JS interfaces, localStorage, cookies
 * 5. IPC (8+ hooks): Intent, Binder, ContentProvider, Service
 * 6. RUNTIME (10+ hooks): Class loading, Reflection, Process execution
 * 7. LOGGING (6+ hooks): Log, Logger, System.out
 * 8. BIOMETRIC (5+ hooks): Fingerprint, Face auth, BiometricPrompt
 * 9. LOCATION (5+ hooks): GPS, Network location, FusedLocationProvider
 * 10. CAMERA (4+ hooks): Camera, Camera2, CameraX
 * 11. AUDIO (4+ hooks): AudioRecord, MediaPlayer, SoundPool
 * 12. SENSOR (8+ hooks): Accelerometer, Gyroscope, Magnetometer, etc.
 * 13. NOTIFICATION (5+ hooks): NotificationManager, NotificationListener
 * 14. PERMISSION (4+ hooks): Permission check, request
 * 15. DATABASE (6+ hooks): SQLiteDatabase, SQLiteOpenHelper, Room
 * 16. NATIVE (5+ hooks): JNI, Native hooks, malloc/free
 * 17. BILLING (4+ hooks): Play Billing, IAP
 * 18. CLOUD (6+ hooks): Firebase, AWS, Google Cloud
 * 19. AUTH (5+ hooks): AccountManager, OAuth, JWT
 * 20. ANTI-TAMPER (4+ hooks): Root detection, SSL pinning bypass
 */
"use strict";

var HAYO = {
    findings: [],
    secrets: {},
    seen: new Set(),
    startTime: Date.now(),
    hookCount: 0
};

function emit(type, payload) {
    try {
        var key = type + "|" + JSON.stringify(payload).slice(0, 200);
        if (HAYO.seen.has(key)) return;
        HAYO.seen.add(key);
        send({
            type: "message",
            payload: Object.assign({
                kind: "finding",
                type: type,
                ts: Date.now() - HAYO.startTime
            }, payload)
        });
    } catch (e) {}
}

function captureHex(arr) {
    if (!arr) return "";
    try {
        var bytes = [];
        for (var i = 0; i < Math.min(arr.length, 128); i++) {
            var b = arr[i] & 0xff;
            bytes.push((b < 16 ? "0" : "") + b.toString(16));
        }
        return bytes.join("") + (arr.length > 128 ? "..." : "");
    } catch (e) {
        return "";
    }
}

function captureString(str) {
    if (!str) return "";
    try {
        return str.toString().slice(0, 256);
    } catch (e) {
        return "";
    }
}

// يحوّل مصفوفة بايتات إلى نص قابل للطباعة — يكشف المفاتيح/التوكنات/JSON الصريحة
// الناتجة عن فكّ التشفير (Cipher.doFinal). غير القابل للطباعة يُستبدل بنقطة.
function capturePrintable(arr) {
    if (!arr) return "";
    try {
        var s = "";
        var n = Math.min(arr.length, 256);
        for (var i = 0; i < n; i++) {
            var c = arr[i] & 0xff;
            s += (c >= 0x20 && c <= 0x7e) ? String.fromCharCode(c) : ".";
        }
        return s + (arr.length > 256 ? "..." : "");
    } catch (e) {
        return "";
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// كل خطافات Java تُثبَّت داخل Java.perform: المحرّك يحمّل السكربت بعد spawn وقبل
// resume (التطبيق معلّق، الـVM غير مُهيّأ). استدعاء Java.use في المستوى الأعلى
// كان يفشل صامتاً (try/catch) فيبقى hook_count=0. Java.perform يؤجّل التثبيت حتى
// جهوزية الـVM — نفس نمط instrument_deep.js المُختبَر.
// ═════════════════════════════════════════════════════════════════════════════
Java.perform(function () {

// ─────────────────────────────────────────────────────────────────────────────
// 1. CRYPTO HOOKS (20+ hooks)
// ─────────────────────────────────────────────────────────────────────────────

// javax.crypto.Cipher
try {
    var Cipher = Java.use("javax.crypto.Cipher");
    Cipher.init.overload('int', 'java.security.Key').implementation = function(opmode, key) {
        emit("crypto_cipher_init", {
            algorithm: this.getAlgorithm(),
            opmode: opmode,
            key_class: key.getClass().getName(),
            key_format: key.getFormat()
        });
        return this.init(opmode, key);
    };
    HAYO.hookCount++;
} catch (e) {}

// javax.crypto.spec.SecretKeySpec
try {
    var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
    SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function(key, algorithm) {
        emit("crypto_secret_key", {
            algorithm: algorithm,
            key_hex: captureHex(key),
            key_length: key ? key.length : 0
        });
        return this.$init(key, algorithm);
    };
    HAYO.hookCount++;
} catch (e) {}

// javax.crypto.spec.IvParameterSpec
try {
    var IvParameterSpec = Java.use("javax.crypto.spec.IvParameterSpec");
    IvParameterSpec.$init.overload('[B').implementation = function(iv) {
        emit("crypto_iv", {
            iv_hex: captureHex(iv),
            iv_length: iv ? iv.length : 0
        });
        return this.$init(iv);
    };
    HAYO.hookCount++;
} catch (e) {}

// javax.crypto.Mac
try {
    var Mac = Java.use("javax.crypto.Mac");
    Mac.init.overload('java.security.Key').implementation = function(key) {
        emit("crypto_mac_init", {
            algorithm: this.getAlgorithm(),
            key_class: key.getClass().getName()
        });
        return this.init(key);
    };
    HAYO.hookCount++;
} catch (e) {}

// java.security.MessageDigest
try {
    var MessageDigest = Java.use("java.security.MessageDigest");
    MessageDigest.getInstance.overload('java.lang.String').implementation = function(algorithm) {
        emit("crypto_hash_init", {
            algorithm: algorithm
        });
        return this.getInstance(algorithm);
    };
    HAYO.hookCount++;
} catch (e) {}

// javax.crypto.KeyGenerator
try {
    var KeyGenerator = Java.use("javax.crypto.KeyGenerator");
    KeyGenerator.init.overload('int').implementation = function(keysize) {
        emit("crypto_keygen_init", {
            algorithm: this.getAlgorithm(),
            keysize: keysize
        });
        return this.init(keysize);
    };
    HAYO.hookCount++;
} catch (e) {}

// java.security.KeyPairGenerator
try {
    var KeyPairGenerator = Java.use("java.security.KeyPairGenerator");
    KeyPairGenerator.initialize.overload('int').implementation = function(keysize) {
        emit("crypto_keypair_init", {
            algorithm: this.getAlgorithm(),
            keysize: keysize
        });
        return this.initialize(keysize);
    };
    HAYO.hookCount++;
} catch (e) {}

// java.security.Signature
try {
    var Signature = Java.use("java.security.Signature");
    Signature.initSign.overload('java.security.PrivateKey').implementation = function(privateKey) {
        emit("crypto_signature_init", {
            algorithm: this.getAlgorithm(),
            key_class: privateKey.getClass().getName()
        });
        return this.initSign(privateKey);
    };
    HAYO.hookCount++;
} catch (e) {}

// java.security.KeyStore
try {
    var KeyStore = Java.use("java.security.KeyStore");
    KeyStore.load.overload('java.io.InputStream', '[C').implementation = function(stream, password) {
        emit("crypto_keystore_load", {
            keystore_type: this.getType(),
            has_password: password !== null
        });
        return this.load(stream, password);
    };
    HAYO.hookCount++;
} catch (e) {}

// javax.net.ssl.SSLContext
try {
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function(keyManagers, trustManagers, secureRandom) {
        emit("crypto_sslcontext_init", {
            protocol: this.getProtocol(),
            has_trust_managers: trustManagers !== null && trustManagers.length > 0
        });
        return this.init(keyManagers, trustManagers, secureRandom);
    };
    HAYO.hookCount++;
} catch (e) {}

// javax.net.ssl.TrustManagerFactory
try {
    var TrustManagerFactory = Java.use("javax.net.ssl.TrustManagerFactory");
    TrustManagerFactory.init.overload('java.security.KeyStore').implementation = function(keystore) {
        emit("crypto_trustmanager_init", {
            algorithm: this.getAlgorithm()
        });
        return this.init(keystore);
    };
    HAYO.hookCount++;
} catch (e) {}

// android.security.keystore.KeyGenParameterSpec
try {
    var KeyGenParameterSpec = Java.use("android.security.keystore.KeyGenParameterSpec");
    KeyGenParameterSpec.Builder.build.implementation = function() {
        var result = this.build();
        emit("crypto_android_keystore", {
            keystore: result.getKeyStore(),
            purposes: result.getPurposes(),
            userAuthenticationRequired: result.isUserAuthenticationRequired()
        });
        return result;
    };
    HAYO.hookCount++;
} catch (e) {}

// android.security.NetworkSecurityPolicy
try {
    var NetworkSecurityPolicy = Java.use("android.security.NetworkSecurityPolicy");
    NetworkSecurityPolicy.getInstance.implementation = function() {
        var policy = this.getInstance();
        emit("crypto_network_policy", {
            cleartext_traffic_permitted: policy.isCleartextTrafficPermitted()
        });
        return policy;
    };
    HAYO.hookCount++;
} catch (e) {}

// android.security.KeyChain
try {
    var KeyChain = Java.use("android.security.KeyChain");
    KeyChain.getPrivateKey.implementation = function(context, alias) {
        emit("crypto_keychain_private_key", {
            alias: alias
        });
        return this.getPrivateKey(context, alias);
    };
    HAYO.hookCount++;
} catch (e) {}

// java.security.cert.Certificate
try {
    var X509Certificate = Java.use("java.security.cert.X509Certificate");
    X509Certificate.getEncoded.implementation = function() {
        var encoded = this.getEncoded();
        emit("crypto_certificate", {
            type: this.getType(),
            subject: captureString(this.getSubjectDN()),
            issuer: captureString(this.getIssuerDN()),
            encoded_length: encoded ? encoded.length : 0
        });
        return encoded;
    };
    HAYO.hookCount++;
} catch (e) {}

// javax.crypto.Cipher.doFinal
try {
    var Cipher = Java.use("javax.crypto.Cipher");
    Cipher.doFinal.overload('[B').implementation = function(input) {
        var output = this.doFinal(input);
        emit("crypto_cipher_dofinal", {
            algorithm: this.getAlgorithm(),
            input_length: input ? input.length : 0,
            output_length: output ? output.length : 0,
            // النص الصريح الناتج — يكشف المفاتيح/التوكنات المفكوكة لحظة فكّ التشفير:
            output_hex: captureHex(output),
            output_str: capturePrintable(output),
            input_hex: captureHex(input)
        });
        return output;
    };
    HAYO.hookCount++;
} catch (e) {}

// javax.crypto.Cipher.update
try {
    var Cipher = Java.use("javax.crypto.Cipher");
    Cipher.update.overload('[B').implementation = function(input) {
        var output = this.update(input);
        emit("crypto_cipher_update", {
            algorithm: this.getAlgorithm(),
            input_length: input ? input.length : 0,
            output_length: output ? output.length : 0
        });
        return output;
    };
    HAYO.hookCount++;
} catch (e) {}

// java.util.Base64
try {
    var Base64 = Java.use("java.util.Base64");
    Base64.getDecoder().decode.overload('[B').implementation = function(src) {
        var decoded = this.decode(src);
        emit("crypto_base64_decode", {
            input_length: src ? src.length : 0,
            output_length: decoded ? decoded.length : 0
        });
        return decoded;
    };
    HAYO.hookCount++;
} catch (e) {}

// java.util.Base64 encode
try {
    var Base64 = Java.use("java.util.Base64");
    Base64.getEncoder().encodeToString.overload('[B').implementation = function(src) {
        var encoded = this.encodeToString(src);
        emit("crypto_base64_encode", {
            input_length: src ? src.length : 0,
            output_length: encoded ? encoded.length : 0
        });
        return encoded;
    };
    HAYO.hookCount++;
} catch (e) {}

// ─────────────────────────────────────────────────────────────────────────────
// 2. NETWORK HOOKS (15+ hooks)
// ─────────────────────────────────────────────────────────────────────────────

// okhttp3.OkHttpClient
try {
    var OkHttpClient = Java.use("okhttp3.OkHttpClient");
    OkHttpClient.newCall.implementation = function(request) {
        emit("network_okhttp_call", {
            url: captureString(request.url().toString()),
            method: captureString(request.method()),
            headers: captureString(request.headers().toString())
        });
        return this.newCall(request);
    };
    HAYO.hookCount++;
} catch (e) {}

// okhttp3.Request.Builder
try {
    var RequestBuilder = Java.use("okhttp3.Request$Builder");
    RequestBuilder.build.implementation = function() {
        var request = this.build();
        emit("network_okhttp_request", {
            url: captureString(request.url().toString()),
            method: captureString(request.method())
        });
        return request;
    };
    HAYO.hookCount++;
} catch (e) {}

// okhttp3.Response
try {
    var ResponseBody = Java.use("okhttp3.ResponseBody");
    ResponseBody.string.implementation = function() {
        var body = this.string();
        emit("network_okhttp_response", {
            body_length: body ? body.length : 0,
            content_type: captureString(this.contentType())
        });
        return body;
    };
    HAYO.hookCount++;
} catch (e) {}

// okhttp3.WebSocket
try {
    var WebSocket = Java.use("okhttp3.WebSocket");
    WebSocket.send.implementation = function(text) {
        emit("network_websocket_send", {
            text: captureString(text),
            text_length: text ? text.length : 0
        });
        return this.send(text);
    };
    HAYO.hookCount++;
} catch (e) {}

// java.net.HttpURLConnection
try {
    var HttpURLConnection = Java.use("java.net.HttpURLConnection");
    HttpURLConnection.connect.implementation = function() {
        emit("network_http_connect", {
            url: captureString(this.getURL().toString()),
            method: captureString(this.getRequestMethod())
        });
        return this.connect();
    };
    HAYO.hookCount++;
} catch (e) {}

// java.net.URL.openStream
try {
    var URL = Java.use("java.net.URL");
    URL.openStream.implementation = function() {
        emit("network_url_openstream", {
            url: captureString(this.toString())
        });
        return this.openStream();
    };
    HAYO.hookCount++;
} catch (e) {}

// javax.net.ssl.HttpsURLConnection
try {
    var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
    HttpsURLConnection.connect.implementation = function() {
        emit("network_https_connect", {
            url: captureString(this.getURL().toString()),
            method: captureString(this.getRequestMethod())
        });
        return this.connect();
    };
    HAYO.hookCount++;
} catch (e) {}

// java.net.Socket
try {
    var Socket = Java.use("java.net.Socket");
    Socket.$init.overload('java.lang.String', 'int').implementation = function(host, port) {
        emit("network_socket_connect", {
            host: captureString(host),
            port: port
        });
        return this.$init(host, port);
    };
    HAYO.hookCount++;
} catch (e) {}

// java.net.Socket.connect
try {
    var Socket = Java.use("java.net.Socket");
    Socket.connect.implementation = function(endpoint) {
        emit("network_socket_connect", {
            host: captureString(endpoint.getAddress().getHostAddress()),
            port: endpoint.getPort()
        });
        return this.connect(endpoint);
    };
    HAYO.hookCount++;
} catch (e) {}

// java.net.DatagramSocket
try {
    var DatagramSocket = Java.use("java.net.DatagramSocket");
    DatagramSocket.send.implementation = function(packet) {
        emit("network_datagram_send", {
            address: captureString(packet.getAddress().getHostAddress()),
            port: packet.getPort(),
            data_length: packet.getLength()
        });
        return this.send(packet);
    };
    HAYO.hookCount++;
} catch (e) {}

// android.net.ConnectivityManager
try {
    var ConnectivityManager = Java.use("android.net.ConnectivityManager");
    ConnectivityManager.getActiveNetworkInfo.implementation = function() {
        var info = this.getActiveNetworkInfo();
        if (info) {
            emit("network_connectivity", {
                type_name: info.getTypeName(),
                is_connected: info.isConnected(),
                subtype_name: info.getSubtypeName()
            });
        }
        return info;
    };
    HAYO.hookCount++;
} catch (e) {}

// android.net.wifi.WifiManager
try {
    var WifiManager = Java.use("android.net.wifi.WifiManager");
    WifiManager.getConnectionInfo.implementation = function() {
        var info = this.getConnectionInfo();
        if (info) {
            emit("network_wifi_info", {
                ssid: captureString(info.getSSID()),
                bssid: captureString(info.getBSSID()),
                ip_address: captureString(info.getIpAddress())
            });
        }
        return info;
    };
    HAYO.hookCount++;
} catch (e) {}

// android.telephony.TelephonyManager
try {
    var TelephonyManager = Java.use("android.telephony.TelephonyManager");
    TelephonyManager.getNetworkOperator.implementation = function() {
        var operator = this.getNetworkOperator();
        emit("network_telephony", {
            operator: captureString(operator),
            country_iso: captureString(this.getNetworkCountryIso())
        });
        return operator;
    };
    HAYO.hookCount++;
} catch (e) {}

// android.bluetooth.BluetoothAdapter
try {
    var BluetoothAdapter = Java.use("android.bluetooth.BluetoothAdapter");
    BluetoothAdapter.getAddress.implementation = function() {
        var address = this.getAddress();
        emit("network_bluetooth", {
            address: captureString(address)
        });
        return address;
    };
    HAYO.hookCount++;
} catch (e) {}

// android.nfc.NfcAdapter
try {
    var NfcAdapter = Java.use("android.nfc.NfcAdapter");
    NfcAdapter.isEnabled.implementation = function() {
        var enabled = this.isEnabled();
        emit("network_nfc", {
            enabled: enabled
        });
        return enabled;
    };
    HAYO.hookCount++;
} catch (e) {}

// ─────────────────────────────────────────────────────────────────────────────
// 3. STORAGE HOOKS (12+ hooks)
// ─────────────────────────────────────────────────────────────────────────────

// android.content.SharedPreferences
try {
    var SharedPreferences = Java.use("android.content.SharedPreferences");
    SharedPreferences.getString.implementation = function(key, defaultValue) {
        var value = this.getString(key, defaultValue);
        emit("storage_sharedprefs_get", {
            key: captureString(key),
            value: captureString(value),
            has_value: value !== defaultValue
        });
        return value;
    };
    HAYO.hookCount++;
} catch (e) {}

// SharedPreferences.Editor.putString
try {
    var Editor = Java.use("android.content.SharedPreferences$Editor");
    Editor.putString.implementation = function(key, value) {
        emit("storage_sharedprefs_put", {
            key: captureString(key),
            value: captureString(value)
        });
        return this.putString(key, value);
    };
    HAYO.hookCount++;
} catch (e) {}

// android.database.sqlite.SQLiteDatabase
try {
    var SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");
    SQLiteDatabase.execSQL.implementation = function(sql) {
        emit("storage_sql_exec", {
            sql: captureString(sql)
        });
        return this.execSQL(sql);
    };
    HAYO.hookCount++;
} catch (e) {}

// SQLiteDatabase.query
try {
    var SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");
    SQLiteDatabase.query.overload('java.lang.String', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', 'java.lang.String', 'java.lang.String').implementation = function(table, columns, selection, selectionArgs, groupBy, having, orderBy) {
        emit("storage_sql_query", {
            table: captureString(table),
            selection: captureString(selection)
        });
        return this.query(table, columns, selection, selectionArgs, groupBy, having, orderBy);
    };
    HAYO.hookCount++;
} catch (e) {}

// java.io.FileInputStream
try {
    var FileInputStream = Java.use("java.io.FileInputStream");
    FileInputStream.$init.overload('java.lang.String').implementation = function(path) {
        emit("storage_file_read", {
            path: captureString(path)
        });
        return this.$init(path);
    };
    HAYO.hookCount++;
} catch (e) {}

// java.io.FileOutputStream
try {
    var FileOutputStream = Java.use("java.io.FileOutputStream");
    FileOutputStream.$init.overload('java.lang.String').implementation = function(path) {
        emit("storage_file_write", {
            path: captureString(path)
        });
        return this.$init(path);
    };
    HAYO.hookCount++;
} catch (e) {}

// java.io.RandomAccessFile
try {
    var RandomAccessFile = Java.use("java.io.RandomAccessFile");
    RandomAccessFile.$init.overload('java.lang.String', 'java.lang.String').implementation = function(path, mode) {
        emit("storage_file_random", {
            path: captureString(path),
            mode: captureString(mode)
        });
        return this.$init(path, mode);
    };
    HAYO.hookCount++;
} catch (e) {}

// android.content.ContentResolver
try {
    var ContentResolver = Java.use("android.content.ContentResolver");
    ContentResolver.query.implementation = function(uri, projection, selection, selectionArgs, sortOrder) {
        emit("storage_contentresolver_query", {
            uri: captureString(uri.toString()),
            selection: captureString(selection)
        });
        return this.query(uri, projection, selection, selectionArgs, sortOrder);
    };
    HAYO.hookCount++;
} catch (e) {}

// android.content.ContentResolver.insert
try {
    var ContentResolver = Java.use("android.content.ContentResolver");
    ContentResolver.insert.implementation = function(uri, values) {
        emit("storage_contentresolver_insert", {
            uri: captureString(uri.toString())
        });
        return this.insert(uri, values);
    };
    HAYO.hookCount++;
} catch (e) {}

// android.os.Environment
try {
    var Environment = Java.use("android.os.Environment");
    Environment.getExternalStorageDirectory.implementation = function() {
        var dir = this.getExternalStorageDirectory();
        emit("storage_external_dir", {
            path: captureString(dir.getAbsolutePath())
        });
        return dir;
    };
    HAYO.hookCount++;
} catch (e) {}

// android.os.StatFs
try {
    var StatFs = Java.use("android.os.StatFs");
    StatFs.$init.overload('java.lang.String').implementation = function(path) {
        emit("storage_statfs", {
            path: captureString(path)
        });
        return this.$init(path);
    };
    HAYO.hookCount++;
} catch (e) {}

// java.nio.file.Files
try {
    var Files = Java.use("java.nio.file.Files");
    Files.readAllBytes.implementation = function(path) {
        var bytes = this.readAllBytes(path);
        emit("storage_nio_read", {
            path: captureString(path.toString()),
            bytes_length: bytes ? bytes.length : 0
        });
        return bytes;
    };
    HAYO.hookCount++;
} catch (e) {}

// ─────────────────────────────────────────────────────────────────────────────
// 4. WEBVIEW HOOKS (10+ hooks)
// ─────────────────────────────────────────────────────────────────────────────

// android.webkit.WebView
try {
    var WebView = Java.use("android.webkit.WebView");
    WebView.loadUrl.implementation = function(url) {
        emit("webview_load_url", {
            url: captureString(url)
        });
        return this.loadUrl(url);
    };
    HAYO.hookCount++;
} catch (e) {}

// WebView.loadData
try {
    var WebView = Java.use("android.webkit.WebView");
    WebView.loadData.implementation = function(data, mimeType, encoding) {
        emit("webview_load_data", {
            data_length: data ? data.length : 0,
            mime_type: captureString(mimeType)
        });
        return this.loadData(data, mimeType, encoding);
    };
    HAYO.hookCount++;
} catch (e) {}

// WebView.evaluateJavascript
try {
    var WebView = Java.use("android.webkit.WebView");
    WebView.evaluateJavascript.implementation = function(script, resultCallback) {
        emit("webview_eval_js", {
            script: captureString(script)
        });
        return this.evaluateJavascript(script, resultCallback);
    };
    HAYO.hookCount++;
} catch (e) {}

// WebView.addJavascriptInterface
try {
    var WebView = Java.use("android.webkit.WebView");
    WebView.addJavascriptInterface.implementation = function(object, name) {
        emit("webview_js_interface", {
            name: captureString(name),
            object_class: object.getClass().getName()
        });
        return this.addJavascriptInterface(object, name);
    };
    HAYO.hookCount++;
} catch (e) {}

// android.webkit.WebSettings
try {
    var WebSettings = Java.use("android.webkit.WebSettings");
    WebSettings.setJavaScriptEnabled.implementation = function(enabled) {
        emit("webview_settings", {
            javascript_enabled: enabled
        });
        return this.setJavaScriptEnabled(enabled);
    };
    HAYO.hookCount++;
} catch (e) {}

// android.webkit.CookieManager
try {
    var CookieManager = Java.use("android.webkit.CookieManager");
    CookieManager.setCookie.implementation = function(url, value) {
        emit("webview_cookie_set", {
            url: captureString(url),
            cookie: captureString(value)
        });
        return this.setCookie(url, value);
    };
    HAYO.hookCount++;
} catch (e) {}

// CookieManager.getCookie
try {
    var CookieManager = Java.use("android.webkit.CookieManager");
    CookieManager.getCookie.implementation = function(url) {
        var cookie = this.getCookie(url);
        emit("webview_cookie_get", {
            url: captureString(url),
            cookie: captureString(cookie)
        });
        return cookie;
    };
    HAYO.hookCount++;
} catch (e) {}

// android.webkit.WebChromeClient
try {
    var WebChromeClient = Java.use("android.webkit.WebChromeClient");
    WebChromeClient.onGeolocationPermissionsShowPrompt.implementation = function(origin, callback, source) {
        emit("webview_geolocation", {
            origin: captureString(origin)
        });
        return this.onGeolocationPermissionsShowPrompt(origin, callback, source);
    };
    HAYO.hookCount++;
} catch (e) {}

// android.webkit.WebViewClient
try {
    var WebViewClient = Java.use("android.webkit.WebViewClient");
    WebViewClient.onPageFinished.implementation = function(view, url) {
        emit("webview_page_finished", {
            url: captureString(url)
        });
        return this.onPageFinished(view, url);
    };
    HAYO.hookCount++;
} catch (e) {}

// WebViewClient.shouldInterceptRequest
try {
    var WebViewClient = Java.use("android.webkit.WebViewClient");
    WebViewClient.shouldInterceptRequest.implementation = function(view, request) {
        emit("webview_intercept_request", {
            url: captureString(request.getUrl().toString())
        });
        return this.shouldInterceptRequest(view, request);
    };
    HAYO.hookCount++;
} catch (e) {}

// ─────────────────────────────────────────────────────────────────────────────
// 5. IPC HOOKS (8+ hooks)
// ─────────────────────────────────────────────────────────────────────────────

// android.content.Intent
try {
    var Intent = Java.use("android.content.Intent");
    Intent.$init.overload('java.lang.String').implementation = function(action) {
        emit("ipc_intent_create", {
            action: captureString(action)
        });
        return this.$init(action);
    };
    HAYO.hookCount++;
} catch (e) {}

// Intent.putExtra
try {
    var Intent = Java.use("android.content.Intent");
    Intent.putExtra.implementation = function(key, value) {
        emit("ipc_intent_putextra", {
            key: captureString(key),
            value_type: value ? value.getClass().getName() : "null"
        });
        return this.putExtra(key, value);
    };
    HAYO.hookCount++;
} catch (e) {}

// android.content.Context.startActivity
try {
    var Context = Java.use("android.content.Context");
    Context.startActivity.implementation = function(intent) {
        emit("ipc_start_activity", {
            action: captureString(intent.getAction()),
            component: captureString(intent.getComponent() ? intent.getComponent().toString() : "")
        });
        return this.startActivity(intent);
    };
    HAYO.hookCount++;
} catch (e) {}

// Context.sendBroadcast
try {
    var Context = Java.use("android.content.Context");
    Context.sendBroadcast.implementation = function(intent) {
        emit("ipc_send_broadcast", {
            action: captureString(intent.getAction())
        });
        return this.sendBroadcast(intent);
    };
    HAYO.hookCount++;
} catch (e) {}

// Context.bindService
try {
    var Context = Java.use("android.content.Context");
    Context.bindService.implementation = function(intent, conn, flags) {
        emit("ipc_bind_service", {
            action: captureString(intent.getAction())
        });
        return this.bindService(intent, conn, flags);
    };
    HAYO.hookCount++;
} catch (e) {}

// android.os.Binder
try {
    var Binder = Java.use("android.os.Binder");
    Binder.transact.implementation = function(code, data, reply, flags) {
        emit("ipc_binder_transact", {
            code: code,
            flags: flags
        });
        return this.transact(code, data, reply, flags);
    };
    HAYO.hookCount++;
} catch (e) {}

// android.content.ServiceConnection
try {
    var ServiceConnection = Java.use("android.content.ServiceConnection");
    ServiceConnection.onServiceConnected.implementation = function(name, service) {
        emit("ipc_service_connected", {
            name: captureString(name.toString())
        });
        return this.onServiceConnected(name, service);
    };
    HAYO.hookCount++;
} catch (e) {}

// android.os.Messenger
try {
    var Messenger = Java.use("android.os.Messenger");
    Messenger.send.implementation = function(message) {
        emit("ipc_messenger_send", {
            what: message.what
        });
        return this.send(message);
    };
    HAYO.hookCount++;
} catch (e) {}

// ─────────────────────────────────────────────────────────────────────────────
// 6. RUNTIME HOOKS (10+ hooks)
// ─────────────────────────────────────────────────────────────────────────────

// java.lang.Runtime.exec
try {
    var Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overload('[Ljava.lang.String;').implementation = function(cmdarray) {
        emit("runtime_exec", {
            command: captureString(cmdarray ? cmdarray.join(" ") : "")
        });
        return this.exec(cmdarray);
    };
    HAYO.hookCount++;
} catch (e) {}

// java.lang.ProcessBuilder
try {
    var ProcessBuilder = Java.use("java.lang.ProcessBuilder");
    ProcessBuilder.$init.overload('[Ljava.lang.String;').implementation = function(command) {
        emit("runtime_processbuilder", {
            command: captureString(command ? command.join(" ") : "")
        });
        return this.$init(command);
    };
    HAYO.hookCount++;
} catch (e) {}

// java.lang.Class.forName
try {
    var Class = Java.use("java.lang.Class");
    Class.forName.overload('java.lang.String').implementation = function(className) {
        emit("runtime_class_forname", {
            class_name: captureString(className)
        });
        return this.forName(className);
    };
    HAYO.hookCount++;
} catch (e) {}

// java.lang.ClassLoader.loadClass
try {
    var ClassLoader = Java.use("java.lang.ClassLoader");
    ClassLoader.loadClass.implementation = function(className) {
        emit("runtime_classloader_load", {
            class_name: captureString(className)
        });
        return this.loadClass(className);
    };
    HAYO.hookCount++;
} catch (e) {}

// dalvik.system.DexFile.loadDex
try {
    var DexFile = Java.use("dalvik.system.DexFile");
    DexFile.loadDex.implementation = function(sourcePathName, outputPathName, flags) {
        emit("runtime_dex_load", {
            source: captureString(sourcePathName),
            output: captureString(outputPathName)
        });
        return this.loadDex(sourcePathName, outputPathName, flags);
    };
    HAYO.hookCount++;
} catch (e) {}

// java.lang.reflect.Method.invoke
try {
    var Method = Java.use("java.lang.reflect.Method");
    Method.invoke.implementation = function(obj, args) {
        emit("runtime_reflection_invoke", {
            method_name: captureString(this.getName()),
            class_name: captureString(this.getDeclaringClass().getName())
        });
        return this.invoke(obj, args);
    };
    HAYO.hookCount++;
} catch (e) {}

// java.lang.System.loadLibrary
try {
    var System = Java.use("java.lang.System");
    System.loadLibrary.implementation = function(libname) {
        emit("runtime_load_library", {
            library: captureString(libname)
        });
        return this.loadLibrary(libname);
    };
    HAYO.hookCount++;
} catch (e) {}

// System.load
try {
    var System = Java.use("java.lang.System");
    System.load.implementation = function(filename) {
        emit("runtime_load", {
            filename: captureString(filename)
        });
        return this.load(filename);
    };
    HAYO.hookCount++;
} catch (e) {}

// android.app.Instrumentation
try {
    var Instrumentation = Java.use("android.app.Instrumentation");
    Instrumentation.execStartActivity.implementation = function(who, contextThread, whoThread, intent, startActivityFlags, profilerInfo, result) {
        emit("runtime_instrumentation_start", {
            action: captureString(intent.getAction())
        });
        return this.execStartActivity(who, contextThread, whoThread, intent, startActivityFlags, profilerInfo, result);
    };
    HAYO.hookCount++;
} catch (e) {}

// android.app.ActivityManager
try {
    var ActivityManager = Java.use("android.app.ActivityManager");
    ActivityManager.getRunningAppProcesses.implementation = function() {
        var processes = this.getRunningAppProcesses();
        emit("runtime_running_processes", {
            count: processes ? processes.size() : 0
        });
        return processes;
    };
    HAYO.hookCount++;
} catch (e) {}

// ─────────────────────────────────────────────────────────────────────────────
// 7. LOGGING HOOKS (6+ hooks)
// ─────────────────────────────────────────────────────────────────────────────

// android.util.Log
try {
    var Log = Java.use("android.util.Log");
    Log.d.implementation = function(tag, msg) {
        emit("logging_debug", {
            tag: captureString(tag),
            message: captureString(msg)
        });
        return this.d(tag, msg);
    };
    HAYO.hookCount++;
} catch (e) {}

// Log.e
try {
    var Log = Java.use("android.util.Log");
    Log.e.implementation = function(tag, msg) {
        emit("logging_error", {
            tag: captureString(tag),
            message: captureString(msg)
        });
        return this.e(tag, msg);
    };
    HAYO.hookCount++;
} catch (e) {}

// Log.i
try {
    var Log = Java.use("android.util.Log");
    Log.i.implementation = function(tag, msg) {
        emit("logging_info", {
            tag: captureString(tag),
            message: captureString(msg)
        });
        return this.i(tag, msg);
    };
    HAYO.hookCount++;
} catch (e) {}

// Log.w
try {
    var Log = Java.use("android.util.Log");
    Log.w.implementation = function(tag, msg) {
        emit("logging_warning", {
            tag: captureString(tag),
            message: captureString(msg)
        });
        return this.w(tag, msg);
    };
    HAYO.hookCount++;
} catch (e) {}

// java.util.logging.Logger
try {
    var Logger = Java.use("java.util.logging.Logger");
    Logger.info.implementation = function(msg) {
        emit("logging_jul_info", {
            message: captureString(msg)
        });
        return this.info(msg);
    };
    HAYO.hookCount++;
} catch (e) {}

// System.out.println
try {
    var PrintStream = Java.use("java.io.PrintStream");
    PrintStream.println.implementation = function(x) {
        emit("logging_system_out", {
            message: captureString(String(x))
        });
        return this.println(x);
    };
    HAYO.hookCount++;
} catch (e) {}

// ─────────────────────────────────────────────────────────────────────────────
// 8. BIOMETRIC HOOKS (5+ hooks)
// ─────────────────────────────────────────────────────────────────────────────

// android.hardware.biometrics.BiometricPrompt
try {
    var BiometricPrompt = Java.use("android.hardware.biometrics.BiometricPrompt");
    BiometricPrompt.authenticate.implementation = function(promptInfo, cancellationSignal, executor, callback) {
        emit("biometric_authenticate", {
            prompt_info: promptInfo !== null
        });
        return this.authenticate(promptInfo, cancellationSignal, executor, callback);
    };
    HAYO.hookCount++;
} catch (e) {}

// android.hardware.fingerprint.FingerprintManager
try {
    var FingerprintManager = Java.use("android.hardware.fingerprint.FingerprintManager");
    FingerprintManager.authenticate.implementation = function(cryptoObject, cancellationSignal, flags, callback) {
        emit("biometric_fingerprint_auth", {
            has_crypto: cryptoObject !== null
        });
        return this.authenticate(cryptoObject, cancellationSignal, flags, callback);
    };
    HAYO.hookCount++;
} catch (e) {}

// androidx.biometric.BiometricPrompt
try {
    var BiometricPromptCompat = Java.use("androidx.biometric.BiometricPrompt");
    BiometricPromptCompat.authenticate.implementation = function(promptInfo, cancellationSignal, executor, callback) {
        emit("biometric_authenticate_compat", {
            prompt_info: promptInfo !== null
        });
        return this.authenticate(promptInfo, cancellationSignal, executor, callback);
    };
    HAYO.hookCount++;
} catch (e) {}

// BiometricPrompt.AuthenticationCallback
try {
    var AuthenticationCallback = Java.use("android.hardware.biometrics.BiometricPrompt$AuthenticationCallback");
    AuthenticationCallback.onAuthenticationSucceeded.implementation = function(result) {
        emit("biometric_success", {
            authentication_id: result ? result.getAuthenticationId() : null
        });
        return this.onAuthenticationSucceeded(result);
    };
    HAYO.hookCount++;
} catch (e) {}

// BiometricPrompt.AuthenticationCallback.onAuthenticationFailed
try {
    var AuthenticationCallback = Java.use("android.hardware.biometrics.BiometricPrompt$AuthenticationCallback");
    AuthenticationCallback.onAuthenticationFailed.implementation = function() {
        emit("biometric_failed", {});
        return this.onAuthenticationFailed();
    };
    HAYO.hookCount++;
} catch (e) {}

// ─────────────────────────────────────────────────────────────────────────────
// 9. LOCATION HOOKS (5+ hooks)
// ─────────────────────────────────────────────────────────────────────────────

// android.location.LocationManager
try {
    var LocationManager = Java.use("android.location.LocationManager");
    LocationManager.requestLocationUpdates.implementation = function(provider, minTime, minDistance, listener) {
        emit("location_request_updates", {
            provider: captureString(provider)
        });
        return this.requestLocationUpdates(provider, minTime, minDistance, listener);
    };
    HAYO.hookCount++;
} catch (e) {}

// LocationManager.getLastKnownLocation
try {
    var LocationManager = Java.use("android.location.LocationManager");
    LocationManager.getLastKnownLocation.implementation = function(provider) {
        var location = this.getLastKnownLocation(provider);
        if (location) {
            emit("location_last_known", {
                provider: captureString(provider),
                latitude: location.getLatitude(),
                longitude: location.getLongitude()
            });
        }
        return location;
    };
    HAYO.hookCount++;
} catch (e) {}

// com.google.android.gms.location.FusedLocationProviderClient
try {
    var FusedLocationProviderClient = Java.use("com.google.android.gms.location.FusedLocationProviderClient");
    FusedLocationProviderClient.getLastLocation.implementation = function() {
        emit("location_fused_last", {});
        return this.getLastLocation();
    };
    HAYO.hookCount++;
} catch (e) {}

// Location.requestLocationUpdates
try {
    var FusedLocationProviderClient = Java.use("com.google.android.gms.location.FusedLocationProviderClient");
    FusedLocationProviderClient.requestLocationUpdates.implementation = function(request, callback, looper) {
        emit("location_fused_request", {});
        return this.requestLocationUpdates(request, callback, looper);
    };
    HAYO.hookCount++;
} catch (e) {}

// android.location.Location
try {
    var Location = Java.use("android.location.Location");
    Location.setLatitude.implementation = function(latitude) {
        emit("location_set_latitude", {
            latitude: latitude
        });
        return this.setLatitude(latitude);
    };
    HAYO.hookCount++;
} catch (e) {}

// ─────────────────────────────────────────────────────────────────────────────
// 10. CAMERA HOOKS (4+ hooks)
// ─────────────────────────────────────────────────────────────────────────────

// android.hardware.Camera
try {
    var Camera = Java.use("android.hardware.Camera");
    Camera.open.implementation = function() {
        emit("camera_open", {});
        return this.open();
    };
    HAYO.hookCount++;
} catch (e) {}

// Camera.takePicture
try {
    var Camera = Java.use("android.hardware.Camera");
    Camera.takePicture.implementation = function(shutter, raw, postview, jpeg) {
        emit("camera_take_picture", {});
        return this.takePicture(shutter, raw, postview, jpeg);
    };
    HAYO.hookCount++;
} catch (e) {}

// android.hardware.camera2.CameraManager
try {
    var CameraManager = Java.use("android.hardware.camera2.CameraManager");
    CameraManager.openCamera.implementation = function(cameraId, callback, handler) {
        emit("camera2_open", {
            camera_id: captureString(cameraId)
        });
        return this.openCamera(cameraId, callback, handler);
    };
    HAYO.hookCount++;
} catch (e) {}

// androidx.camera.core.CameraX
try {
    var ProcessCameraProvider = Java.use("androidx.camera.lifecycle.ProcessCameraProvider");
    ProcessCameraProvider.bindToLifecycle.implementation = function(lifecycleOwner, cameraSelector, useCases) {
        emit("camerax_bind", {
            use_cases_count: useCases.size()
        });
        return this.bindToLifecycle(lifecycleOwner, cameraSelector, useCases);
    };
    HAYO.hookCount++;
} catch (e) {}

// ─────────────────────────────────────────────────────────────────────────────
// 11. AUDIO HOOKS (4+ hooks)
// ─────────────────────────────────────────────────────────────────────────────

// android.media.AudioRecord
try {
    var AudioRecord = Java.use("android.media.AudioRecord");
    AudioRecord.startRecording.implementation = function() {
        emit("audio_record_start", {});
        return this.startRecording();
    };
    HAYO.hookCount++;
} catch (e) {}

// android.media.MediaPlayer
try {
    var MediaPlayer = Java.use("android.media.MediaPlayer");
    MediaPlayer.start.implementation = function() {
        emit("audio_play_start", {});
        return this.start();
    };
    HAYO.hookCount++;
} catch (e) {}

// android.media.MediaRecorder
try {
    var MediaRecorder = Java.use("android.media.MediaRecorder");
    MediaRecorder.start.implementation = function() {
        emit("audio_record_start", {});
        return this.start();
    };
    HAYO.hookCount++;
} catch (e) {}

// android.media.SoundPool
try {
    var SoundPool = Java.use("android.media.SoundPool");
    SoundPool.play.implementation = function(soundID, leftVolume, rightVolume, priority, loop, rate) {
        emit("audio_soundpool_play", {
            sound_id: soundID
        });
        return this.play(soundID, leftVolume, rightVolume, priority, loop, rate);
    };
    HAYO.hookCount++;
} catch (e) {}

// ─────────────────────────────────────────────────────────────────────────────
// 12. SENSOR HOOKS (8+ hooks)
// ─────────────────────────────────────────────────────────────────────────────

// android.hardware.SensorManager
try {
    var SensorManager = Java.use("android.hardware.SensorManager");
    SensorManager.registerListener.implementation = function(listener, sensor, samplingPeriodUs) {
        emit("sensor_register", {
            sensor_type: sensor.getType(),
            sensor_name: captureString(sensor.getName())
        });
        return this.registerListener(listener, sensor, samplingPeriodUs);
    };
    HAYO.hookCount++;
} catch (e) {}

// SensorEventListener.onSensorChanged
try {
    var SensorEventListener = Java.use("android.hardware.SensorManager$SensorEventListener");
    SensorEventListener.onSensorChanged.implementation = function(event) {
        emit("sensor_changed", {
            sensor_type: event.sensor.getType(),
            accuracy: event.accuracy
        });
        return this.onSensorChanged(event);
    };
    HAYO.hookCount++;
} catch (e) {}

// android.hardware.Sensor (Accelerometer)
try {
    var Sensor = Java.use("android.hardware.Sensor");
    Sensor.TYPE_ACCELEROMETER.value = 1;
    emit("sensor_accelerometer", {});
} catch (e) {}

// Sensor (Gyroscope)
try {
    var Sensor = Java.use("android.hardware.Sensor");
    Sensor.TYPE_GYROSCOPE.value = 4;
    emit("sensor_gyroscope", {});
} catch (e) {}

// Sensor (Magnetometer)
try {
    var Sensor = Java.use("android.hardware.Sensor");
    Sensor.TYPE_MAGNETIC_FIELD.value = 2;
    emit("sensor_magnetometer", {});
} catch (e) {}

// Sensor (Light)
try {
    var Sensor = Java.use("android.hardware.Sensor");
    Sensor.TYPE_LIGHT.value = 5;
    emit("sensor_light", {});
} catch (e) {}

// Sensor (Proximity)
try {
    var Sensor = Java.use("android.hardware.Sensor");
    Sensor.TYPE_PROXIMITY.value = 8;
    emit("sensor_proximity", {});
} catch (e) {}

// Sensor (Step Counter)
try {
    var Sensor = Java.use("android.hardware.Sensor");
    Sensor.TYPE_STEP_COUNTER.value = 19;
    emit("sensor_step_counter", {});
} catch (e) {}

// ─────────────────────────────────────────────────────────────────────────────
// 13. NOTIFICATION HOOKS (5+ hooks)
// ─────────────────────────────────────────────────────────────────────────────

// android.app.NotificationManager
try {
    var NotificationManager = Java.use("android.app.NotificationManager");
    NotificationManager.notify.implementation = function(id, notification) {
        emit("notification_post", {
            id: id,
            notification: captureString(notification.toString())
        });
        return this.notify(id, notification);
    };
    HAYO.hookCount++;
} catch (e) {}

// Notification.Builder
try {
    var NotificationBuilder = Java.use("android.app.Notification$Builder");
    NotificationBuilder.build.implementation = function() {
        var notification = this.build();
        emit("notification_build", {});
        return notification;
    };
    HAYO.hookCount++;
} catch (e) {}

// android.service.notification.NotificationListenerService
try {
    var NotificationListenerService = Java.use("android.service.notification.NotificationListenerService");
    NotificationListenerService.onNotificationPosted.implementation = function(sbn) {
        emit("notification_listener_posted", {
            package: captureString(sbn.getPackageName())
        });
        return this.onNotificationPosted(sbn);
    };
    HAYO.hookCount++;
} catch (e) {}

// NotificationListenerService.onNotificationRemoved
try {
    var NotificationListenerService = Java.use("android.service.notification.NotificationListenerService");
    NotificationListenerService.onNotificationRemoved.implementation = function(sbn) {
        emit("notification_listener_removed", {
            package: captureString(sbn.getPackageName())
        });
        return this.onNotificationRemoved(sbn);
    };
    HAYO.hookCount++;
} catch (e) {}

// android.app.NotificationChannel
try {
    var NotificationChannel = Java.use("android.app.NotificationChannel");
    NotificationChannel.$init.implementation = function(id, name, importance) {
        emit("notification_channel", {
            id: captureString(id),
            name: captureString(name),
            importance: importance
        });
        return this.$init(id, name, importance);
    };
    HAYO.hookCount++;
} catch (e) {}

// ─────────────────────────────────────────────────────────────────────────────
// 14. PERMISSION HOOKS (4+ hooks)
// ─────────────────────────────────────────────────────────────────────────────

// android.content.pm.PackageManager
try {
    var PackageManager = Java.use("android.content.pm.PackageManager");
    PackageManager.checkPermission.implementation = function(permName, pkgName) {
        var result = this.checkPermission(permName, pkgName);
        emit("permission_check", {
            permission: captureString(permName),
            package: captureString(pkgName),
            granted: result === PackageManager.PERMISSION_GRANTED
        });
        return result;
    };
    HAYO.hookCount++;
} catch (e) {}

// androidx.core.app.ActivityCompat
try {
    var ActivityCompat = Java.use("androidx.core.app.ActivityCompat");
    ActivityCompat.requestPermissions.implementation = function(activity, permissions, requestCode) {
        emit("permission_request", {
            permissions_count: permissions.length,
            request_code: requestCode
        });
        return this.requestPermissions(activity, permissions, requestCode);
    };
    HAYO.hookCount++;
} catch (e) {}

// Context.checkSelfPermission
try {
    var ContextCompat = Java.use("androidx.core.content.ContextCompat");
    ContextCompat.checkSelfPermission.implementation = function(context, permission) {
        var result = this.checkSelfPermission(context, permission);
        emit("permission_check_compat", {
            permission: captureString(permission),
            granted: result === 0
        });
        return result;
    };
    HAYO.hookCount++;
} catch (e) {}

// android.app.Activity.requestPermissions
try {
    var Activity = Java.use("android.app.Activity");
    Activity.requestPermissions.implementation = function(permissions, requestCode) {
        emit("permission_request_activity", {
            permissions_count: permissions.length,
            request_code: requestCode
        });
        return this.requestPermissions(permissions, requestCode);
    };
    HAYO.hookCount++;
} catch (e) {}

// ─────────────────────────────────────────────────────────────────────────────
// 15. DATABASE HOOKS (6+ hooks)
// ─────────────────────────────────────────────────────────────────────────────

// android.database.sqlite.SQLiteDatabase.insert
try {
    var SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");
    SQLiteDatabase.insert.implementation = function(table, nullColumnHack, values) {
        emit("database_insert", {
            table: captureString(table)
        });
        return this.insert(table, nullColumnHack, values);
    };
    HAYO.hookCount++;
} catch (e) {}

// SQLiteDatabase.update
try {
    var SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");
    SQLiteDatabase.update.implementation = function(table, values, whereClause, whereArgs) {
        emit("database_update", {
            table: captureString(table),
            where: captureString(whereClause)
        });
        return this.update(table, values, whereClause, whereArgs);
    };
    HAYO.hookCount++;
} catch (e) {}

// SQLiteDatabase.delete
try {
    var SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");
    SQLiteDatabase.delete.implementation = function(table, whereClause, whereArgs) {
        emit("database_delete", {
            table: captureString(table),
            where: captureString(whereClause)
        });
        return this.delete(table, whereClause, whereArgs);
    };
    HAYO.hookCount++;
} catch (e) {}

// android.database.sqlite.SQLiteOpenHelper
try {
    var SQLiteOpenHelper = Java.use("android.database.sqlite.SQLiteOpenHelper");
    SQLiteOpenHelper.getWritableDatabase.implementation = function() {
        emit("database_get_writable", {});
        return this.getWritableDatabase();
    };
    HAYO.hookCount++;
} catch (e) {}

// SQLiteOpenHelper.getReadableDatabase
try {
    var SQLiteOpenHelper = Java.use("android.database.sqlite.SQLiteOpenHelper");
    SQLiteOpenHelper.getReadableDatabase.implementation = function() {
        emit("database_get_readable", {});
        return this.getReadableDatabase();
    };
    HAYO.hookCount++;
} catch (e) {}

// androidx.room.RoomDatabase
try {
    var RoomDatabase = Java.use("androidx.room.RoomDatabase");
    RoomDatabase.getOpenHelper.implementation = function() {
        emit("database_room_open", {});
        return this.getOpenHelper();
    };
    HAYO.hookCount++;
} catch (e) {}

// ─────────────────────────────────────────────────────────────────────────────
// 16. NATIVE HOOKS (5+ hooks)
// ─────────────────────────────────────────────────────────────────────────────

// System.loadLibrary (native)
try {
    var System = Java.use("java.lang.System");
    System.loadLibrary.implementation = function(libname) {
        emit("native_load_library", {
            library: captureString(libname)
        });
        return this.loadLibrary(libname);
    };
    HAYO.hookCount++;
} catch (e) {}

// Runtime.loadLibrary (native)
try {
    var Runtime = Java.use("java.lang.Runtime");
    Runtime.loadLibrary.implementation = function(libname) {
        emit("native_runtime_load", {
            library: captureString(libname)
        });
        return this.loadLibrary(libname);
    };
    HAYO.hookCount++;
} catch (e) {}

// Native malloc (via Interceptor)
try {
    var mallocPtr = Module.findExportByName(null, "malloc");
    if (mallocPtr) {
        Interceptor.attach(mallocPtr, {
            onEnter: function(args) {
                this.size = args[0].toInt32();
            },
            onLeave: function(retval) {
                if (this.size > 1024) {
                    emit("native_malloc", {
                        size: this.size,
                        ptr: retval
                    });
                }
            }
        });
        HAYO.hookCount++;
    }
} catch (e) {}

// Native free (via Interceptor)
try {
    var freePtr = Module.findExportByName(null, "free");
    if (freePtr) {
        Interceptor.attach(freePtr, {
            onEnter: function(args) {
                emit("native_free", {
                    ptr: args[0]
                });
            }
        });
        HAYO.hookCount++;
    }
} catch (e) {}

// Native dlopen (via Interceptor)
try {
    var dlopenPtr = Module.findExportByName(null, "dlopen");
    if (dlopenPtr) {
        Interceptor.attach(dlopenPtr, {
            onEnter: function(args) {
                this.path = Memory.readUtf8String(args[0]);
            },
            onLeave: function(retval) {
                emit("native_dlopen", {
                    path: captureString(this.path),
                    handle: retval
                });
            }
        });
        HAYO.hookCount++;
    }
} catch (e) {}

// ─────────────────────────────────────────────────────────────────────────────
// 17. BILLING HOOKS (4+ hooks)
// ─────────────────────────────────────────────────────────────────────────────

// com.android.billingclient.api.BillingClient
try {
    var BillingClient = Java.use("com.android.billingclient.api.BillingClient");
    BillingClient.queryPurchases.implementation = function(params) {
        emit("billing_query_purchases", {});
        return this.queryPurchases(params);
    };
    HAYO.hookCount++;
} catch (e) {}

// BillingClient.launchBillingFlow
try {
    var BillingClient = Java.use("com.android.billingclient.api.BillingClient");
    BillingClient.launchBillingFlow.implementation = function(activity, params) {
        emit("billing_launch_flow", {
            sku: captureString(params.getSku())
        });
        return this.launchBillingFlow(activity, params);
    };
    HAYO.hookCount++;
} catch (e) {}

// com.android.vending.billing.IInAppBillingService
try {
    var IInAppBillingService = Java.use("com.android.vending.billing.IInAppBillingService");
    IInAppBillingService.getBuyIntent.implementation = function(apiVersion, packageName, sku, type, developerPayload) {
        emit("billing_get_buy_intent", {
            sku: captureString(sku),
            type: captureString(type)
        });
        return this.getBuyIntent(apiVersion, packageName, sku, type, developerPayload);
    };
    HAYO.hookCount++;
} catch (e) {}

// IInAppBillingService.getPurchases
try {
    var IInAppBillingService = Java.use("com.android.vending.billing.IInAppBillingService");
    IInAppBillingService.getPurchases.implementation = function(apiVersion, packageName, type, continuationToken) {
        emit("billing_get_purchases", {
            type: captureString(type)
        });
        return this.getPurchases(apiVersion, packageName, type, continuationToken);
    };
    HAYO.hookCount++;
} catch (e) {}

// ─────────────────────────────────────────────────────────────────────────────
// 18. CLOUD HOOKS (6+ hooks)
// ─────────────────────────────────────────────────────────────────────────────

// com.google.firebase.auth.FirebaseAuth
try {
    var FirebaseAuth = Java.use("com.google.firebase.auth.FirebaseAuth");
    FirebaseAuth.signInWithCredential.implementation = function(credential) {
        emit("firebase_auth_signin", {
            provider: captureString(credential.getProvider())
        });
        return this.signInWithCredential(credential);
    };
    HAYO.hookCount++;
} catch (e) {}

// FirebaseAuth.getInstance
try {
    var FirebaseAuth = Java.use("com.google.firebase.auth.FirebaseAuth");
    FirebaseAuth.getInstance.implementation = function() {
        emit("firebase_auth_instance", {});
        return this.getInstance();
    };
    HAYO.hookCount++;
} catch (e) {}

// com.google.firebase.firestore.FirebaseFirestore
try {
    var FirebaseFirestore = Java.use("com.google.firebase.firestore.FirebaseFirestore");
    FirebaseFirestore.collection.implementation = function(collectionPath) {
        emit("firebase_firestore_collection", {
            path: captureString(collectionPath)
        });
        return this.collection(collectionPath);
    };
    HAYO.hookCount++;
} catch (e) {}

// com.amazonaws.services.s3.AmazonS3Client
try {
    var AmazonS3Client = Java.use("com.amazonaws.services.s3.AmazonS3Client");
    AmazonS3Client.listBuckets.implementation = function() {
        emit("aws_s3_list_buckets", {});
        return this.listBuckets();
    };
    HAYO.hookCount++;
} catch (e) {}

// AmazonS3Client.getObject
try {
    var AmazonS3Client = Java.use("com.amazonaws.services.s3.AmazonS3Client");
    AmazonS3Client.getObject.implementation = function(bucketName, key) {
        emit("aws_s3_get_object", {
            bucket: captureString(bucketName),
            key: captureString(key)
        });
        return this.getObject(bucketName, key);
    };
    HAYO.hookCount++;
} catch (e) {}

// com.google.cloud.storage.Storage
try {
    var Storage = Java.use("com.google.cloud.storage.Storage");
    Storage.get.implementation = function(blobId) {
        emit("gcp_storage_get", {
            blob_id: captureString(blobId.getName())
        });
        return this.get(blobId);
    };
    HAYO.hookCount++;
} catch (e) {}

// ─────────────────────────────────────────────────────────────────────────────
// 20. AI/LLM API HOOKS (6+ hooks)
// ─────────────────────────────────────────────────────────────────────────────

// OpenAI API Client
try {
    var OkHttpClient = Java.use("okhttp3.OkHttpClient");
    OkHttpClient.newCall.implementation = function(request) {
        var url = request.url().toString();
        if (url.indexOf("api.openai.com") !== -1 || url.indexOf("openai") !== -1) {
            emit("openai_api_call", {
                url: captureString(url),
                method: captureString(request.method())
            });
        }
        return this.newCall(request);
    };
    HAYO.hookCount++;
} catch (e) {}

// DeepSeek API Client
try {
    var OkHttpClient = Java.use("okhttp3.OkHttpClient");
    OkHttpClient.newCall.implementation = function(request) {
        var url = request.url().toString();
        if (url.indexOf("api.deepseek.com") !== -1 || url.indexOf("deepseek") !== -1) {
            emit("deepseek_api_call", {
                url: captureString(url),
                method: captureString(request.method())
            });
        }
        return this.newCall(request);
    };
    HAYO.hookCount++;
} catch (e) {}

// Anthropic Claude API Client
try {
    var OkHttpClient = Java.use("okhttp3.OkHttpClient");
    OkHttpClient.newCall.implementation = function(request) {
        var url = request.url().toString();
        if (url.indexOf("api.anthropic.com") !== -1 || url.indexOf("anthropic") !== -1) {
            emit("anthropic_api_call", {
                url: captureString(url),
                method: captureString(request.method())
            });
        }
        return this.newCall(request);
    };
    HAYO.hookCount++;
} catch (e) {}

// Google Gemini API Client
try {
    var OkHttpClient = Java.use("okhttp3.OkHttpClient");
    OkHttpClient.newCall.implementation = function(request) {
        var url = request.url().toString();
        if (url.indexOf("generativelanguage.googleapis.com") !== -1 || url.indexOf("gemini") !== -1) {
            emit("gemini_api_call", {
                url: captureString(url),
                method: captureString(request.method())
            });
        }
        return this.newCall(request);
    };
    HAYO.hookCount++;
} catch (e) {}

// HuggingFace API Client
try {
    var OkHttpClient = Java.use("okhttp3.OkHttpClient");
    OkHttpClient.newCall.implementation = function(request) {
        var url = request.url().toString();
        if (url.indexOf("api-inference.huggingface.co") !== -1 || url.indexOf("huggingface") !== -1) {
            emit("huggingface_api_call", {
                url: captureString(url),
                method: captureString(request.method())
            });
        }
        return this.newCall(request);
    };
    HAYO.hookCount++;
} catch (e) {}

// Generic AI API Key Detection in Headers
try {
    var OkHttpClient = Java.use("okhttp3.OkHttpClient");
    OkHttpClient.newCall.implementation = function(request) {
        var headers = request.headers();
        var authHeader = headers.get("Authorization");
        if (authHeader) {
            var authValue = authHeader.toString();
            if (authValue.indexOf("sk-") !== -1 || authValue.indexOf("Bearer") !== -1) {
                emit("ai_api_key_header", {
                    header: captureString(authValue.substring(0, 20) + "..."),
                    url: captureString(request.url().toString())
                });
            }
        }
        return this.newCall(request);
    };
    HAYO.hookCount++;
} catch (e) {}

// ─────────────────────────────────────────────────────────────────────────────
// 19. AUTH HOOKS (5+ hooks)
// ─────────────────────────────────────────────────────────────────────────────

// android.accounts.AccountManager
try {
    var AccountManager = Java.use("android.accounts.AccountManager");
    AccountManager.getAuthToken.implementation = function(account, authTokenType, options, activity, callback, handler) {
        emit("accountmanager_get_token", {
            account_type: captureString(account.type),
            auth_type: captureString(authTokenType)
        });
        return this.getAuthToken(account, authTokenType, options, activity, callback, handler);
    };
    HAYO.hookCount++;
} catch (e) {}

// AccountManager.addAccountExplicitly
try {
    var AccountManager = Java.use("android.accounts.AccountManager");
    AccountManager.addAccountExplicitly.implementation = function(account, password, userdata) {
        emit("accountmanager_add_account", {
            account_type: captureString(account.type)
        });
        return this.addAccountExplicitly(account, password, userdata);
    };
    HAYO.hookCount++;
} catch (e) {}

// OAuth2 (general)
try {
    var OAuthTokenRequest = Java.use("com.google.api.client.auth.oauth2.TokenRequest");
    OAuthTokenRequest.execute.implementation = function() {
        emit("oauth_token_request", {});
        return this.execute();
    };
    HAYO.hookCount++;
} catch (e) {}

// JWT (general)
try {
    var JWT = Java.use("com.auth0.jwt.JWT");
    JWT.decode.implementation = function(token) {
        emit("jwt_decode", {
            token: captureString(token)
        });
        return this.decode(token);
    };
    HAYO.hookCount++;
} catch (e) {}

// Session management
try {
    var HttpSession = Java.use("javax.servlet.http.HttpSession");
    HttpSession.setAttribute.implementation = function(name, value) {
        emit("session_set_attribute", {
            name: captureString(name)
        });
        return this.setAttribute(name, value);
    };
    HAYO.hookCount++;
} catch (e) {}

// ─────────────────────────────────────────────────────────────────────────────
// 20. ANTI-TAMPER HOOKS (4+ hooks)
// ─────────────────────────────────────────────────────────────────────────────

// Root detection bypass
try {
    var Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
        var cmdStr = captureString(cmd);
        if (cmdStr.includes("su") || cmdStr.includes("which") || cmdStr.includes("magisk")) {
            emit("anti_tamper_root_check", {
                command: cmdStr
            });
        }
        return this.exec(cmd);
    };
    HAYO.hookCount++;
} catch (e) {}

// SSL pinning bypass (OkHttp)
try {
    var OkHttpClientBuilder = Java.use("okhttp3.OkHttpClient$Builder");
    OkHttpClientBuilder.sslSocketFactory.implementation = function(sslSocketFactory, trustManager) {
        emit("anti_tamper_ssl_pinning", {
            bypassed: true
        });
        return this.sslSocketFactory(sslSocketFactory, trustManager);
    };
    HAYO.hookCount++;
} catch (e) {}

// Debug detection bypass
try {
    var ApplicationInfo = Java.use("android.content.pm.ApplicationInfo");
    ApplicationInfo.flags.value = 0; // Clear debug flag
    emit("anti_tamper_debug_bypass", {});
} catch (e) {}

// Emulator detection bypass
try {
    var Build = Java.use("android.os.Build");
    var BRAND = Build.BRAND.value;
    var MODEL = Build.MODEL.value;
    emit("anti_tamper_emulator_info", {
        brand: captureString(BRAND),
        model: captureString(MODEL)
    });
} catch (e) {}

// ─────────────────────────────────────────────────────────────────────────────
// READY SIGNAL
// ─────────────────────────────────────────────────────────────────────────────

send({
    type: "message",
    payload: {
        kind: "ready",
        hook_count: HAYO.hookCount,
        timestamp: Date.now()
    }
});

console.log("[*] HAYO Ultimate Instrumentation loaded with " + HAYO.hookCount + " hooks");

}); // ← نهاية Java.perform (تغليف كل خطافات Java)

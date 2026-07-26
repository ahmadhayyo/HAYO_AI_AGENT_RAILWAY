/*
 * HAYO Cipher-7 — Universal NATIVE TLS Capture (payload_native_ssl.js)
 * ==================================================================
 * The most robust capture: hooks BoringSSL/OpenSSL SSL_read / SSL_write at the
 * NATIVE layer, so it captures EVERY HTTPS request/response AFTER decryption —
 * regardless of the Java networking stack (OkHttp, Retrofit, HttpURLConnection,
 * Cronet, Flutter/dart:io, streaming/SSE). Use this when the OkHttp-only payload
 * only logs [URL] lines but no response bodies.
 *
 * Authorized graduation-evaluation PoC on the committee's own app only.
 */

// ── 1) Java-layer SSL unpinning (so pinning can't drop the connection) ──
Java.perform(function () {
    try {
        var TM = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TM.verifyChain.implementation = function (a, b, c, d, e, f) { return a; };
    } catch (e) {}
    try {
        var CP = Java.use('okhttp3.CertificatePinner');
        CP.check.overloads.forEach(function (o) { o.implementation = function () { return; }; });
    } catch (e) {}
    console.log("[+] Java SSL unpinning installed.");
});

// ── 2) Native SSL_read / SSL_write capture (the universal part) ──
function printableRatio(s) {
    if (!s.length) return 0;
    var p = 0;
    for (var i = 0; i < s.length; i++) {
        var c = s.charCodeAt(i);
        if (c === 9 || c === 10 || c === 13 || (c >= 32 && c < 127)) p++;
    }
    return p / s.length;
}

function toStr(bytes) {
    var s = "";
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return s;
}

var INTERESTING = /HTTP\/|Content-Type|application\/json|Authorization|Bearer |api[_-]?key|token|"(subscription|premium|isPro|plan|user|email|password|balance|message|choices|content|access_token|id_token)"|AIza|sk-|\{"/i;

function dump(dir, buf, len) {
    try {
        if (len <= 0 || len > 262144) return;
        var bytes = new Uint8Array(buf.readByteArray(len));
        var s = toStr(bytes);
        if (printableRatio(s) < 0.75) return;         // skip binary/handshake noise
        if (!INTERESTING.test(s)) return;             // skip keep-alives / non-HTTP
        console.log("\n==============================================");
        console.log("🔴 [TLS " + dir + " — CLOUD DATA (native)] 🔴");
        console.log(s.substring(0, 4000));
        console.log("==============================================\n");
    } catch (e) {}
}

function hookNativeTLS() {
    var count = 0;
    var wr = Module.findExportByName(null, "SSL_write");
    if (wr) {
        Interceptor.attach(wr, {
            onEnter: function (args) {
                try { var n = args[2].toInt32(); if (n > 0) dump("→ SENT (request)", args[1], n); } catch (e) {}
            }
        });
        count++;
    }
    var rd = Module.findExportByName(null, "SSL_read");
    if (rd) {
        Interceptor.attach(rd, {
            onEnter: function (args) { this.buf = args[1]; },
            onLeave: function (ret) {
                try { var n = ret.toInt32(); if (n > 0) dump("← RECEIVED (response)", this.buf, n); } catch (e) {}
            }
        });
        count++;
    }
    return count;
}

// Some apps load the TLS library lazily → retry a few times.
var attempts = 0;
var timer = setInterval(function () {
    attempts++;
    var n = hookNativeTLS();
    if (n > 0) {
        console.log("[+] Native TLS hooks installed (SSL_read/SSL_write). Capturing ALL HTTPS traffic.");
        console.log("[*] Now USE the app (send a chat message / open pages) to generate traffic.\n");
        clearInterval(timer);
    } else if (attempts > 15) {
        console.log("[!] SSL_read/SSL_write not found as exports (statically linked?). Java hooks still active.");
        clearInterval(timer);
    }
}, 800);

/* HAYO Cipher-7 — Cronet/QUIC Interception (payload_cronet.js)
 * ==========================================================
 * Hooks Google's Cronet networking stack (Chrome, WebView, many Android apps).
 * Captures QUIC, HTTP/3, HTTP/2, HTTP/1.1 traffic flowing through CronetEngine.
 * Covers: CronetUrlRequest, BidirectionalStream (gRPC), native QUIC stack.
 */
Java.perform(function () {
    console.log("[CRONET] Hooking Cronet/QUIC stack...");

    var cronetEngineClasses = [
        "org.chromium.net.CronetEngine",
        "org.chromium.net.impl.CronetEngineBase",
        "org.chromium.net.impl.NativeCronetEngine",
        "org.chromium.net.impl.CronetUrlRequest"
    ];

    cronetEngineClasses.forEach(function (clazzName) {
        try {
            var CronetCls = Java.use(clazzName);
            try {
                CronetCls.startWithRequestInfo.overload('org.chromium.net.RequestInfo', 'java.nio.ByteBuffer', 'org.chromium.net.UrlRequest$Callback', 'java.util.concurrent.Executor').implementation = function (info, buffer, callback, executor) {
                    var url = info != null ? info.getUrl() : "null";
                    console.log("[CRONET] Request: " + url);
                    return this.startWithRequestInfo(info, buffer, callback, executor);
                };
            } catch (e) {}
            try {
                CronetCls.newRequestBuilder.overload('java.lang.String', 'org.chromium.net.UrlRequest$Callback', 'java.util.concurrent.Executor').implementation = function (url, callback, executor) {
                    console.log("[CRONET] newRequestBuilder: " + url);
                    return this.newRequestBuilder(url, callback, executor);
                };
            } catch (e) {}
        } catch (e) {}
    });

    try {
        var CronetUrlRequest = Java.use("org.chromium.net.impl.CronetUrlRequest");
        try {
            CronetUrlRequest.read.overload('java.nio.ByteBuffer').implementation = function (buffer) {
                if (buffer != null) {
                    var data = [];
                    for (var i = buffer.position(); i < buffer.limit(); i++) {
                        data.push(buffer.get(i));
                    }
                    var str = String.fromCharCode.apply(null, data);
                    if (str && str.length > 0) {
                        console.log("[CRONET] Response data chunk: " + str.substring(0, 500));
                        if (/eyJ[a-zA-Z0-9_\-]{10,}/.test(str)) console.log("[CRONET] JWT found: " + str.match(/eyJ[a-zA-Z0-9_\-]{10,}/)[0]);
                        if (/AIza[0-9A-Za-z\-_]{35}/.test(str)) console.log("[CRONET] API key: " + str.match(/AIza[0-9A-Za-z\-_]{35}/)[0]);
                    }
                }
                return this.read(buffer);
            };
        } catch (e) {}
        try {
            CronetUrlRequest.onSucceeded.overload('org.chromium.net.impl.CronetUrlRequest$UrlResponseInfoOrError').implementation = function (info) {
                if (info != null && info.getResponseInfo != null) {
                    var resp = info.getResponseInfo();
                    console.log("[CRONET] Response: HTTP " + (resp.getHttpStatusCode ? resp.getHttpStatusCode() : "?"));
                }
                return this.onSucceeded(info);
            };
        } catch (e) {}
        try {
            CronetUrlRequest.onFailed.overload('org.chromium.net.impl.CronetUrlRequest$UrlResponseInfoOrError').implementation = function (info) {
                if (info != null && info.getResponseInfo != null) {
                    var resp = info.getResponseInfo();
                    console.log("[CRONET] FAILED: HTTP " + (resp.getHttpStatusCode ? resp.getHttpStatusCode() : "?") + " | URL: " + (resp.getUrl ? resp.getUrl() : "?"));
                }
                return this.onFailed(info);
            };
        } catch (e) {}
    } catch (e) {}

    try {
        var BiDiStream = Java.use("org.chromium.net.impl.CronetBidirectionalStream");
        try {
            BiDiStream.start.implementation = function () {
                console.log("[CRONET][gRPC] BidirectionalStream started");
                return this.start();
            };
        } catch (e) {}
        try {
            BiDiStream.send.overload('java.nio.ByteBuffer', 'boolean').implementation = function (buffer, endOfStream) {
                if (buffer != null) {
                    var data = [];
                    for (var i = buffer.position(); i < buffer.limit(); i++) data.push(buffer.get(i));
                    var str = String.fromCharCode.apply(null, data);
                    console.log("[CRONET][gRPC] Send: " + str.substring(0, 200));
                }
                return this.send(buffer, endOfStream);
            };
        } catch (e) {}
        try {
            BiDiStream.read.overload('java.nio.ByteBuffer').implementation = function (buffer) {
                var ret = this.read(buffer);
                if (buffer != null && ret != null) {
                    var data = [];
                    for (var i = buffer.position(); i < buffer.limit(); i++) data.push(buffer.get(i));
                    var str = String.fromCharCode.apply(null, data);
                    if (str && str.length > 0) console.log("[CRONET][gRPC] Read: " + str.substring(0, 200));
                }
                return ret;
            };
        } catch (e) {}
    } catch (e) {}

    try {
        var cronetModule = Process.findModuleByName("libcronet.so");
        if (cronetModule) {
            var quicSession = Module.findExportByName("libcronet.so", "Cronet_QUIC_Session_Create");
            if (quicSession) Interceptor.attach(quicSession, { onEnter: function() { console.log("[CRONET][NATIVE] QUIC Session"); }});
            var quicWrite = Module.findExportByName("libcronet.so", "Cronet_QUIC_Stream_Write");
            if (quicWrite) Interceptor.attach(quicWrite, { onEnter: function(args) {
                if (args[1]) { var d = Memory.readUtf8String(args[1]); if (d) console.log("[CRONET][NATIVE] QUIC Write: " + d.substring(0,200)); }
            }});
            var quicRead = Module.findExportByName("libcronet.so", "Cronet_QUIC_Stream_Read");
            if (quicRead) Interceptor.attach(quicRead, { onExit: function(retval) {
                if (retval) { var d = Memory.readUtf8String(retval); if (d) console.log("[CRONET][NATIVE] QUIC Read: " + d.substring(0,200)); }
            }});
            console.log("[CRONET] Native QUIC hooks installed");
        }
    } catch (e) {}

    try {
        var RequestInfo = Java.use("org.chromium.net.RequestInfo");
        RequestInfo.getUrl.implementation = function () {
            var url = this.getUrl();
            console.log("[CRONET] RequestInfo URL: " + url);
            return url;
        };
    } catch (e) {}

    console.log("[CRONET] All Cronet/QUIC hooks installed.");
});

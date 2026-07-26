/*
 * DeepSeek Core v5 — payloads/payload_network_ultra.js
 * Full request/response capture at every layer:
 *   - OkHttp: RealInterceptorChain.proceed (bodies + headers)
 *   - OkHttp: RealCall.execute (sync calls)
 *   - OkHttp: ResponseBody.string() (streamed bodies)
 *   - java.net.HttpURLConnection (plaintext requests)
 *   - Flutter/dart:io HttpClient (best-effort)
 *   - Native sockets: connect() (IP/port discovery)
 * All captured data is emitted via send() for the brain.
 */
"use strict";
var _seen = {};
function once(k) { if (_seen[k]) return false; _seen[k] = true; return true; }
function emit(o) { try { send(o); } catch (e) { } }

function decodeHeaders(headers) {
    var result = {};
    try {
        var size = headers.size();
        for (var i = 0; i < size; i++) {
            result[headers.name(i)] = headers.value(i);
        }
    } catch (e) { }
    return result;
}

function hookOkHttp() {
    Java.perform(function () {
        try {
            var Chain = Java.use("okhttp3.internal.http.RealInterceptorChain");
            Chain.proceed.overload("okhttp3.Request").implementation = function (req) {
                var url = "", method = "", reqHeaders = {}, reqBody = "";
                try {
                    url = req.url().toString();
                    method = req.method();
                    reqHeaders = decodeHeaders(req.headers());
                    try {
                        var rb = req.body();
                        if (rb) {
                            var buf = [];
                            rb.writeTo({ write: function (b) { buf.push(String.fromCharCode.apply(null, new Uint8Array(b))); } });
                            reqBody = buf.join("").slice(0, 2000);
                        }
                    } catch (e) { }
                } catch (e) { }

                var resp = this.proceed(req);
                try {
                    var body = "";
                    try { var peek = resp.peekBody(1048576); body = peek.string(); } catch (e) { }
                    var code = 0; try { code = resp.code ? resp.code() : 0; } catch (e) { }
                    var resHeaders = decodeHeaders(resp.headers());

                    if (once("net-" + method + url.split("?")[0])) {
                        emit({
                            event: "http",
                            method: method,
                            url: url,
                            status: code,
                            request_headers: reqHeaders,
                            response_headers: resHeaders,
                            body_snippet: (body || "").slice(0, 1000)
                        });
                    }

                    // Harvest secrets from bodies
                    var combined = (body || "") + (reqBody || "");
                    if (combined && /token|access_token|id_token|api_key|secret|key|premium|subscription|plan|"pro"|sk-|AIza/i.test(combined) && once("rb-sec-" + combined.slice(0, 40))) {
                        emit({
                            event: "http_body_secret",
                            body: combined.slice(0, 3000),
                            url: url,
                            method: method
                        });
                    }
                } catch (e) { }
                return resp;
            };
        } catch (e) { }

        // RealCall.execute() hook
        try {
            var RC = Java.use("okhttp3.RealCall");
            if (RC.execute) {
                RC.execute.implementation = function () {
                    var r = this.execute();
                    try {
                        var u = this.request().url().toString();
                        if (once("exec-" + u.split("?")[0])) {
                            emit({ event: "http_exec", url: u, status: r.code ? r.code() : 0 });
                        }
                    } catch (e) { }
                    return r;
                };
            }
        } catch (e) { }
    });
}

function hookHttpURLConnection() {
    Java.perform(function () {
        try {
            var HUC = Java.use("java.net.HttpURLConnection");
            HUC.getInputStream.implementation = function () {
                var is = this.getInputStream();
                try {
                    var u = this.getURL() ? this.getURL().toString() : "";
                    if (once("huc-body-" + u.split("?")[0])) {
                        emit({
                            event: "http",
                            method: this.getRequestMethod(),
                            url: u,
                            status: this.getResponseCode(),
                            source: "HttpURLConnection"
                        });
                    }
                } catch (e) { }
                return is;
            };
        } catch (e) { }
    });
}

function hookNativeSockets() {
    try {
        var connect = Module.findExportByName(null, "connect");
        if (connect) {
            Interceptor.attach(connect, {
                onEnter: function (args) {
                    try {
                        var sa = args[1], fam = Memory.readU16(sa);
                        if (fam === 2) {
                            var port = (Memory.readU8(sa.add(2)) << 8) | Memory.readU8(sa.add(3));
                            var ip = [0, 1, 2, 3].map(function (i) { return Memory.readU8(sa.add(4 + i)); }).join(".");
                            if (once("sock-" + ip + ":" + port))
                                emit({ event: "native_socket", ip: ip, port: port });
                        }
                    } catch (e) { }
                }
            });
        }
    } catch (e) { }
}

setTimeout(function () {
    hookOkHttp();
    hookHttpURLConnection();
    hookNativeSockets();
    emit({ event: "ready", module: "network_ultra_v5" });
}, 0);

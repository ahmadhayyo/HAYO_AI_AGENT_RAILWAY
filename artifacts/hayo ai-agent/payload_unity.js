/* HAYO Cipher-7 — Unity3D Interception (payload_unity.js) */
Java.perform(function () {
    console.log("[UNITY] Hooking Unity3D engine...");
    try {
        var UnityPlayer = Java.use("com.unity3d.player.UnityPlayer");
        console.log("[UNITY] Found UnityPlayer");
        try { UnityPlayer.UnitySendMessage.overload('java.lang.String','java.lang.String','java.lang.String').implementation = function(o,m,msg){ console.log("[UNITY] "+o+"."+m+"("+(msg?msg.substring(0,300):"")+")"); if(/token|secret|key|password|auth|jwt|api.?key|login/i.test(m+" "+(msg||""))) console.log("[UNITY][SENSITIVE] "+o+"."+m+"="+(msg?msg.substring(0,300):"")); return this.UnitySendMessage(o,m,msg); }; } catch(e){}
    } catch(e) {}
    function hookUnityNative() {
        ["libunity.so","libil2cpp.so","libmain.so","libmono.so"].forEach(function(libName){
            try {
                var mod = Process.findModuleByName(libName);
                if (!mod) return;
                console.log("[UNITY] Found "+libName+" @ "+mod.base);
                if (libName === "libunity.so") {
                    var certH = Module.findExportByName(libName,"CertificateHandler_ValidateCertificate");
                    if (certH) Interceptor.attach(certH,{onExit:function(r){r.replace(ptr(1));}});
                }
                if (libName === "libil2cpp.so") {
                    var i2n = Module.findExportByName(libName,"il2cpp_string_new");
                    if (i2n) Interceptor.attach(i2n,{onEnter:function(a){if(a[0]){try{var s=Memory.readUtf8String(a[0]);if(s&&(s.indexOf("https://")!==-1||s.indexOf("token")!==-1||s.indexOf("secret")!==-1)) console.log("[UNITY][IL2CPP] String: "+s.substring(0,300));}catch(e){}}}});
                }
                if (libName === "libmono.so") {
                    var msn = Module.findExportByName(libName,"mono_string_new");
                    if (msn) Interceptor.attach(msn,{onEnter:function(a){if(a[1]){try{var s=Memory.readUtf8String(a[1]);if(s&&(s.indexOf("https://")!==-1||s.indexOf("token")!==-1||s.indexOf("secret")!==-1)) console.log("[UNITY][MONO] String: "+s.substring(0,300));}catch(e){}}}});
                }
            } catch(e) {}
        });
    }
    hookUnityNative();
    console.log("[UNITY] All Unity3D hooks installed.");
});

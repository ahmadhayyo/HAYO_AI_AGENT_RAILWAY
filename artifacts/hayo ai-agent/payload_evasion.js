/* HAYO Cipher-7 — Evasion & Anti-Frida Detection Bypass (payload_evasion.js) */
Java.perform(function () {
    console.log("[EVASION] Evasion & anti-detection engaged...");
    var antiFridaClasses = [
        "com.kjc.FridaCheck","com.scottyab.rootbeer.RootBeer",
        "com.scottyab.rootbeer.RootCheck","com.jrummyapps.android.root.RootUtils",
        "com.topjohnwu.safetynet.SafetyNet","com.google.android.gms.safetynet.SafetyNetApi"
    ];
    antiFridaClasses.forEach(function(cn){
        try{
            var c=Java.use(cn);
            if(c){console.log("[EVASION] Hooking "+cn);
                var methods=c.class.getDeclaredMethods();
                for(var i=0;i<methods.length;i++){
                    try{var m=methods[i],n=m.getName();
                        if(m.getReturnType().getName()==="boolean"&&(n.indexOf("check")!==-1||n.indexOf("is")!==-1||n.indexOf("has")!==-1||n.indexOf("detect")!==-1)){
                            c[n].overloads.forEach(function(ov){if(ov.returnType.className==="boolean")ov.implementation=function(){console.log("[EVASION] Bypassed: "+cn+"."+n);return false;};});
                        }}catch(e){}
                }
            }
        }catch(e){}
    });
    function patchNative(){
        try{
            var pt=Module.findExportByName("libc.so","ptrace");
            if(pt)Interceptor.attach(pt,{onEnter:function(a){var r=a[0].toInt32();if(r===0x10||r===0x4){console.log("[EVASION] Ptrace blocked");this.b=true;}},onLeave:function(r){if(this.b)r.replace(ptr(0));}});
            var fg=Module.findExportByName("libc.so","fgets");
            if(fg)Interceptor.attach(fg,{onEnter:function(a){this.b=a[0];},onLeave:function(r){if(this.b&&r.isNull()===false){try{var l=Memory.readUtf8String(this.b);if(l&&l.indexOf("TracerPid")!==-1)Memory.writeUtf8String(this.b,"TracerPid:\t0");}catch(e){}}}});
        }catch(e){}
    }
    function bypassSSLPinning(){
        try{var cp=Java.use("okhttp3.CertificatePinner");cp.check.overload('java.lang.String','java.util.List').implementation=function(h,pc){console.log("[EVASION] SSL pinning bypassed: "+h);return;};}catch(e){}
        try{var xtm=Java.use("javax.net.ssl.X509TrustManager");try{xtm.checkServerTrusted.overload('[Ljava.security.cert.X509Certificate;','java.lang.String').implementation=function(c,a){console.log("[EVASION] TrustManager bypassed");};}catch(e){}}catch(e){}
        try{var hnv=Java.use("javax.net.ssl.HostnameVerifier");hnv.verify.overload('java.lang.String','javax.net.ssl.SSLSession').implementation=function(h,s){console.log("[EVASION] HostnameVerifier bypassed: "+h);return true;};}catch(e){}
    }
    patchNative();bypassSSLPinning();
    setInterval(function(){
        antiFridaClasses.forEach(function(cn){try{var c=Java.use(cn);if(c){var methods=c.class.getDeclaredMethods();for(var i=0;i<methods.length;i++){try{var m=methods[i],n=m.getName();if(m.getReturnType().getName()==="boolean"&&(n.indexOf("check")!==-1||n.indexOf("is")!==-1))c[n].overloads.forEach(function(ov){if(ov.returnType.className==="boolean")ov.implementation=function(){return false;};});}catch(e){}}}}catch(e){}});
    },30000);
    console.log("[EVASION] All evasion hooks installed.");
});

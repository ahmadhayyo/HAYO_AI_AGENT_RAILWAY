/*
 * HAYO Cipher-7 — Advanced Obfuscation Detection & Bypass Engine
 * ==============================================================
 * Implements directive 2.1:
 *  - String decryption/de-obfuscation (XOR, Base64, custom algorithms)
 *  - Control flow flattening bypass heuristics
 *  - Reflection detection & dynamic re-hooking
 *  - API hashing / signature matching
 *  - Call stack analysis for obfuscated wrapper identification
 *
 * Load AFTER instrument.js:  frida -l instrument.js -l obfuscation_bypass.js
 */
"use strict";

// ─────────────────── String De-obfuscation Engine ─────────────────────
var DE_OBFUSCATION = {
    stringsDecrypted: 0,
    patternsDetected: [],
    reflectionCalls: 0,
    rehookedTargets: 0
};

// Pattern recognition for common obfuscation (heuristic)
var OBFUSCATION_PATTERNS = [
    { type: "xor_key",      regex: /xor|key|decrypt|deobfuscate|deob/i },
    { type: "base64_decode", regex: /base64|b64|decode|fromBase64/i },
    { type: "string_array",  regex: /str\[|string\[|strings\[|s\[/i },
    { type: "char_decode",   regex: /charAt|charCodeAt|fromCharCode|Character\.toString/i },
    { type: "substring_magic", regex: /substring|substr|split.*join|replace.*split/i },
];

// ── 1) Dynamic String Decryption ─────────────────────────────────────
function installStringDeobfuscation() {
    Java.perform(function () {
        // Hook StringBuilder/StringBuffer to capture assembled strings
        try {
            var SB = Java.use("java.lang.StringBuilder");
            var originalSB = SB.toString;
            SB.toString.implementation = function () {
                var result = this.toString();
                try {
                    // Check for common patterns in assembled strings
                    if (result && result.length > 8) {
                        // Detect dynamically assembled URLs, API keys, secrets
                        if (/^(https?:\/\/|api|http:|ws:|wss:)/i.test(result) ||
                            /secret|key|token|password|credential/i.test(result)) {
                            if (once("sb-assembly-" + result.slice(0, 40))) {
                                reportDynamic("deobfuscated_string", 
                                    "String de-obfuscated via StringBuilder: " + result.slice(0, 200),
                                    [{ label: "decoded", value: result.slice(0, 400), sensitive: true }], "high");
                                DE_OBFUSCATION.stringsDecrypted++;
                            }
                        }
                    }
                } catch (e) {}
                return result;
            };
        } catch (e) {}

        // Hook String constructor(byte[], charset) for charset-based decoding
        try {
            var Str = Java.use("java.lang.String");
            Str.$init.overload("[B", "java.lang.String").implementation = function (bytes, charset) {
                var result = this.$init(bytes, charset);
                try {
                    var s = String(result);
                    if (s && s.length > 10 && s.length < 2000) {
                        var entropy = shannon(s);
                        if (entropy > 4.5 && /^[A-Za-z0-9+\/=_-]+$/.test(s)) {
                            // High-entropy string decoded from bytes - likely a deobfuscated secret
                            if (once("str-decode-" + s.slice(0, 30))) {
                                reportDynamic("deobfuscated_string",
                                    "String decoded from byte[] via charset: " + s.slice(0, 200),
                                    [{ label: "decoded", value: s.slice(0, 400), sensitive: true }], "high");
                                DE_OBFUSCATION.stringsDecrypted++;
                            }
                        }
                    }
                } catch (e) {}
                return result;
            };
        } catch (e) {}

        // Hook Character.toString for char-by-char deobfuscation
        try {
            var Char = Java.use("java.lang.Character");
            Char.toString.overload("char").implementation = function (c) {
                return Char.toString(c);
            };
        } catch (e) {}

        // Hook common XOR byte operations used in custom obfuscation
        try {
            // ByteArrayOutputStream - often used to build deobfuscated byte arrays
            var BAOS = Java.use("java.io.ByteArrayOutputStream");
            BAOS.write.overload("[B").implementation = function (b) {
                var result = this.write(b);
                try {
                    if (b && b.length > 4 && b.length < 512) {
                        // Check if this byte array contains what looks like decoded data
                        var hx = bytesToHex(b, 32);
                        if (once("baos-" + hx)) {
                            reportKeyish(b, "ByteArrayOutputStream.write(byte[])");
                        }
                    }
                } catch (e) {}
                return result;
            };
        } catch (e) {}

        // Hook Arrays.copyOf which is used in many custom deobfuscation routines
        try {
            var Arr = Java.use("java.util.Arrays");
            Arr.copyOf.overload("[B", "int").implementation = function (original, newLength) {
                var result = this.copyOf(original, newLength);
                try {
                    if (original && original.length > 8 && original.length < 200) {
                        var outHx = bytesToHex(result, 16);
                        var origHx = bytesToHex(original, 16);
                        if (outHx !== origHx && once("copyof-" + outHx)) {
                            reportKeyish(result, "Arrays.copyOf (possible deobfuscation)");
                        }
                    }
                } catch (e) {}
                return result;
            };
        } catch (e) {}
    });
}

// ── 2) Control Flow Flattening Bypass Heuristics ──────────────────────
function installControlFlowBypass() {
    Java.perform(function () {
        // Identify flattened control flows by monitoring switch-case dispatch patterns
        // Common pattern: obfuscated code uses integer state variables to switch between blocks
        try {
            var AtomicInteger = Java.use("java.util.concurrent.atomic.AtomicInteger");
            var origAIGet = AtomicInteger.get;
            AtomicInteger.get.implementation = function () {
                var val = this.get();
                // If an AtomicInteger is being used to track state in a tight loop,
                // the state values will rapidly cycle - flag this pattern
                try {
                    var trace = Java.use("android.util.Log").getStackTraceString(new Java.use("java.lang.Exception").$new());
                    if (trace && trace.length > 50) {
                        var frames = trace.split("\n");
                        // If called from app code with repeating state pattern
                        if (frames.length > 3 && frames.some(function(f) { return f.indexOf("switch") > -1 || f.indexOf("case") > -1; })) {
                            if (once("cff-state-" + val)) {
                                reportDynamic("control_flow_flattening",
                                    "Possible control-flow flattening detected - state=" + val,
                                    [{ label: "state", value: String(val) }], "medium");
                            }
                        }
                    }
                } catch (e) {}
                return val;
            };
        } catch (e) {}

        // Hook Method.invoke which flattened code uses extensively
        try {
            var Method = Java.use("java.lang.reflect.Method");
            Method.invoke.implementation = function (obj, args) {
                var result = this.invoke(obj, args);
                try {
                    var mName = this.getName();
                    if (mName && once("invoke-" + mName)) {
                        reportDynamic("reflective_call",
                            "Reflective call detected: " + this.getDeclaringClass().getName() + "." + mName + "()",
                            [{ label: "method", value: String(mName), sensitive: false },
                             { label: "class", value: String(this.getDeclaringClass().getName()), sensitive: false }],
                            "medium");
                    }
                } catch (e) {}
                return result;
            };
        } catch (e) {}
    });
}

// ── 3) Reflection Detection & Dynamic Re-hooking ──────────────────────
function installReflectionDetection() {
    Java.perform(function () {
        // Hook Class.forName to detect dynamic class loading
        try {
            var Cls = Java.use("java.lang.Class");
            Cls.forName.overload("java.lang.String").implementation = function (className) {
                var result = this.forName(className);
                try {
                    var cn = String(className);
                    if (cn && cn.indexOf("hayo") === -1 && !cn.startsWith("java.") && !cn.startsWith("android.") && !cn.startsWith("dalvik.") && !cn.startsWith("kotlin.") && !cn.startsWith("okhttp") && !cn.startsWith("retrofit")) {
                        if (once("forname-" + cn)) {
                            reportDynamic("reflective_call",
                                "Class.forName: " + cn + " (possible dynamically resolved class)",
                                [{ label: "class", value: cn, sensitive: false }], "medium");
                            DE_OBFUSCATION.reflectionCalls++;
                        }
                    }
                } catch (e) {}
                return result;
            };
        } catch (e) {}

        // Hook ClassLoader.loadClass for dynamic class resolution
        try {
            var CL = Java.use("java.lang.ClassLoader");
            CL.loadClass.overload("java.lang.String").implementation = function (className) {
                var result = this.loadClass(className);
                try {
                    var cn = String(className);
                    if (cn && cn.indexOf("hayo") === -1 && !cn.startsWith("java.") && !cn.startsWith("android.") && !cn.startsWith("dalvik.") && !cn.startsWith("kotlin.")) {
                        if (once("clload-" + cn)) {
                            reportDynamic("reflective_call",
                                "ClassLoader.loadClass: " + cn,
                                [{ label: "class", value: cn, sensitive: false }], "medium");
                        }
                    }
                } catch (e) {}
                return result;
            };
        } catch (e) {}

        // Hook Method.invoke to detect reflectively called methods (already in CFF module)

        // Hook Field.set/get to detect reflective field access
        try {
            var Field = Java.use("java.lang.reflect.Field");
            Field.set.implementation = function (obj, value) {
                try {
                    var fName = this.getName();
                    if (fName && once("field-set-" + fName)) {
                        reportDynamic("reflective_call",
                            "Reflective field write: " + this.getDeclaringClass().getName() + "." + fName,
                            [{ label: "field", value: String(fName), sensitive: false }], "low");
                    }
                } catch (e) {}
                return this.set(obj, value);
            };
            Field.get.implementation = function (obj) {
                try {
                    var fName = this.getName();
                    if (fName && once("field-get-" + fName)) {
                        reportDynamic("reflective_call",
                            "Reflective field read: " + this.getDeclaringClass().getName() + "." + fName,
                            [{ label: "field", value: String(fName), sensitive: false }], "low");
                    }
                } catch (e) {}
                return this.get(obj);
            };
        } catch (e) {}

        // Dynamic re-hooking: when a reflectively loaded class is detected, auto-hook it
        // This is a best-effort mechanism that requires instrument.js's hookRegistration
        var rehookInterval = setInterval(function () {
            try {
                // Look for recently loaded classes that might be dynamically resolved
                Java.enumerateLoadedClasses({
                    onMatch: function (className) {
                        try {
                            // Check if this class was previously loaded via Class.forName
                            if (DE_OBFUSCATION.reflectionCalls > 0) {
                                // For app-specific classes, try re-hooking common patterns
                                if (className.indexOf("com.") === 0 || className.indexOf("org.") === 0) {
                                    var clazz = Java.use(className);
                                    if (clazz) {
                                        var methods = clazz.class.getDeclaredMethods();
                                        for (var i = 0; i < methods.length; i++) {
                                            try {
                                                var m = methods[i];
                                                var n = m.getName();
                                                var rt = m.getReturnType().getName();
                                                
                                                // Re-hook premium check methods if they appear on dynamically loaded classes
                                                var PREMIUM_NAMES = ["isPremium", "isPro", "isVip", "isSubscribed", "hasSubscription", "isUnlocked", "isPaid", "isActivated", "getSubscription", "getPlan", "getTier", "isGold", "isPlatinum", "isDiamond", "isElite"];
                                                for (var p = 0; p < PREMIUM_NAMES.length; p++) {
                                                    if (n === PREMIUM_NAMES[p] && (rt === "boolean" || rt === "java.lang.Boolean")) {
                                                        try {
                                                            clazz[n].overloads.forEach(function (ov) {
                                                                if (ov.returnType.className === "boolean") {
                                                                    ov.implementation = function () {
                                                                        reportDynamic("subscription_bypass",
                                                                            "Re-hooked premium gate via reflection on " + className + "." + n + "()",
                                                                            [], "critical");
                                                                        return true;
                                                                    };
                                                                    DE_OBFUSCATION.rehookedTargets++;
                                                                }
                                                            });
                                                        } catch (e) {}
                                                        break;
                                                    }
                                                }
                                            } catch (e) {}
                                        }
                                    }
                                }
                            }
                        } catch (e) {}
                    },
                    onComplete: function () {}
                });
            } catch (e) {}
        }, 15000); // Check every 15 seconds for dynamically loaded classes
    });
}

// ── 4) Call Stack Analysis Engine ─────────────────────────────────────
function installCallStackAnalysis() {
    Java.perform(function () {
        // Hook sensitive Android APIs and analyze call stacks
        var SENSITIVE_APIS = [
            { clazz: "android.telephony.TelephonyManager", method: "getDeviceId", args: [] },
            { clazz: "android.telephony.TelephonyManager", method: "getImei", args: [] },
            { clazz: "android.location.LocationManager", method: "getLastKnownLocation", args: ["java.lang.String"] },
            { clazz: "android.content.ClipboardManager", method: "getPrimaryClip", args: [] },
            { clazz: "android.provider.Settings$Secure", method: "getString", args: ["android.content.ContentResolver", "java.lang.String"] },
        ];

        SENSITIVE_APIS.forEach(function (api) {
            try {
                var clazz = Java.use(api.clazz);
                var method;
                try {
                    method = api.args.length > 0 ? clazz[api.method].overload.apply(clazz[api.method], api.args) : clazz[api.method];
                } catch (e) {
                    method = clazz[api.method];
                }
                if (method && method.implementation !== undefined) {
                    var origImpl = method.implementation;
                    method.implementation = function () {
                        try {
                            // Capture call stack via Exception
                            var stackTrace = Java.use("android.util.Log").getStackTraceString(new Java.use("java.lang.Exception").$new());
                            if (stackTrace && stackTrace.length > 50) {
                                var lines = stackTrace.split("\n");
                                var wrappedCallers = [];
                                for (var i = 0; i < lines.length && i < 8; i++) {
                                    var line = lines[i];
                                    // Look for obfuscated wrapper methods (short names, unusual patterns)
                                    if (line.indexOf(".a(") > -1 || line.indexOf(".b(") > -1 ||
                                        line.indexOf("$") > -1 || /\.\w{1,2}\(/.test(line)) {
                                        var m = line.match(/at\s+([^\s(]+)/);
                                        if (m && m[1]) {
                                            wrappedCallers.push(m[1]);
                                        }
                                    }
                                }
                                if (wrappedCallers.length > 0 && once("stack-api-" + api.clazz + "." + api.method)) {
                                    reportDynamic("obfuscation_wrapper_found",
                                        "Obfuscated wrapper detected calling " + api.clazz + "." + api.method + "(): " + wrappedCallers.join(", "),
                                        [{ label: "callers", value: wrappedCallers.join("\n"), sensitive: false },
                                         { label: "target", value: api.clazz + "." + api.method, sensitive: false }],
                                        "high");
                                }
                            }
                        } catch (e) {}
                        return origImpl.apply(this, arguments);
                    };
                }
            } catch (e) {}
        });
    });
}

// ── 5) API Signature Matching (not just name-based) ───────────────────
function installSignatureMatching() {
    Java.perform(function () {
        // Enumerate all loaded classes and identify potential premium/subscription
        // methods by their return type + parameter signature, not just name
        try {
            var subCheckCount = 0;
            Java.enumerateLoadedClasses({
                onMatch: function (className) {
                    // Only check app-level classes to reduce noise
                    if ((className.indexOf("com.") === 0 || className.indexOf("org.") === 0) &&
                        className.indexOf("hayo") === -1) {
                        try {
                            var clazz = Java.use(className);
                            var methods = clazz.class.getDeclaredMethods();
                            for (var i = 0; i < methods.length; i++) {
                                try {
                                    var m = methods[i];
                                    var rt = m.getReturnType().getName();
                                    var params = m.getParameterTypes();
                                    var name = m.getName();
                                    
                                    // Detect methods that:
                                    // 1) Return boolean and take no parameters → potential isXxx() check
                                    // 2) Return String (plan/tier/role) and take no params → potential getPlan()
                                    // 3) Return int/long (coins/points) and take no params → potential getBalance()
                                    var isBoolNoArg = (rt === "boolean" || rt === "java.lang.Boolean") && params.length === 0;
                                    var isStringNoArg = (rt === "java.lang.String" || rt === "java.lang.String") && params.length === 0;
                                    var isIntNoArg = (rt === "int" || rt === "java.lang.Integer" || rt === "long" || rt === "java.lang.Long") && params.length === 0;
                                    
                                    if (isBoolNoArg && name.indexOf("is") === 0 && name !== "is" && name !== "isEnabled" && name !== "isShown" && name !== "isShowing" && name !== "isFinishing" && name !== "isDestroyed") {
                                        // Even if the method name doesn't match our known list,
                                        // by signature pattern it's a premium/subscription candidate
                                        var sigStr = className + "." + name + "():" + rt;
                                        if (once("sig-boolean-" + sigStr) && subCheckCount < 100) {
                                            reportDynamic("signature_match_potential_premium",
                                                "Signature-matched potential premium check: " + sigStr,
                                                [{ label: "signature", value: sigStr, sensitive: false }],
                                                "info");
                                            subCheckCount++;
                                        }
                                    } else if (isStringNoArg && (name.indexOf("get") === 0 || name.indexOf("is") === 0) && 
                                               (name.indexOf("Plan") > -1 || name.indexOf("Tier") > -1 || name.indexOf("Role") > -1 || name.indexOf("Type") > -1 || name.indexOf("Level") > -1)) {
                                        var sigStr2 = className + "." + name + "():" + rt;
                                        if (once("sig-string-plan-" + sigStr2) && subCheckCount < 50) {
                                            reportDynamic("signature_match_plan_tier",
                                                "Signature-matched plan/tier getter: " + sigStr2,
                                                [{ label: "signature", value: sigStr2, sensitive: false }],
                                                "info");
                                            subCheckCount++;
                                        }
                                    }
                                } catch (e) {}
                            }
                        } catch (e) {}
                    }
                },
                onComplete: function () {}
            });
        } catch (e) {}
    });
}

// ── Startup ───────────────────────────────────────────────────────────
function reportDynamic(type, title, evidence, severity) {
    try {
        var payload = {
            kind: "finding",
            type: type,
            title: title,
            severity: severity,
            detail: title,
            evidence: evidence,
            phase: "dynamic"
        };
        send(payload);
    } catch (e) {}
}

// Reports a summary of obfuscation findings
function reportObfuscationSummary() {
    send({
        kind: "finding",
        type: "obfuscation_summary",
        title: "Obfuscation Analysis Summary",
        severity: "info",
        detail: "Strings decrypted: " + DE_OBFUSCATION.stringsDecrypted + 
                ", Reflection calls: " + DE_OBFUSCATION.reflectionCalls + 
                ", Re-hooked targets: " + DE_OBFUSCATION.rehookedTargets,
        evidence: [
            { label: "strings_decrypted", value: String(DE_OBFUSCATION.stringsDecrypted) },
            { label: "reflection_calls", value: String(DE_OBFUSCATION.reflectionCalls) },
            { label: "rehooked_targets", value: String(DE_OBFUSCATION.rehookedTargets) },
        ],
        phase: "dynamic"
    });
}

// Initialize all obfuscation bypass modules
Java.perform(function () {
    console.log("\n🟢 HAYO Obfuscation Bypass Engine engaged...\n");
    installStringDeobfuscation();
    installControlFlowBypass();
    installReflectionDetection();
    installCallStackAnalysis();
    // Signature matching runs on delayed timer to allow all classes to load
    setTimeout(installSignatureMatching, 5000);
    // Report summary after 30 seconds
    setTimeout(reportObfuscationSummary, 30000);
    console.log("\n🟢 Obfuscation bypass modules installed.\n");
});

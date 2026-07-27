/*
 * HAYO Cipher-7 — FINAL Premium Unlock System
 * ============================================
 * نظام شامل ومتقدم لفتح الميزات المميزة - الإصدار النهائي
 * 
 * الاستراتيجيات المُنفذة:
 * 1. SharedPreferences Bypass - تعديل القيم المحفوظة
 * 2. SQLite Database Bypass - تعديل قاعدة البيانات
 * 3. Network Response Modification - تعديل استجابات الشبكة
 * 4. Boolean/String Return Value Hooking - اعتراض القيم المُرجعة
 * 5. Activity onCreate Hook - تعديل عند بدء التطبيق
 * 6. Memory Patching - تعديل الذاكرة مباشرة
 * 7. Universal Method Hooking - اعتراض جميع الدوال
 */

"use strict";

var PREMIUM_EMAILS = ["fmf0038@gmail.com"];
var hookCount = 0;
var premiumActivated = false;

function log(message) {
    hookCount++;
    console.log("[FINAL_UNLOCK] " + message);
    send({
        type: "message",
        payload: {
            kind: "final_unlock",
            message: message,
            ts: Date.now(),
            hookCount: hookCount,
            premiumActivated: premiumActivated
        }
    });
}

// ═════════════════════════════════════════════════════════════════════════════
// الأقسام 1–5 تُثبَّت داخل Java.perform: المحرّك يحمّل السكربت بعد spawn وقبل resume،
// فاستدعاء Java.use في المستوى الأعلى كان يفشل صامتاً (try/catch) فلا يُثبَّت أي خطّاف.
// ═════════════════════════════════════════════════════════════════════════════
Java.perform(function () {

// ─────────────────────────────────────────────────────────────────────────────
// 1. SharedPreferences Bypass - تعديل القيم المحفوظة
// ─────────────────────────────────────────────────────────────────────────────

try {
    var SharedPreferences = Java.use("android.content.SharedPreferences");
    
    SharedPreferences.getBoolean.implementation = function(key, defValue) {
        var result = this.getBoolean(key, defValue);
        
        if (key.indexOf("premium") !== -1 || 
            key.indexOf("subscription") !== -1 ||
            key.indexOf("pro") !== -1 ||
            key.indexOf("paid") !== -1 ||
            key.indexOf("vip") !== -1 ||
            key.indexOf("unlock") !== -1 ||
            key.indexOf("billing") !== -1) {
            
            log("SharedPreferences.getBoolean(" + key + ") -> true");
            return true;
        }
        
        if (key.indexOf("free") !== -1 || 
            key.indexOf("trial") !== -1 ||
            key.indexOf("limit") !== -1 ||
            key.indexOf("restrict") !== -1 ||
            key.indexOf("block") !== -1) {
            
            log("SharedPreferences.getBoolean(" + key + ") -> false");
            return false;
        }
        
        return result;
    };
    
    SharedPreferences.getString.implementation = function(key, defValue) {
        var result = this.getString(key, defValue);
        
        if (key.indexOf("subscription") !== -1 || 
            key.indexOf("tier") !== -1 ||
            key.indexOf("plan") !== -1 ||
            key.indexOf("level") !== -1 ||
            key.indexOf("status") !== -1 ||
            key.indexOf("type") !== -1) {
            
            if (result === "free" || result === "basic" || result === "trial" || result === "standard" || result === "starter") {
                log("SharedPreferences.getString(" + key + ") -> premium");
                return "premium";
            }
        }
        
        if (key.indexOf("email") !== -1) {
            for (var i = 0; i < PREMIUM_EMAILS.length; i++) {
                if (result === PREMIUM_EMAILS[i]) {
                    log("Premium email found: " + result);
                    premiumActivated = true;
                }
            }
        }
        
        return result;
    };
    
    SharedPreferences.getInt.implementation = function(key, defValue) {
        var result = this.getInt(key, defValue);
        
        if (key.indexOf("quota") !== -1 || 
            key.indexOf("limit") !== -1 ||
            key.indexOf("remaining") !== -1 ||
            key.indexOf("count") !== -1 ||
            key.indexOf("max") !== -1 ||
            key.indexOf("requests") !== -1 ||
            key.indexOf("messages") !== -1) {
            
            if (result < 1000000) {
                log("SharedPreferences.getInt(" + key + ") -> 999999999");
                return 999999999;
            }
        }
        
        return result;
    };
    
    SharedPreferences.getLong.implementation = function(key, defValue) {
        var result = this.getLong(key, defValue);
        
        if (key.indexOf("quota") !== -1 || 
            key.indexOf("limit") !== -1 ||
            key.indexOf("remaining") !== -1 ||
            key.indexOf("expiry") !== -1 ||
            key.indexOf("timestamp") !== -1 ||
            key.indexOf("time") !== -1 ||
            key.indexOf("date") !== -1) {
            
            if (result < 1000000000) {
                log("SharedPreferences.getLong(" + key + ") -> 999999999999");
                return 999999999999;
            }
        }
        
        return result;
    };
    
    log("SharedPreferences bypass installed");
} catch (e) {
    log("Failed to hook SharedPreferences: " + e);
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. SQLite Database Bypass - تعديل قاعدة البيانات
// ─────────────────────────────────────────────────────────────────────────────

try {
    var SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");
    
    SQLiteDatabase.rawQuery.overload('java.lang.String', '[Ljava.lang.String;').implementation = function(sql, selectionArgs) {
        var sqlStr = sql.toString();
        
        if (sqlStr.indexOf("subscription") !== -1 || 
            sqlStr.indexOf("premium") !== -1 ||
            sqlStr.indexOf("tier") !== -1 ||
            sqlStr.indexOf("plan") !== -1 ||
            sqlStr.indexOf("user") !== -1 ||
            sqlStr.indexOf("account") !== -1 ||
            sqlStr.indexOf("billing") !== -1) {
            
            log("SQLite.rawQuery: " + sqlStr);
            
            var modifiedSql = sqlStr
                .replace(/tier\s*=\s*['"]free['"]/g, "tier = 'premium'")
                .replace(/tier\s*=\s*['"]basic['"]/g, "tier = 'premium'")
                .replace(/subscription\s*=\s*['"]free['"]/g, "subscription = 'premium'")
                .replace(/plan\s*=\s*['"]free['"]/g, "plan = 'premium'")
                .replace(/is_premium\s*=\s*0/g, "is_premium = 1")
                .replace(/is_premium\s*=\s*false/g, "is_premium = true")
                .replace(/is_premium\s*=\s*'false'/g, "is_premium = 'true'")
                .replace(/has_premium\s*=\s*0/g, "has_premium = 1")
                .replace(/has_premium\s*=\s*false/g, "has_premium = true")
                .replace(/quota\s*<\s*\d+/g, "quota < 999999999")
                .replace(/limit\s*<\s*\d+/g, "limit < 999999999")
                .replace(/remaining\s*<\s*\d+/g, "remaining < 999999999");
            
            if (modifiedSql !== sqlStr) {
                log("Modified SQL: " + modifiedSql);
                return this.rawQuery(modifiedSql, selectionArgs);
            }
        }
        
        return this.rawQuery(sql, selectionArgs);
    };
    
    log("SQLite bypass installed");
} catch (e) {
    log("Failed to hook SQLite: " + e);
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Network Response Modification - تعديل استجابات الشبكة
// ─────────────────────────────────────────────────────────────────────────────

try {
    var HttpURLConnection = Java.use("java.net.HttpURLConnection");
    
    HttpURLConnection.getInputStream.implementation = function() {
        var url = this.getURL().toString();
        var originalStream = this.getInputStream();
        
        if (url.indexOf("subscription") !== -1 || 
            url.indexOf("billing") !== -1 ||
            url.indexOf("premium") !== -1 ||
            url.indexOf("account") !== -1 ||
            url.indexOf("user") !== -1 ||
            url.indexOf("auth") !== -1 ||
            url.indexOf("firebase") !== -1 ||
            url.indexOf("googleapis") !== -1 ||
            url.indexOf("android.googleapis.com") !== -1) {
            
            log("Intercepting response from: " + url);
            
            try {
                var BufferedReader = Java.use("java.io.BufferedReader");
                var InputStreamReader = Java.use("java.io.InputStreamReader");
                var reader = BufferedReader.$new(InputStreamReader.$new(originalStream));
                var response = "";
                var line;
                while ((line = reader.readLine()) !== null) {
                    response += line;
                }
                
                var modified = response
                    .replace(/"subscription":\s*"free"/g, '"subscription":"premium"')
                    .replace(/"subscription":\s*"basic"/g, '"subscription":"premium"')
                    .replace(/"tier":\s*"free"/g, '"tier":"premium"')
                    .replace(/"tier":\s*"basic"/g, '"tier":"premium"')
                    .replace(/"plan":\s*"free"/g, '"plan":"premium"')
                    .replace(/"isPremium":\s*false/g, '"isPremium":true')
                    .replace(/"hasPremium":\s*false/g, '"hasPremium":true')
                    .replace(/"premium":\s*false/g, '"premium":true')
                    .replace(/"is_premium":\s*false/g, '"is_premium":true')
                    .replace(/"has_premium":\s*false/g, '"has_premium":true')
                    .replace(/"quota":\s*\d+/g, '"quota":999999999')
                    .replace(/"limit":\s*\d+/g, '"limit":999999999')
                    .replace(/"remaining":\s*\d+/g, '"remaining":999999999')
                    .replace(/"requests_remaining":\s*\d+/g, '"requests_remaining":999999999')
                    .replace(/"expiry":\s*\d+/g, '"expiry":999999999999')
                    .replace(/"status":\s*"expired"/g, '"status":"active"')
                    .replace(/"status":\s*"cancelled"/g, '"status":"active"')
                    .replace(/"status":\s*"inactive"/g, '"status":"active"');
                
                if (modified !== response) {
                    log("Modified response for premium");
                    premiumActivated = true;
                    
                    var ByteArrayInputStream = Java.use("java.io.ByteArrayInputStream");
                    var bytes = Java.array('byte', modified.split('').map(function(c) { return c.charCodeAt(0); }));
                    return ByteArrayInputStream.$new(bytes);
                }
            } catch (e) {
                log("Failed to modify response: " + e);
            }
        }
        
        return originalStream;
    };
    
    log("Network response bypass installed");
} catch (e) {
    log("Failed to hook network response: " + e);
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Boolean/String Return Value Hooking - اعتراض القيم المُرجعة
// ─────────────────────────────────────────────────────────────────────────────

try {
    var Boolean = Java.use("java.lang.Boolean");
    
    Boolean.valueOf.overload('java.lang.String').implementation = function(s) {
        var str = s.toString();
        
        if (str.indexOf("premium") !== -1 || 
            str.indexOf("paid") !== -1 || 
            str.indexOf("subscription") !== -1 ||
            str.indexOf("pro") !== -1 ||
            str.indexOf("vip") !== -1) {
            
            log("Boolean.valueOf(" + str + ") -> true");
            return Boolean.valueOf(true);
        }
        
        return Boolean.valueOf(s);
    };
    
    Boolean.parseBoolean.implementation = function(s) {
        var str = s.toString();
        
        if (str.indexOf("premium") !== -1 || 
            str.indexOf("paid") !== -1 || 
            str.indexOf("subscription") !== -1) {
            
            log("Boolean.parseBoolean(" + str + ") -> true");
            return true;
        }
        
        return Boolean.parseBoolean(s);
    };
    
    log("Boolean bypass installed");
} catch (e) {
    log("Failed to hook Boolean: " + e);
}

try {
    var String = Java.use("java.lang.String");
    
    String.contains.implementation = function(charSequence) {
        var str = this.toString();
        var target = charSequence.toString();
        
        if (target === "premium" || target === "paid" || target === "subscription") {
            log("String.contains('" + target + "') -> true");
            return true;
        }
        
        if (target === "free" || target === "trial" || target === "basic") {
            log("String.contains('" + target + "') -> false");
            return false;
        }
        
        return this.contains(charSequence);
    };
    
    log("String bypass installed");
} catch (e) {
    log("Failed to hook String: " + e);
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Activity onCreate Hook - تعديل عند بدء التطبيق
// ─────────────────────────────────────────────────────────────────────────────

try {
    var Activity = Java.use("android.app.Activity");
    
    Activity.onCreate.overload('android.os.Bundle').implementation = function(savedInstanceState) {
        log("Activity created: " + this.getClass().getName());
        
        try {
            var prefs = this.getSharedPreferences("preferences", 0);
            var editor = prefs.edit();
            
            editor.putBoolean("premium", true);
            editor.putBoolean("has_premium", true);
            editor.putBoolean("is_premium", true);
            editor.putString("subscription", "premium");
            editor.putString("tier", "premium");
            editor.putString("plan", "premium");
            editor.putString("status", "active");
            editor.putInt("quota", 999999999);
            editor.putInt("limit", 999999999);
            editor.putLong("expiry", 999999999999);
            
            editor.commit();
            log("Modified SharedPreferences for premium");
            premiumActivated = true;
        } catch (e) {
            log("Failed to modify SharedPreferences: " + e);
        }
        
        return this.onCreate(savedInstanceState);
    };
    
    log("Activity onCreate hook installed");
} catch (e) {
    log("Failed to hook Activity: " + e);
}

}); // ← نهاية Java.perform (تغليف الأقسام 1–5)

// ─────────────────────────────────────────────────────────────────────────────
// 6. Memory Patching - تعديل الذاكرة مباشرة
// ─────────────────────────────────────────────────────────────────────────────

try {
    setTimeout(function() {
        log("Starting memory scan for premium variables...");
        
        Java.perform(function() {
            var pattern = "free";
            var patternBytes = [];
            for (var i = 0; i < pattern.length; i++) {
                patternBytes.push(pattern.charCodeAt(i));
            }
            
            var ranges = Process.enumerateRanges('rw-');
            var modifiedCount = 0;
            
            for (var i = 0; i < ranges.length; i++) {
                try {
                    var range = ranges[i];
                    if (range.size > 0x100000) continue;
                    
                    var data = Memory.readByteArray(range.base, range.size);
                    
                    for (var j = 0; j < data.length - patternBytes.length; j++) {
                        var match = true;
                        for (var k = 0; k < patternBytes.length; k++) {
                            if (data[j + k] !== patternBytes[k]) {
                                match = false;
                                break;
                            }
                        }
                        
                        if (match) {
                            var address = range.base.add(j);
                            log("Found 'free' at: " + address);
                            
                            try {
                                Memory.writeUtf8String(address, "premium");
                                log("Modified to 'premium' at: " + address);
                                premiumActivated = true;
                                modifiedCount++;
                                
                                if (modifiedCount >= 10) break;
                            } catch (e) {
                                log("Failed to modify memory: " + e);
                            }
                        }
                    }
                    
                    if (modifiedCount >= 10) break;
                } catch (e) {
                }
            }
            
            log("Memory scan complete. Modified: " + modifiedCount);
        });
    }, 5000);
    
    log("Memory patching scheduled");
} catch (e) {
    log("Failed to schedule memory patching: " + e);
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. Universal Method Hooking - اعتراض جميع الدوال
// ─────────────────────────────────────────────────────────────────────────────

try {
    var hookMethod = function(className, methodName) {
        try {
            var clazz = Java.use(className);
            
            if (clazz[methodName] && typeof clazz[methodName] === 'function') {
                var original = clazz[methodName];
                
                clazz[methodName].implementation = function() {
                    var result = original.apply(this, arguments);
                    
                    if (typeof result === 'boolean' && result === false) {
                        log(className + "." + methodName + "() -> true");
                        return true;
                    }
                    
                    if (typeof result === 'string' && 
                        (result === 'free' || result === 'basic' || result === 'trial' || result === 'standard')) {
                        log(className + "." + methodName + "() -> premium");
                        return 'premium';
                    }
                    
                    return result;
                };
                
                log("Hooked: " + className + "." + methodName);
            }
        } catch (e) {
        }
    };
    
    var commonClasses = [
        "android.content.SharedPreferences",
        "android.database.sqlite.SQLiteDatabase",
        "java.lang.Boolean",
        "java.lang.String"
    ];
    
    for (var i = 0; i < commonClasses.length; i++) {
        try {
            var clazz = Java.use(commonClasses[i]);
            var methods = clazz.class.getDeclaredMethods();
            
            for (var j = 0; j < methods.length; j++) {
                var method = methods[j];
                var methodName = method.getName();
                
                if (methodName.indexOf("is") === 0 || 
                    methodName.indexOf("has") === 0 ||
                    methodName.indexOf("check") === 0 ||
                    methodName.indexOf("get") === 0 ||
                    methodName.indexOf("query") === 0) {
                    
                    hookMethod(commonClasses[i], methodName);
                }
            }
        } catch (e) {
        }
    }
    
    log("Universal method hooking installed");
} catch (e) {
    log("Failed to hook generic methods: " + e);
}

log("FINAL Premium Unlock System loaded successfully");
log("Total hooks: " + hookCount);
log("Premium status: " + (premiumActivated ? "ACTIVATED" : "PENDING"));

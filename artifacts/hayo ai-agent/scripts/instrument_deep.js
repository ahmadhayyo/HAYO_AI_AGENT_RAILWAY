/*
 * HAYO Cipher-7 — ULTIMATE DEEP INSTRUMENTATION ENGINE (instrument_deep.js)
 * =========================================================================
 * Comprehensive Frida hooks for Android dynamic security analysis:
 *   1. Crypto: Java Ciphers, Keys, IVs, KeyStore, PBE, and Native BoringSSL/OpenSSL hooks
 *   2. De-obfuscation: Runtime String constructors, Base64 decoders, Reflection
 *   3. Network: OkHttp, Retrofit, Volley, Ktor, gRPC, WebSocket, Cronet, HttpURLConnection
 *   4. Auth & Tokens: SharedPreferences, AccountManager, JWT, OAuth, Session Cookies
 *   5. Storage & Databases: EncryptedSharedPreferences, SQLite, SQLCipher, Realm, Room, DataStore
 *   6. Cloud SDKs: Firebase Auth, Firestore, RemoteConfig, AWS, Supabase, Google Sign-In
 *   7. Billing & Premium: Play Billing v3-v6, IAB, reflection premium bypass
 *   8. SSL Unpinning & Anti-Tamper: Universal X509/Conscrypt/OkHttp bypass + RootBeer bypass
 *   9. Exfiltration & Leaks: Clipboard, Intent extras, ContentResolver, Android Log, WebView JS bridges
 *  10. Memory Scanner v2: Validated pattern extraction (API Keys, JWTs, Cloud Secrets)
 *  11. Runtime Auto-Hook: Dynamic target package introspection
 */
"use strict";

var HAYO = {
    findings: [],
    secrets: {},
    seen: new Set(),
    startTime: Date.now()
};

function emit(type, payload) {
    try {
        var key = type + "|" + JSON.stringify(payload).slice(0, 200);
        if (HAYO.seen.has(key)) return;
        HAYO.seen.add(key);
        send({
            type: "message",
            payload: Object.assign({
                kind: "finding",
                type: type,
                ts: Date.now() - HAYO.startTime
            }, payload)
        });
    } catch (e) {}
}

function captureHex(arr) {
    if (!arr) return "";
    try {
        var bytes = [];
        for (var i = 0; i < Math.min(arr.length, 128); i++) {
            var b = arr[i] & 0xff;
            bytes.push((b < 16 ? "0" : "") + b.toString(16));
        }
        return bytes.join("") + (arr.length > 128 ? "..." : "");
    } catch (e) {
        return "[unreadable]";
    }
}

function captureString(s) {
    if (!s) return "";
    try {
        s = String(s);
        return s.length > 300 ? s.slice(0, 300) + "..." : s;
    } catch (e) {
        return "";
    }
}

function tryHook(className, fn, wrapper) {
    try {
        var clz = Java.use(className);
        if (typeof wrapper === "function") {
            wrapper(clz);
        }
    } catch (e) {
        // silently skip unavailable classes
    }
}

// Regex patterns for runtime secret detector
var SECRET_PATTERNS = [
    /AIzaSy[A-Za-z0-9_\-]{33}/,                       // Google API Key
    /AKIA[0-9A-Z]{16}/,                               // AWS Access Key ID
    /sk_live_[0-9a-zA-Z]{24,}/,                        // Stripe Live Key
    /eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}/,  // JWT Token
    /-----BEGIN (RSA|EC|PRIVATE|CERTIFICATE) KEY-----/,// PEM keys
    /ghp_[A-Za-z0-9]{36}/,                             // GitHub Personal Token
    /xox[baprs]-[0-9a-zA-Z]{10,}/,                     // Slack Token
    /https:\/\/[a-z0-9\-]+\.supabase\.co/i,            // Supabase URL
    /hf_[A-Za-z0-9]{34,}/,                             // HuggingFace Token
    /1:\d{10,12}:android:[a-f0-9]{16,32}/             // Firebase App ID
];

function isClassNameOrNoise(s) {
    if (!s || typeof s !== "string") return true;
    if (s.indexOf("/") >= 0 || s.indexOf(";") >= 0 || s.indexOf("Lcom/") >= 0 || s.indexOf("Landroid/") >= 0) return true;
    if (s.endsWith("_class") || s.endsWith("Class") || s.startsWith("class ")) return true;
    if (s.indexOf(".") >= 2 && !s.startsWith("http") && !s.includes(" ")) return true;
    return false;
}

function checkAndEmitSecret(source, text, severity) {
    if (!text || typeof text !== "string") return;
    for (var i = 0; i < SECRET_PATTERNS.length; i++) {
        var match = text.match(SECRET_PATTERNS[i]);
        if (match) {
            var val = match[0];
            if (isClassNameOrNoise(val)) continue;
            emit("validated_secret_found", {
                source: source,
                matched_text: val,
                snippet: captureString(text),
                severity: severity || "critical"
            });
            break;
        }
    }
}

// =========================================================================
//  1. CRYPTO HOOKS — Java Ciphers, Keys, IVs, KeyStore, PBE & Native BoringSSL
// =========================================================================
function hookCrypto() {
    // 1.1 Cipher.init & Cipher.doFinal
    tryHook("javax.crypto.Cipher", null, function(Cipher) {
        Cipher.init.overloads.forEach(function(ov) {
            ov.implementation = function() {
                try {
                    var mode = arguments[0]; // 1=ENCRYPT, 2=DECRYPT
                    var key = arguments[1];
                    var modeStr = (mode === 1) ? "ENCRYPT" : (mode === 2) ? "DECRYPT" : String(mode);
                    var algo = this.getAlgorithm();
                    var keyHex = "";
                    if (key && key.getEncoded) {
                        keyHex = captureHex(key.getEncoded());
                    }
                    var ivHex = "";
                    if (arguments.length > 2 && arguments[2]) {
                        var spec = arguments[2];
                        if (spec.getIV) {
                            ivHex = captureHex(spec.getIV());
                        }
                    }
                    emit("crypto_cipher_init", {
                        mode: modeStr,
                        algorithm: algo,
                        key_hex: keyHex,
                        iv_hex: ivHex,
                        key_algorithm: key ? String(key.getAlgorithm()) : "?",
                        severity: "critical"
                    });
                } catch (e) {}
                return ov.apply(this, arguments);
            };
        });

        Cipher.doFinal.overloads.forEach(function(ov) {
            ov.implementation = function() {
                var result = ov.apply(this, arguments);
                try {
                    var algo = this.getAlgorithm();
                    var info = { algorithm: algo };
                    if (arguments[0] && arguments[0].getBytes) {
                        info.input_hex = captureHex(arguments[0].getBytes());
                    } else if (arguments[0] && Array.isArray(arguments[0])) {
                        info.input_hex = captureHex(arguments[0]);
                    }
                    if (result) {
                        info.output_hex = captureHex(result);
                    }
                    emit("crypto_cipher_dofinal", info);
                } catch (e) {}
                return result;
            };
        });
    });

    // 1.2 SecretKeySpec & KeyFactory & PBEKeySpec
    tryHook("javax.crypto.spec.SecretKeySpec", null, function(SKS) {
        SKS.$init.overloads.forEach(function(ov) {
            ov.implementation = function() {
                var result = ov.apply(this, arguments);
                try {
                    if (arguments[0]) {
                        var keyHex = captureHex(arguments[0]);
                        var algo = arguments[1] || "?";
                        emit("crypto_key", {
                            key_hex: keyHex,
                            algorithm: String(algo),
                            severity: "critical"
                        });
                    }
                } catch (e) {}
                return result;
            };
        });
    });

    tryHook("javax.crypto.spec.PBEKeySpec", null, function(PBE) {
        PBE.$init.overloads.forEach(function(ov) {
            ov.implementation = function() {
                try {
                    var passChars = arguments[0];
                    var passStr = passChars ? String.fromCharCode.apply(null, passChars) : "";
                    var saltHex = arguments.length > 1 && arguments[1] ? captureHex(arguments[1]) : "";
                    var iter = arguments.length > 2 ? arguments[2] : 0;
                    var keyLen = arguments.length > 3 ? arguments[3] : 0;
                    emit("crypto_pbe_spec", {
                        password: captureString(passStr),
                        salt_hex: saltHex,
                        iterations: iter,
                        key_length: keyLen,
                        severity: "critical"
                    });
                } catch (e) {}
                return ov.apply(this, arguments);
            };
        });
    });

    tryHook("javax.crypto.SecretKeyFactory", null, function(SKF) {
        SKF.generateSecret.implementation = function(spec) {
            var secret = this.generateSecret(spec);
            try {
                if (secret && secret.getEncoded) {
                    emit("crypto_pbe_generated_key", {
                        algorithm: this.getAlgorithm(),
                        key_hex: captureHex(secret.getEncoded()),
                        severity: "critical"
                    });
                }
            } catch (e) {}
            return secret;
        };
    });

    // 1.3 KeyStore & KeyGenParameterSpec
    tryHook("java.security.KeyStore", null, function(KS) {
        KS.load.implementation = function(stream, password) {
            try {
                var pwStr = password ? String.fromCharCode.apply(null, password) : "[none]";
                emit("keystore_load", {
                    type: this.getType(),
                    password: captureString(pwStr),
                    severity: "high"
                });
            } catch (e) {}
            return this.load(stream, password);
        };

        KS.getKey.implementation = function(alias, password) {
            var key = this.getKey(alias, password);
            try {
                var pwStr = password ? String.fromCharCode.apply(null, password) : "[none]";
                emit("keystore_get_key", {
                    alias: alias,
                    password: captureString(pwStr),
                    key_hex: key && key.getEncoded ? captureHex(key.getEncoded()) : "[keystore_protected]",
                    severity: "critical"
                });
            } catch (e) {}
            return key;
        };

        KS.getEntry.implementation = function(alias, param) {
            var entry = this.getEntry(alias, param);
            try {
                emit("keystore_get_entry", {
                    alias: alias,
                    entry_type: entry ? entry.getClass().getName() : "null",
                    severity: "high"
                });
            } catch (e) {}
            return entry;
        };

        KS.setKeyEntry.overloads.forEach(function(ov) {
            ov.implementation = function() {
                try {
                    var alias = arguments[0];
                    emit("keystore_set_key_entry", {
                        alias: String(alias),
                        severity: "high"
                    });
                } catch (e) {}
                return ov.apply(this, arguments);
            };
        });
    });

    tryHook("android.security.keystore.KeyGenParameterSpec$Builder", null, function(B) {
        B.build.implementation = function() {
            var spec = this.build();
            try {
                emit("keystore_keygen_spec", {
                    keystore_alias: spec.getKeystoreAlias(),
                    key_size: spec.getKeySize(),
                    purposes: spec.getPurposes(),
                    block_modes: spec.getBlockModes() ? spec.getBlockModes().join(",") : "",
                    encryption_paddings: spec.getEncryptionPaddings() ? spec.getEncryptionPaddings().join(",") : "",
                    severity: "high"
                });
            } catch (e) {}
            return spec;
        };
    });

    // 1.4 IvParameterSpec, KeyPairGenerator, Mac, MessageDigest, Signature
    tryHook("javax.crypto.spec.IvParameterSpec", null, function(IvPS) {
        IvPS.$init.overloads.forEach(function(ov) {
            ov.implementation = function() {
                try {
                    if (arguments[0]) {
                        emit("crypto_iv", {
                            iv_hex: captureHex(arguments[0]),
                            severity: "high"
                        });
                    }
                } catch (e) {}
                return ov.apply(this, arguments);
            };
        });
    });

    tryHook("java.security.KeyPairGenerator", null, function(KPG) {
        KPG.generateKeyPair.implementation = function() {
            var kp = this.generateKeyPair();
            try {
                var pub = kp.getPublic();
                var priv = kp.getPrivate();
                emit("crypto_keypair", {
                    algorithm: this.getAlgorithm(),
                    public_encoded: pub ? captureHex(pub.getEncoded()) : "",
                    private_encoded: priv ? captureHex(priv.getEncoded()) : "",
                    severity: "critical"
                });
            } catch (e) {}
            return kp;
        };
    });

    tryHook("javax.crypto.Mac", null, function(Mac) {
        Mac.init.overloads.forEach(function(ov) {
            ov.implementation = function(key) {
                try {
                    if (key && key.getEncoded) {
                        emit("crypto_mac_key", {
                            algorithm: this.getAlgorithm(),
                            key_hex: captureHex(key.getEncoded()),
                            severity: "high"
                        });
                    }
                } catch (e) {}
                return ov.apply(this, arguments);
            };
        });
    });

    tryHook("java.security.MessageDigest", null, function(MD) {
        MD.digest.overloads.forEach(function(ov) {
            ov.implementation = function() {
                var result = ov.apply(this, arguments);
                try {
                    emit("crypto_hash", {
                        algorithm: this.getAlgorithm(),
                        output_hex: captureHex(result)
                    });
                } catch (e) {}
                return result;
            };
        });
    });

    tryHook("java.security.Signature", null, function(Sig) {
        Sig.initSign.overloads.forEach(function(ov) {
            ov.implementation = function() {
                try {
                    emit("crypto_signature_initsign", { algorithm: this.getAlgorithm(), severity: "high" });
                } catch (e) {}
                return ov.apply(this, arguments);
            };
        });
        Sig.initVerify.overloads.forEach(function(ov) {
            ov.implementation = function() {
                try {
                    emit("crypto_signature_initverify", { algorithm: this.getAlgorithm(), severity: "medium" });
                } catch (e) {}
                return ov.apply(this, arguments);
            };
        });
    });

    // 1.5 Native BoringSSL / OpenSSL Hooks
    hookNativeBoringSSL();
}

function hookNativeBoringSSL() {
    try {
        var modules = Process.enumerateModules();
        var cryptoLibs = [];
        for (var i = 0; i < modules.length; i++) {
            var mName = modules[i].name.toLowerCase();
            if (mName.indexOf("crypto") >= 0 || mName.indexOf("ssl") >= 0 || mName.indexOf("native") >= 0) {
                cryptoLibs.push(modules[i]);
            }
        }

        cryptoLibs.forEach(function(mod) {
            // Hook EVP_EncryptInit_ex / EVP_DecryptInit_ex
            ["EVP_EncryptInit_ex", "EVP_DecryptInit_ex"].forEach(function(symName) {
                var addr = Module.findExportByName(mod.name, symName);
                if (addr) {
                    Interceptor.attach(addr, {
                        onEnter: function(args) {
                            var keyPtr = args[3];
                            var ivPtr = args[4];
                            var keyHex = keyPtr.isNull() ? "" : captureHex(keyPtr.readByteArray(32));
                            var ivHex = ivPtr.isNull() ? "" : captureHex(ivPtr.readByteArray(16));
                            emit("native_evp_cipher_init", {
                                function: symName,
                                module: mod.name,
                                key_hex: keyHex,
                                iv_hex: ivHex,
                                severity: "critical"
                            });
                        }
                    });
                }
            });

            // Hook EVP_CipherUpdate
            var evpUpdateAddr = Module.findExportByName(mod.name, "EVP_CipherUpdate");
            if (evpUpdateAddr) {
                Interceptor.attach(evpUpdateAddr, {
                    onEnter: function(args) {
                        try {
                            var inPtr = args[3];
                            var inl = args[4].toInt32();
                            if (!inPtr.isNull() && inl > 0 && inl <= 1024) {
                                var inHex = captureHex(inPtr.readByteArray(Math.min(inl, 128)));
                                emit("native_evp_cipher_update", {
                                    module: mod.name,
                                    input_len: inl,
                                    input_hex: inHex,
                                    severity: "high"
                                });
                            }
                        } catch (e) {}
                    }
                });
            }

            // Hook RSA_private_decrypt
            var rsaDecAddr = Module.findExportByName(mod.name, "RSA_private_decrypt");
            if (rsaDecAddr) {
                Interceptor.attach(rsaDecAddr, {
                    onEnter: function(args) {
                        try {
                            var flen = args[0].toInt32();
                            var fromPtr = args[1];
                            if (!fromPtr.isNull() && flen > 0) {
                                var fromHex = captureHex(fromPtr.readByteArray(Math.min(flen, 128)));
                                emit("native_rsa_private_decrypt", {
                                    module: mod.name,
                                    len: flen,
                                    input_hex: fromHex,
                                    severity: "critical"
                                });
                            }
                        } catch (e) {}
                    }
                });
            }

            // Hook AES_set_encrypt_key / AES_set_decrypt_key
            ["AES_set_encrypt_key", "AES_set_decrypt_key"].forEach(function(symName) {
                var addr = Module.findExportByName(mod.name, symName);
                if (addr) {
                    Interceptor.attach(addr, {
                        onEnter: function(args) {
                            try {
                                var keyPtr = args[0];
                                var bits = args[1].toInt32();
                                var bytesLen = Math.min(Math.floor(bits / 8), 64);
                                var keyHex = keyPtr.isNull() ? "" : captureHex(keyPtr.readByteArray(bytesLen));
                                emit("native_aes_set_key", {
                                    function: symName,
                                    module: mod.name,
                                    bits: bits,
                                    key_hex: keyHex,
                                    severity: "critical"
                                });
                            } catch (e) {}
                        }
                    });
                }
            });

            // Hook HMAC_Init_ex
            var hmacAddr = Module.findExportByName(mod.name, "HMAC_Init_ex");
            if (hmacAddr) {
                Interceptor.attach(hmacAddr, {
                    onEnter: function(args) {
                        try {
                            var keyPtr = args[1];
                            var len = args[2].toInt32();
                            if (!keyPtr.isNull() && len > 0) {
                                var keyHex = captureHex(keyPtr.readByteArray(Math.min(len, 64)));
                                emit("native_hmac_init", {
                                    module: mod.name,
                                    key_len: len,
                                    key_hex: keyHex,
                                    severity: "high"
                                });
                            }
                        } catch (e) {}
                    }
                });
            }

            // Hook PKCS5_PBKDF2_HMAC
            var pbkdf2Addr = Module.findExportByName(mod.name, "PKCS5_PBKDF2_HMAC");
            if (pbkdf2Addr) {
                Interceptor.attach(pbkdf2Addr, {
                    onEnter: function(args) {
                        try {
                            var passPtr = args[0];
                            var passLen = args[1].toInt32();
                            var saltPtr = args[2];
                            var saltLen = args[3].toInt32();
                            var iter = args[4].toInt32();
                            var passStr = (!passPtr.isNull() && passLen > 0) ? passPtr.readUtf8String(passLen) : "";
                            var saltHex = (!saltPtr.isNull() && saltLen > 0) ? captureHex(saltPtr.readByteArray(Math.min(saltLen, 32))) : "";
                            emit("native_pbkdf2", {
                                module: mod.name,
                                pass: captureString(passStr),
                                salt_hex: saltHex,
                                iterations: iter,
                                severity: "critical"
                            });
                        } catch (e) {}
                    }
                });
            }

            // Native SSL Unpinning Hooks
            ["SSL_CTX_set_custom_verify", "SSL_set_verify"].forEach(function(symName) {
                var addr = Module.findExportByName(mod.name, symName);
                if (addr) {
                    Interceptor.attach(addr, {
                        onEnter: function(args) {
                            try {
                                emit("ssl_unpin", {
                                    target: "native:" + symName,
                                    module: mod.name,
                                    bypassed: true,
                                    severity: "high"
                                });
                            } catch (e) {}
                        }
                    });
                }
            });
        });
    } catch (e) {}
}

// =========================================================================
//  2. STRING DE-OBFUSCATION & BASE64 HOOKS
// =========================================================================
function hookDeobfuscation() {
    // 2.1 String Constructor from byte arrays
    tryHook("java.lang.String", null, function(Str) {
        Str.$init.overloads.forEach(function(ov) {
            ov.implementation = function() {
                var res = ov.apply(this, arguments);
                try {
                    if (arguments[0] && Array.isArray(arguments[0])) {
                        var s = this.toString();
                        checkAndEmitSecret("String_constructor", s, "high");
                        if (/(http:\/\/|https:\/\/|api_key|token|bearer|secret|password)/i.test(s)) {
                            emit("string_deobfuscated", {
                                value: captureString(s),
                                severity: "high"
                            });
                        }
                    }
                } catch (e) {}
                return res;
            };
        });
    });

    // 2.2 Android & Java Base64 Decoders
    tryHook("android.util.Base64", null, function(B64) {
        B64.decode.overloads.forEach(function(ov) {
            ov.implementation = function() {
                var res = ov.apply(this, arguments);
                try {
                    if (res) {
                        var decodedStr = "";
                        var bytes = res;
                        for (var i = 0; i < Math.min(bytes.length, 200); i++) {
                            decodedStr += String.fromCharCode(bytes[i] & 0xff);
                        }
                        checkAndEmitSecret("Base64_decode", decodedStr, "critical");
                        if (/(access_token|refresh_token|api_key|secret|jwt|password|https:\/\/)/i.test(decodedStr)) {
                            emit("base64_decoded_secret", {
                                decoded_snippet: captureString(decodedStr),
                                severity: "high"
                            });
                        }
                    }
                } catch (e) {}
                return res;
            };
        });
        B64.encodeToString.overloads.forEach(function(ov) {
            ov.implementation = function() {
                var res = ov.apply(this, arguments);
                try {
                    checkAndEmitSecret("Base64_encodeToString", res, "high");
                } catch (e) {}
                return res;
            };
        });
    });

    tryHook("java.util.Base64$Decoder", null, function(JBase64) {
        JBase64.decode.overloads.forEach(function(ov) {
            ov.implementation = function() {
                var res = ov.apply(this, arguments);
                try {
                    if (res) {
                        var decodedStr = "";
                        for (var i = 0; i < Math.min(res.length, 200); i++) {
                            decodedStr += String.fromCharCode(res[i] & 0xff);
                        }
                        checkAndEmitSecret("Java_Base64_decode", decodedStr, "critical");
                    }
                } catch (e) {}
                return res;
            };
        });
    });

    // 2.3 Java Reflection Method Invocation
    tryHook("java.lang.reflect.Method", null, function(Method) {
        Method.invoke.implementation = function(obj, args) {
            var res = this.invoke(obj, args);
            try {
                var mName = this.getName();
                if (/(get|fetch|read|decrypt|key|token|secret|password|auth|pay|billing)/i.test(mName)) {
                    var resStr = res ? res.toString() : "null";
                    if (!isClassNameOrNoise(resStr)) {
                        emit("reflection_invoke", {
                            method: mName,
                            class: this.getDeclaringClass().getName(),
                            result_snippet: captureString(resStr)
                        });
                    }
                }
            } catch (e) {}
            return res;
        };
    });
}

// =========================================================================
//  3. NETWORK & TRAFFIC HOOKS — OkHttp, Retrofit, Volley, Ktor, WebSocket, gRPC, Cronet
// =========================================================================
function hookNetwork() {
    // 3.1 OkHttp3 Client & Interceptor
    tryHook("okhttp3.OkHttpClient", null, function(OHC) {
        OHC.newCall.implementation = function(request) {
            try {
                var url = request.url().toString();
                var method = request.method();
                var headers = [];
                try {
                    var hdrs = request.headers();
                    for (var i = 0; i < hdrs.size(); i++) {
                        headers.push(hdrs.name(i) + ": " + hdrs.value(i));
                    }
                } catch (e) {}
                emit("network_request", {
                    url: url,
                    method: method,
                    headers: headers.slice(0, 20).join(" | ")
                });

                headers.forEach(function(h) {
                    checkAndEmitSecret("okhttp_header", h, "critical");
                    if (/(authorization|bearer|x-api-key|token|api-key|cookie)/i.test(h)) {
                        emit("network_auth", {
                            url: url,
                            header: captureString(h),
                            severity: "critical"
                        });
                    }
                });
            } catch (e) {}
            return this.newCall(request);
        };
    });

    tryHook("okhttp3.RealCall", null, function(RC) {
        RC.execute.implementation = function() {
            try {
                emit("okhttp_realcall_execute", { url: this.request().url().toString() });
            } catch (e) {}
            return this.execute();
        };
    });

    // 3.2 OkHttp3 Response Body
    tryHook("okhttp3.ResponseBody", null, function(RB) {
        RB.string.implementation = function() {
            var body = this.string();
            try {
                emit("network_response_body", {
                    url: "[okhttp body]",
                    body_snippet: captureString(body)
                });
                checkAndEmitSecret("okhttp_response_body", body, "critical");
            } catch (e) {}
            return body;
        };
    });

    // 3.3 HttpURLConnection
    tryHook("java.net.HttpURLConnection", null, function(HUC) {
        HUC.connect.implementation = function() {
            try {
                var url = this.getURL() ? this.getURL().toString() : "?";
                var method = this.getRequestMethod();
                emit("network_httpurl", { url: url, method: method });
            } catch (e) {}
            return this.connect();
        };
        HUC.getRequestProperty.implementation = function(key) {
            var val = this.getRequestProperty(key);
            try {
                if (val) checkAndEmitSecret("HttpURLConnection_header", key + ": " + val, "high");
            } catch (e) {}
            return val;
        };
        HUC.getHeaderFields.implementation = function() {
            var hdrs = this.getHeaderFields();
            try {
                if (hdrs) emit("httpurl_headers", { headers_str: hdrs.toString().slice(0, 300) });
            } catch (e) {}
            return hdrs;
        };
    });

    // 3.4 Volley, Ktor, Apache
    tryHook("com.android.volley.Request", null, function(VR) {
        VR.getHeaders.implementation = function() {
            var hdrs = this.getHeaders();
            try {
                emit("volley_headers", {
                    url: this.getUrl(),
                    headers: hdrs ? hdrs.toString() : ""
                });
            } catch (e) {}
            return hdrs;
        };
    });

    // gRPC Metadata
    tryHook("io.grpc.Metadata", null, function(Meta) {
        Meta.get.implementation = function(key) {
            var val = this.get(key);
            try {
                if (val) {
                    var keyName = key ? key.toString() : "?";
                    var valStr = val.toString();
                    checkAndEmitSecret("grpc_metadata", keyName + ": " + valStr, "critical");
                    if (/(authorization|token|key|secret)/i.test(keyName)) {
                        emit("grpc_metadata_secret", {
                            key: keyName,
                            value: captureString(valStr),
                            severity: "critical"
                        });
                    }
                }
            } catch (e) {}
            return val;
        };
    });

    // 3.5 WebSocket & Listener
    tryHook("okhttp3.WebSocket", null, function(WS) {
        WS.send.overload("java.lang.String").implementation = function(text) {
            emit("websocket_send", {
                text: captureString(text),
                severity: "medium"
            });
            checkAndEmitSecret("websocket_send", text, "high");
            return this.send(text);
        };
    });

    tryHook("okhttp3.WebSocketListener", null, function(WSL) {
        WSL.onMessage.overload("okhttp3.WebSocket", "java.lang.String").implementation = function(ws, text) {
            emit("websocket_recv", { text: captureString(text) });
            checkAndEmitSecret("websocket_recv", text, "high");
            return this.onMessage(ws, text);
        };
    });

    // 3.6 Cronet Engine
    tryHook("org.chromium.net.CronetEngine", null, function(CE) {
        CE.startNetLogToFile.implementation = function(path, logAll) {
            emit("cronet_netlog", { path: path });
            return this.startNetLogToFile(path, logAll);
        };
    });
}

// =========================================================================
//  4. AUTHENTICATION & TOKEN HOOKS
// =========================================================================
function hookAuth() {
    // 4.1 SharedPreferences — get & put
    tryHook("android.content.SharedPreferences", null, function(SP) {
        SP.getString.implementation = function(key, defValue) {
            var val = this.getString(key, defValue);
            if (val) checkAndEmitSecret("SharedPreferences_getString", val, "critical");
            if (/(token|key|secret|password|auth|jwt|session|cookie|premium|subscription)/i.test(key)) {
                emit("pref_secret", {
                    key: key,
                    value: captureString(val),
                    severity: "critical"
                });
            }
            return val;
        };

        SP.getAll.implementation = function() {
            var all = this.getAll();
            try {
                if (all) {
                    var entries = [];
                    var map = Java.cast(all, Java.use("java.util.HashMap"));
                    var it = map.keySet().iterator();
                    while (it.hasNext()) {
                        var k = String(it.next());
                        var v = String(map.get(k));
                        entries.push(k + "=" + captureString(v));
                        checkAndEmitSecret("SharedPreferences_getAll", v, "critical");
                        if (/(token|key|secret|password|jwt)/i.test(k)) {
                            emit("pref_secret_all", {
                                key: k,
                                value: captureString(v),
                                severity: "critical"
                            });
                        }
                    }
                    emit("pref_all", { entries: entries.slice(0, 30).join(" | ") });
                }
            } catch (e) {}
            return all;
        };
    });

    tryHook("android.content.SharedPreferences$Editor", null, function(SPE) {
        SPE.putString.implementation = function(key, value) {
            try {
                if (value) checkAndEmitSecret("SharedPreferences_putString", value, "critical");
                if (/(token|key|secret|password|jwt|auth)/i.test(key)) {
                    emit("pref_put_secret", {
                        key: key,
                        value: captureString(value),
                        severity: "critical"
                    });
                }
            } catch (e) {}
            return this.putString(key, value);
        };
    });

    // 4.2 AccountManager
    tryHook("android.accounts.AccountManager", null, function(AM) {
        AM.getPassword.implementation = function(account) {
            var pw = this.getPassword(account);
            if (pw) {
                emit("account_password", {
                    account: account.toString(),
                    password: captureString(pw),
                    severity: "critical"
                });
            }
            return pw;
        };
        AM.peekAuthToken.implementation = function(account, authTokenType) {
            var token = this.peekAuthToken(account, authTokenType);
            if (token) {
                emit("account_peek_token", {
                    account: account.toString(),
                    token: captureString(token),
                    severity: "high"
                });
            }
            return token;
        };
        AM.getAuthToken.overloads.forEach(function(ov) {
            ov.implementation = function() {
                var res = ov.apply(this, arguments);
                try {
                    var acct = arguments[0] ? arguments[0].toString() : "?";
                    var tokenType = arguments[1] ? String(arguments[1]) : "?";
                    emit("account_get_authtoken", {
                        account: acct,
                        auth_token_type: tokenType,
                        severity: "critical"
                    });
                } catch (e) {}
                return res;
            };
        });
    });

    // 4.3 JWT Parser
    tryHook("io.jsonwebtoken.Jwts", null, function(Jwts) {
        Jwts.parser.implementation = function() {
            emit("jwt_parser", { ts: Date.now() });
            return this.parser();
        };
    });
}

// =========================================================================
//  5. STORAGE & DATABASE HOOKS — SQLite, SQLCipher, Realm, EncryptedPrefs, Room, DataStore
// =========================================================================
function hookStorage() {
    // 5.1 EncryptedSharedPreferences
    tryHook("androidx.security.crypto.EncryptedSharedPreferences", null, function(ESP) {
        ESP.create.overloads.forEach(function(ov) {
            ov.implementation = function() {
                var res = ov.apply(this, arguments);
                try {
                    emit("encrypted_prefs_created", {
                        fileName: arguments[0] ? String(arguments[0]) : "?",
                        masterKeyAlias: arguments[1] ? String(arguments[1]) : "?",
                        severity: "critical"
                    });
                } catch (e) {}
                return res;
            };
        });
    });

    tryHook("androidx.security.crypto.MasterKey$Builder", null, function(MKB) {
        MKB.build.implementation = function() {
            var mk = this.build();
            try {
                emit("master_key_built", {
                    keyAlias: mk.getKeyAlias(),
                    isKeyStoreBacked: mk.isKeyStoreBacked(),
                    severity: "critical"
                });
            } catch (e) {}
            return mk;
        };
    });

    // Jetpack DataStore
    tryHook("androidx.datastore.preferences.core.MutablePreferences", null, function(DataStorePref) {
        DataStorePref.set.implementation = function(key, value) {
            try {
                var kName = key ? key.toString() : "?";
                var valStr = value ? value.toString() : "";
                checkAndEmitSecret("datastore_set", valStr, "critical");
                if (/(token|key|secret|password|auth|jwt)/i.test(kName)) {
                    emit("datastore_secret_put", {
                        key: kName,
                        value: captureString(valStr),
                        severity: "critical"
                    });
                }
            } catch (e) {}
            return this.set(key, value);
        };
    });

    // 5.2 SQLite & SQLCipher
    tryHook("android.database.sqlite.SQLiteDatabase", null, function(SD) {
        SD.rawQuery.overloads.forEach(function(ov) {
            ov.implementation = function() {
                var res = ov.apply(this, arguments);
                try {
                    if (arguments[0]) {
                        var sql = String(arguments[0]);
                        emit("sqlite_query", { sql: captureString(sql) });
                        checkAndEmitSecret("sqlite_query", sql, "high");
                    }
                } catch (e) {}
                return res;
            };
        });
        SD.execSQL.overload("java.lang.String").implementation = function(sql) {
            emit("sqlite_exec", { sql: captureString(sql) });
            return this.execSQL(sql);
        };
    });

    // SQLCipher database password hook
    tryHook("net.sqlcipher.database.SQLiteDatabase", null, function(SQLC) {
        SQLC.openOrCreateDatabase.overloads.forEach(function(ov) {
            ov.implementation = function() {
                try {
                    var path = arguments[0] ? String(arguments[0]) : "?";
                    var password = arguments[1] ? String(arguments[1]) : "";
                    emit("sqlcipher_db_opened", {
                        path: path,
                        password: captureString(password),
                        severity: "critical"
                    });
                } catch (e) {}
                return ov.apply(this, arguments);
            };
        });
    });

    // 5.3 Realm Database
    tryHook("io.realm.RealmConfiguration$Builder", null, function(RC) {
        RC.encryptionKey.implementation = function(key) {
            try {
                if (key) {
                    var keyHex = captureHex(key);
                    emit("realm_encryption_key", {
                        key_hex: keyHex,
                        severity: "critical"
                    });
                }
            } catch (e) {}
            return this.encryptionKey(key);
        };
    });

    // 5.4 SQLite Cursor value inspection
    tryHook("android.database.Cursor", null, function(Cursor) {
        Cursor.getString.implementation = function(columnIndex) {
            var val = this.getString(columnIndex);
            try {
                if (val) checkAndEmitSecret("Cursor_getString", val, "high");
                var colName = this.getColumnName(columnIndex);
                if (/(token|key|secret|password|jwt)/i.test(colName)) {
                    emit("cursor_secret", {
                        column: colName,
                        value: captureString(val),
                        severity: "high"
                    });
                }
            } catch (e) {}
            return val;
        };
    });

    // 5.5 FileOutputStream secret detection
    tryHook("java.io.FileOutputStream", null, function(FOS) {
        FOS.write.overload("[B").implementation = function(b) {
            try {
                if (b) {
                    var content = "";
                    for (var i = 0; i < Math.min(b.length, 150); i++) {
                        content += String.fromCharCode(b[i] & 0xff);
                    }
                    checkAndEmitSecret("FileOutputStream_write", content, "critical");
                }
            } catch (e) {}
            return this.write(b);
        };
    });
}

// =========================================================================
//  6. BILLING & PREMIUM BYPASS HOOKS
// =========================================================================
function hookBilling() {
    // 6.1 Play Billing Client v3-v6
    tryHook("com.android.billingclient.api.BillingClient", null, function(BC) {
        BC.queryPurchases.overloads.forEach(function(ov) {
            ov.implementation = function() {
                emit("billing_query_purchases", { ts: Date.now() });
                return ov.apply(this, arguments);
            };
        });
        BC.isFeatureSupported.implementation = function(feature) {
            emit("billing_feature_supported", { feature: feature });
            return 0; // RESPONSE_CODE_OK
        };
    });

    // 6.2 Purchase Details
    tryHook("com.android.billingclient.api.Purchase", null, function(Purchase) {
        Purchase.getPurchaseToken.implementation = function() {
            var token = this.getPurchaseToken();
            emit("billing_purchase_token", {
                token: token,
                severity: "critical"
            });
            return token;
        };
        Purchase.getSignature.implementation = function() {
            var sig = this.getSignature();
            emit("billing_signature", {
                signature: captureString(sig),
                severity: "critical"
            });
            return sig;
        };
        Purchase.getOriginalJson.implementation = function() {
            var json = this.getOriginalJson();
            emit("billing_original_json", {
                json: captureString(json),
                severity: "high"
            });
            return json;
        };
    });

    // 6.3 In-App Billing Service (v3)
    tryHook("com.android.vending.billing.IInAppBillingService", null, function(IAB) {
        IAB.getPurchases.implementation = function(apiVersion, packageName, itemType, continuationToken) {
            emit("iab_get_purchases", { packageName: packageName, itemType: itemType });
            return this.getPurchases(apiVersion, packageName, itemType, continuationToken);
        };
    });
}

// =========================================================================
//  7. FIREBASE & CLOUD SDK HOOKS
// =========================================================================
function hookCloud() {
    // 7.1 Firebase Auth Tokens
    tryHook("com.google.firebase.auth.FirebaseAuth", null, function(FA) {
        FA.getUid.implementation = function() {
            var uid = this.getUid();
            emit("firebase_uid", { uid: uid });
            return uid;
        };
        FA.getAccessToken.implementation = function(addTaskListener) {
            emit("firebase_token_request", { ts: Date.now() });
            return this.getAccessToken(addTaskListener);
        };
    });

    tryHook("com.google.firebase.auth.GetTokenResult", null, function(GTR) {
        GTR.getToken.implementation = function() {
            var token = this.getToken();
            emit("firebase_id_token", {
                token: captureString(token),
                severity: "critical"
            });
            checkAndEmitSecret("firebase_token", token, "critical");
            return token;
        };
    });

    // 7.2 Firebase Installations
    tryHook("com.google.firebase.installations.FirebaseInstallations", null, function(FI) {
        FI.getToken.overloads.forEach(function(ov) {
            ov.implementation = function() {
                emit("firebase_installation_token_req", { ts: Date.now() });
                return ov.apply(this, arguments);
            };
        });
    });

    // 7.3 Google Sign-In Account
    tryHook("com.google.android.gms.auth.api.signin.GoogleSignInAccount", null, function(GSA) {
        GSA.getIdToken.implementation = function() {
            var token = this.getIdToken();
            emit("google_signin_id_token", {
                token: captureString(token),
                severity: "critical"
            });
            checkAndEmitSecret("google_signin_id_token", token, "critical");
            return token;
        };
        GSA.getServerAuthCode.implementation = function() {
            var code = this.getServerAuthCode();
            emit("google_signin_auth_code", {
                code: captureString(code),
                severity: "high"
            });
            return code;
        };
    });

    // 7.4 AWS Credentials
    tryHook("com.amazonaws.auth.BasicAWSCredentials", null, function(AWS) {
        AWS.$init.implementation = function(accessKey, secretKey) {
            emit("aws_credentials", {
                access_key: accessKey,
                secret_key: captureString(secretKey),
                severity: "critical"
            });
            return this.$init(accessKey, secretKey);
        };
    });
}

// =========================================================================
//  8. UNIVERSAL SSL UNPINNING & ANTI-TAMPER BYPASS
// =========================================================================
function hookSSLUnpinningAndAntiTamper() {
    // 8.1 Universal X509 TrustManager & Conscrypt Bypass
    tryHook("com.android.org.conscrypt.TrustManagerImpl", null, function(TMI) {
        TMI.verifyChain.implementation = function(unverifiedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSvcData) {
            emit("ssl_unpin", {
                target: "TrustManagerImpl.verifyChain",
                host: host,
                bypassed: true,
                severity: "high"
            });
            return unverifiedChain;
        };

        TMI.checkServerTrusted.overloads.forEach(function(ov) {
            ov.implementation = function() {
                emit("ssl_unpin", {
                    target: "TrustManagerImpl.checkServerTrusted",
                    bypassed: true,
                    severity: "high"
                });
                return;
            };
        });
    });

    // 8.2 OkHttp3 CertificatePinner Bypass
    tryHook("okhttp3.CertificatePinner", null, function(CP) {
        CP.check.overloads.forEach(function(ov) {
            ov.implementation = function() {
                emit("ssl_unpin", {
                    target: "CertificatePinner.check",
                    hostname: arguments[0] ? String(arguments[0]) : "?",
                    bypassed: true,
                    severity: "high"
                });
                return;
            };
        });
    });

    // 8.3 RootBeer & Root Checks Bypass
    tryHook("com.scottyab.rootbeer.RootBeer", null, function(RB) {
        RB.isRooted.implementation = function() {
            emit("root_bypass", { target: "RootBeer.isRooted", bypassed: true, severity: "high" });
            return false;
        };
        RB.isRootedWithBusyBoxCheck.implementation = function() {
            emit("root_bypass", { target: "RootBeer.isRootedWithBusyBoxCheck", bypassed: true, severity: "high" });
            return false;
        };
    });

    tryHook("java.io.File", null, function(FileClz) {
        FileClz.exists.implementation = function() {
            try {
                var path = this.getAbsolutePath();
                if (path && (path.indexOf("/su") >= 0 || path.indexOf("/Superuser.apk") >= 0 || path.indexOf("/magisk") >= 0 || path.indexOf("/busybox") >= 0)) {
                    emit("root_bypass", {
                        target: "File.exists(" + path + ")",
                        bypassed: true,
                        severity: "high"
                    });
                    return false;
                }
            } catch (e) {}
            return this.exists();
        };
    });
}

// =========================================================================
//  9. EXFILTRATION CHANNELS & LEAKS — Clipboard, Intents, Logs, WebView Bridges, ContentResolver
// =========================================================================
function hookExfiltration() {
    // 9.1 Clipboard
    tryHook("android.content.ClipboardManager", null, function(CM) {
        CM.setPrimaryClip.implementation = function(clip) {
            try {
                if (clip && clip.getItemCount() > 0) {
                    var item = clip.getItemAt(0);
                    var text = item.getText() ? item.getText().toString() : "";
                    emit("clipboard_set", {
                        text: captureString(text),
                        severity: "high"
                    });
                    checkAndEmitSecret("clipboard_set", text, "critical");
                }
            } catch (e) {}
            return this.setPrimaryClip(clip);
        };
        CM.getPrimaryClip.implementation = function() {
            var clip = this.getPrimaryClip();
            try {
                if (clip && clip.getItemCount() > 0) {
                    var item = clip.getItemAt(0);
                    var text = item.getText() ? item.getText().toString() : "";
                    emit("clipboard_get", { text: captureString(text) });
                    checkAndEmitSecret("clipboard_get", text, "high");
                }
            } catch (e) {}
            return clip;
        };
    });

    // 9.2 Intent Extras
    tryHook("android.content.Intent", null, function(Intent) {
        Intent.getStringExtra.implementation = function(name) {
            var val = this.getStringExtra(name);
            try {
                if (val) {
                    checkAndEmitSecret("Intent_getStringExtra", val, "high");
                    if (/(token|key|secret|password|auth|jwt|url)/i.test(name)) {
                        emit("intent_extra_secret", {
                            key: name,
                            value: captureString(val),
                            severity: "high"
                        });
                    }
                }
            } catch (e) {}
            return val;
        };
    });

    // 9.3 ContentResolver
    tryHook("android.content.ContentResolver", null, function(CR) {
        CR.query.overloads.forEach(function(ov) {
            ov.implementation = function() {
                var cursor = ov.apply(this, arguments);
                try {
                    var uri = arguments[0] ? arguments[0].toString() : "?";
                    emit("content_resolver_query", {
                        uri: uri,
                        severity: "medium"
                    });
                } catch (e) {}
                return cursor;
            };
        });
    });

    // 9.4 Android Log Leaks
    tryHook("android.util.Log", null, function(Log) {
        ["d", "i", "w", "e", "v"].forEach(function(level) {
            Log[level].overloads.forEach(function(ov) {
                ov.implementation = function() {
                    try {
                        var tag = arguments[0] ? String(arguments[0]) : "";
                        var msg = arguments[1] ? String(arguments[1]) : "";
                        checkAndEmitSecret("android_log", tag + ": " + msg, "critical");
                    } catch (e) {}
                    return ov.apply(this, arguments);
                };
            });
        });
    });

    // 9.5 WebView Javascript Interfaces
    tryHook("android.webkit.WebView", null, function(WV) {
        WV.addJavascriptInterface.implementation = function(object, name) {
            emit("webview_js_interface", {
                interface_name: name,
                class_name: object ? object.getClass().getName() : "null",
                severity: "high"
            });
            return this.addJavascriptInterface(object, name);
        };
    });
}

// =========================================================================
//  10. MEMORY SCANNER V2 — Validated Secret Extraction (No Class Noise)
// =========================================================================
function hookMemoryScannerV2() {
    // ⚠️ Java.choose("java.lang.String") يمشي على كامل كومة Java (عشرات آلاف السلاسل)
    // ويُجمّد التطبيق أثناء المسح. كان يعمل كل 25s → يجمّد الواجهة باستمرار أثناء
    // تفاعل الـ AI. الآن: مؤجَّل (لا يمسّ الإقلاع) + نادر + محميّ من التداخل.
    var scanning = false;
    function scanOnce() {
        if (scanning) return;      // لا تبدأ مسحاً جديداً قبل انتهاء السابق
        scanning = true;
        try {
            Java.perform(function() {
                Java.choose("java.lang.String", {
                    onMatch: function(s) {
                        try {
                            var str = s.toString();
                            if (!str || str.length < 12) return;
                            if (isClassNameOrNoise(str)) return;
                            checkAndEmitSecret("heap_memory_scan", str, "critical");
                        } catch (e) {}
                    },
                    onComplete: function() { scanning = false; }
                });
            });
        } catch (e) { scanning = false; }
    }
    // أول مسح بعد 75s (بعد أن يستقر التطبيق ويستكشفه الـ AI)، ثم كل 180s فقط
    setTimeout(function() { scanOnce(); setInterval(scanOnce, 180000); }, 75000);
}

// =========================================================================
//  11. PREMIUM BYPASS & RUNTIME AUTO-HOOK
// =========================================================================
function hookPremiumBypass() {
    var PREMIUM_METHODS = [
        "isPremium", "is_premium", "getPremium", "hasPremium",
        "isPro", "is_pro", "getPro", "hasPro",
        "isSubscribed", "is_subscribed", "getSubscription", "hasSubscription",
        "isUnlocked", "is_unlocked", "isPurchased", "hasPurchased",
        "isVip", "is_vip", "getVipLevel", "getVipStatus"
    ];

    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            var lower = className.toLowerCase();
            if (lower.indexOf("premium") >= 0 || lower.indexOf("billing") >= 0 || lower.indexOf("subscription") >= 0) {
                try {
                    var clz = Java.use(className);
                    var methods = clz.class.getDeclaredMethods();
                    for (var m = 0; m < methods.length; m++) {
                        var mn = methods[m].getName();
                        if (PREMIUM_METHODS.indexOf(mn) >= 0) {
                            emit("bypass_hook_premium", { class: className, method: mn, severity: "critical" });
                            try {
                                clz[mn].overloads.forEach(function(ov) {
                                    ov.implementation = function() {
                                        emit("bypass_triggered", { class: className, method: mn, return_value: "true" });
                                        return Java.use("java.lang.Boolean").TRUE;
                                    };
                                });
                            } catch (e) {}
                        }
                    }
                } catch (e) {}
            }
        },
        onComplete: function() {}
    });
}

function hookRetrofit() {
    tryHook("retrofit2.ServiceMethod", null, function(SM) {
        SM.invoke.overloads.forEach(function(ov) {
            ov.implementation = function() {
                emit("retrofit_invoke", { ts: Date.now() });
                return ov.apply(this, arguments);
            };
        });
    });

    tryHook("retrofit2.OkHttpCall", null, function(OHC) {
        OHC.execute.implementation = function() {
            emit("retrofit_execute", { ts: Date.now() });
            return this.execute();
        };
        OHC.enqueue.implementation = function(callback) {
            try {
                emit("retrofit_enqueue", { ts: Date.now() });
            } catch (e) {}
            return this.enqueue(callback);
        };
    });

    tryHook("retrofit2.CallAdapter", null, function(CA) {
        CA.adapt.implementation = function(call) {
            emit("retrofit_adapt", { ts: Date.now() });
            return this.adapt(call);
        };
    });

    tryHook("okhttp3.EventListener", null, function(EL) {
        EL.callStart.implementation = function(call) {
            try {
                var req = call.request();
                emit("okhttp_event_call", {
                    url: req.url().toString(),
                    method: req.method()
                });
            } catch (e) {}
            return this.callStart(call);
        };
    });

    tryHook("com.google.gson.Gson", null, function(Gson) {
        Gson.toJson.overloads.forEach(function(ov) {
            ov.implementation = function() {
                try {
                    var src = arguments[0];
                    if (src && src.getClass) {
                        var clsName = src.getClass().getName();
                        if (clsName.indexOf("com.anthropic") >= 0 ||
                            clsName.indexOf("request") >= 0 ||
                            clsName.indexOf("response") >= 0 ||
                            clsName.indexOf("payload") >= 0 ||
                            clsName.indexOf("login") >= 0 ||
                            clsName.indexOf("auth") >= 0) {
                            var json = ov.apply(this, arguments);
                            emit("gson_serialize", {
                                class: clsName,
                                json: captureString(json),
                                severity: "high"
                            });
                            return json;
                        }
                    }
                } catch (e) {}
                return ov.apply(this, arguments);
            };
        });
        Gson.fromJson.overloads.forEach(function(ov) {
            ov.implementation = function() {
                var result = ov.apply(this, arguments);
                try {
                    var json = arguments[0];
                    if (typeof json === "string" &&
                        (json.indexOf("access_token") >= 0 ||
                         json.indexOf("refresh_token") >= 0 ||
                         json.indexOf("api_key") >= 0 ||
                         json.indexOf("session") >= 0 ||
                         json.indexOf("secret") >= 0)) {
                        emit("gson_deserialize_secret", {
                            json: captureString(json),
                            severity: "critical"
                        });
                    }
                } catch (e) {}
                return result;
            };
        });
    });

    tryHook("com.fasterxml.jackson.databind.ObjectMapper", null, function(OM) {
        OM.writeValueAsString.implementation = function(value) {
            var json = this.writeValueAsString(value);
            try {
                if (json && value && value.getClass) {
                    var clsName = value.getClass().getName();
                    if (clsName.indexOf("com.anthropic") >= 0 ||
                        json.indexOf("access_token") >= 0 ||
                        json.indexOf("refresh_token") >= 0 ||
                        json.indexOf("api_key") >= 0 ||
                        json.indexOf("secret") >= 0 ||
                        json.indexOf("password") >= 0) {
                        emit("jackson_serialize", {
                            class: clsName,
                            json: captureString(json),
                            severity: "high"
                        });
                    }
                }
            } catch (e) {}
            return json;
        };
        OM.readValue.overloads.forEach(function(ov) {
            ov.implementation = function() {
                var result = ov.apply(this, arguments);
                emit("jackson_deserialize", { ts: Date.now() });
                return result;
            };
        });
    });
}

function hookWebViewAdvanced() {
    tryHook("android.webkit.WebView", null, function(WV) {
        WV.evaluateJavascript.implementation = function(script, callback) {
            emit("webview_eval", {
                script: captureString(script),
                severity: "medium"
            });
            return this.evaluateJavascript(script, callback);
        };
        WV.loadData.implementation = function(data, mimeType, encoding) {
            emit("webview_loaddata", { data_snippet: captureString(data) });
            return this.loadData(data, mimeType, encoding);
        };
        WV.loadDataWithBaseURL.implementation = function(baseUrl, data, mimeType, encoding, historyUrl) {
            emit("webview_loaddata_url", {
                baseUrl: baseUrl,
                data_snippet: captureString(data)
            });
            return this.loadDataWithBaseURL(baseUrl, data, mimeType, encoding, historyUrl);
        };
        try {
            var WVC = Java.use("android.webkit.WebViewClient");
            WVC.onPageStarted.implementation = function(view, url, favicon) {
                emit("webview_page_start", { url: url });
                return this.onPageStarted(view, url, favicon);
            };
        } catch (e) {}
        try {
            var WVC2 = Java.use("android.webkit.WebViewClient");
            WVC2.shouldOverrideUrlLoading.overload("android.webkit.WebView", "android.webkit.WebResourceRequest").implementation = function(view, request) {
                try {
                    emit("webview_url_override", { url: request.getUrl().toString() });
                } catch (e) {}
                return this.shouldOverrideUrlLoading(view, request);
            };
        } catch (e) {}
    });
}

function hookNetworkLegacy() {
    tryHook("okhttp3.OkHttpClient", null, function(OHC) {
        OHC.newCall.implementation = function(request) {
            try {
                var url = request.url().toString();
                var method = request.method();
                var headers = [];
                try {
                    var hdrs = request.headers();
                    for (var i = 0; i < hdrs.size(); i++) {
                        headers.push(hdrs.name(i) + ": " + hdrs.value(i));
                    }
                } catch (e) {}
                emit("network_request", {
                    url: url,
                    method: method,
                    headers: headers.slice(0, 20).join(" | ")
                });

                for (var j = 0; j < headers.length; j++) {
                    var h = headers[j];
                    if (/(authorization|bearer|x-api-key|token)/i.test(h)) {
                        emit("network_auth", {
                            url: url,
                            header: h.slice(0, 120),
                            severity: "critical"
                        });
                    }
                }
            } catch (e) {}
            return this.newCall(request);
        };
    });

    tryHook("okhttp3.ResponseBody", null, function(RB) {
        RB.string.implementation = function() {
            var body = this.string();
            try {
                emit("network_response_body", {
                    url: "[okhttp body]",
                    body_snippet: captureString(body)
                });
                if (/(access_token|refresh_token|api_key|secret|jwt|password)/i.test(body)) {
                    emit("network_secret_in_response", {
                        body_snippet: captureString(body),
                        severity: "high"
                    });
                }
            } catch (e) {}
            return body;
        };
    });

    tryHook("java.net.HttpURLConnection", null, function(HUC) {
        HUC.connect.implementation = function() {
            try {
                var url = this.getURL() ? this.getURL().toString() : "?";
                var method = this.getRequestMethod();
                emit("network_httpurl", { url: url, method: method });
            } catch (e) {}
            return this.connect();
        };
        HUC.getOutputStream.implementation = function() {
            emit("network_output_stream", { ts: Date.now() });
            return this.getOutputStream();
        };
    });

    tryHook("okhttp3.WebSocket", null, function(WS) {
        WS.send.overload("java.lang.String").implementation = function(text) {
            emit("websocket_send", {
                text: captureString(text),
                severity: "medium"
            });
            return this.send(text);
        };
    });

    tryHook("org.chromium.net.CronetEngine", null, function(CE) {
        CE.startNetLogToFile.implementation = function(path, logAll) {
            emit("cronet_netlog", { path: path });
            return this.startNetLogToFile(path, logAll);
        };
    });

    tryHook("java.net.URL", null, function(URL) {
        URL.openConnection.implementation = function() {
            var conn = this.openConnection();
            emit("network_url_open", { url: this.toString() });
            return conn;
        };
    });

    tryHook("okhttp3.sse.EventSource", null, function(ES) {
        ES.request.implementation = function() {
            emit("network_sse", { ts: Date.now() });
            return this.request();
        };
    });
}

function hookCloudLegacy() {
    tryHook("com.google.firebase.database.FirebaseDatabase", null, function(FD) {
        FD.getReference.overload("java.lang.String").implementation = function(path) {
            emit("firebase_ref", { path: path });
            return this.getReference(path);
        };
        FD.getReference.implementation = function() {
            emit("firebase_root_ref", { ts: Date.now() });
            return this.getReference();
        };
    });

    tryHook("com.google.firebase.firestore.FirebaseFirestore", null, function(FF) {
        FF.collection.implementation = function(path) {
            emit("firestore_collection", { path: path });
            return this.collection(path);
        };
        FF.document.implementation = function(path) {
            emit("firestore_document", { path: path });
            return this.document(path);
        };
    });

    tryHook("com.google.firebase.remoteconfig.FirebaseRemoteConfig", null, function(FRC) {
        FRC.getString.implementation = function(key) {
            var val = this.getString(key);
            emit("remote_config_get", { key: key, value: captureString(val) });
            return val;
        };
        FRC.getKeys.implementation = function() {
            emit("remote_config_keys", { ts: Date.now() });
            return this.getKeys();
        };
    });

    tryHook("com.amazonaws.auth.BasicAWSCredentials", null, function(AWS) {
        AWS.$init.implementation = function(accessKey, secretKey) {
            emit("aws_credentials", {
                access_key: accessKey,
                severity: "critical"
            });
            return this.$init(accessKey, secretKey);
        };
    });

    tryHook("com.google.android.gms.common.api.GoogleApiClient", null, function(GAC) {
        GAC.connect.implementation = function() {
            emit("google_api_connect", { ts: Date.now() });
            return this.connect();
        };
    });

    tryHook("supabase.KtSession", null, function(SS) {
        SS.getAccessToken.implementation = function() {
            var token = this.getAccessToken();
            emit("supabase_token", {
                token: captureString(token),
                severity: "high"
            });
            return token;
        };
    });
}

// =========================================================================
//  AUTH-GATE BYPASS — تجاوز بوابة تسجيل الدخول لإكمال المراحل الديناميكية
// =========================================================================
function hookAuthGateBypass() {
    var AUTH_RE = /(isLogged|isLogin|isAuthenticated|isSignedIn|isUserLoggedIn|hasSession|hasValidSession|checkLogin|isPremium|isPro|isSubscribed|isVip|isPaid|isActivated|isMember)/i;
    var NEG_RE  = /(needLogin|requireLogin|isGuest|isLoggedOut|shouldLogin|mustLogin|isAnonymous)/i;
    var KEY_RE  = /(login|logged|auth|signed|session|premium|_pro|subscribed|vip|paid|activated|member)/i;

    // 1) SharedPreferences: مفاتيح حالة الدخول/الاشتراك → true (سريع، شائع جداً)
    try {
        var SP = Java.use("android.app.SharedPreferencesImpl");
        SP.getBoolean.implementation = function (key, def) {
            try {
                if (key && KEY_RE.test(String(key))) {
                    emit("auth_bypass", { via: "SharedPreferences.getBoolean", key: String(key), forced: true, severity: "high" });
                    return true;
                }
            } catch (e) {}
            return this.getBoolean(key, def);
        };
    } catch (e) {}

    // 2) مسح مؤجَّل وخفيف لأصناف التطبيق فقط: دوال تحقّق بلا وسائط ترجع boolean → true.
    // مؤجَّل 12s (بعد استقرار الإقلاع) + محدود بميزانية زمنية 2.5s حتى لا يُجمّد التطبيق.
    setTimeout(function () {
        try {
            Java.perform(function () {
                var SKIP = /^(android|androidx|com\.google|kotlin|kotlinx|java|javax|dalvik|sun|org\.json|okhttp3|retrofit2|okio|com\.facebook|com\.unity3d|io\.flutter|com\.bumptech|io\.reactivex|com\.squareup|org\.chromium|com\.airbnb)/;
                var classes = Java.enumerateLoadedClassesSync();
                var hooked = 0, scanned = 0;
                var deadline = Date.now() + 2500;   // ميزانية زمنية: لا تُجمّد الواجهة
                for (var i = 0; i < classes.length && hooked < 40 && scanned < 600; i++) {
                    if (Date.now() > deadline) break;
                    var cn = classes[i];
                    if (SKIP.test(cn)) continue;
                    scanned++;
                    try {
                        var clz = Java.use(cn);
                        var methods = clz.class.getDeclaredMethods();
                        for (var m = 0; m < methods.length; m++) {
                            var mm = methods[m];
                            if (mm.getParameterTypes().length !== 0) continue;
                            if (mm.getReturnType().getName() !== "boolean") continue;
                            var name = mm.getName();
                            var positive = AUTH_RE.test(name) && !NEG_RE.test(name);
                            var negative = NEG_RE.test(name);
                            if (!positive && !negative) continue;
                            try {
                                clz[name].implementation = positive
                                    ? function () { return true; }
                                    : function () { return false; };
                                emit("auth_bypass", { via: "method", clazz: cn, method: name, forced_to: positive, severity: "critical" });
                                hooked++;
                            } catch (e) {}
                        }
                    } catch (e) {}
                }
                if (hooked > 0) console.log("[HAYO] auth-gate bypass: forced " + hooked + " login/premium predicates.");
            });
        } catch (e) {}
    }, 6000);
}

// =========================================================================
//  EXTRA SECRET HOOKS — env/system props + auth headers set before send
// =========================================================================
function hookExtraSecrets() {
    var KW = /key|secret|token|password|passwd|api|auth|credential|bearer/i;
    // 1) متغيرات البيئة وخصائص النظام (مفاتيح تُقرأ من env/props)
    tryHook("java.lang.System", null, function (Sys) {
        try {
            Sys.getenv.overload("java.lang.String").implementation = function (name) {
                var v = this.getenv(name);
                if (v && name && KW.test(String(name)))
                    emit("env_secret", { name: String(name), value: captureString(v), severity: "high" });
                return v;
            };
        } catch (e) {}
        try {
            Sys.getProperty.overload("java.lang.String").implementation = function (name) {
                var v = this.getProperty(name);
                if (v && name && KW.test(String(name)))
                    emit("property_secret", { name: String(name), value: captureString(v), severity: "high" });
                return v;
            };
        } catch (e) {}
    });
    // 2) ترويسات OkHttp (Authorization/Cookie/X-Api-Key تُضبط قبل الإرسال = التقاط التوكن)
    tryHook("okhttp3.Request$Builder", null, function (RB) {
        ["header", "addHeader"].forEach(function (m) {
            try {
                RB[m].overload("java.lang.String", "java.lang.String").implementation = function (n, v) {
                    if (n && /authorization|cookie|api[-_]?key|x-api|x-auth|token|secret|bearer/i.test(String(n)))
                        emit("http_auth_header", { name: String(n), value: captureString(v), severity: "critical" });
                    return this[m](n, v);
                };
            } catch (e) {}
        });
    });
    // 3) HttpURLConnection.setRequestProperty (نفس الفكرة لمكدّس غير OkHttp)
    tryHook("java.net.HttpURLConnection", null, function (H) {
        try {
            H.setRequestProperty.implementation = function (n, v) {
                if (n && /authorization|cookie|api[-_]?key|token|secret|bearer/i.test(String(n)))
                    emit("http_auth_header", { name: String(n), value: captureString(v), severity: "critical" });
                return this.setRequestProperty(n, v);
            };
        } catch (e) {}
    });
}

// =========================================================================
//  MAIN ENGINE INITIALIZATION
// =========================================================================
Java.perform(function() {
    console.log("[HAYO] Ultimate Deep Instrumentation Engine — Initializing all hooks...");

    hookNetworkLegacy();
    hookCloudLegacy();

    hookCrypto();
    hookDeobfuscation();
    hookNetwork();
    hookAuth();
    hookStorage();
    hookBilling();
    hookCloud();
    hookSSLUnpinningAndAntiTamper();
    hookAuthGateBypass();
    hookExfiltration();
    hookExtraSecrets();
    hookMemoryScannerV2();
    hookPremiumBypass();
    hookRetrofit();
    hookWebViewAdvanced();

    console.log("[HAYO] All deep hooks loaded successfully. Engine active.");

    send({
        type: "message",
        payload: { kind: "ready" }
    });
});

/*
 * HAYO Cipher-7 — Cloud Premium Unlock via RESPONSE REWRITE (unlock_cloud.js)
 * =========================================================================
 * For account/login-based (Gmail-linked) premium where the SERVER returns an
 * entitlement the app then trusts client-side. We intercept the server's HTTP
 * response IN MEMORY (after SSL decryption, before the app parses it) and rewrite
 * the subscription fields free -> premium. No proxy, no cert needed.
 *
 * HONEST SCOPE: this works when premium is a FLAG in the response the app reads.
 * If the server withholds the actual premium DATA/feature (not just a flag), no
 * client-side rewrite can conjure data the server never sent — that case is
 * genuinely server-enforced and you report it as such.
 *
 */
Java.perform(function () {
    console.log("\n🟢 HAYO Cipher-7: Cloud response-rewrite engaged (free -> premium)...\n");

    // ── SSL unpinning (so any pinning doesn't hide the traffic if also proxied) ──
    try {
        var TMImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TMImpl.verifyChain.implementation = function (a, b, c, d, e, f) { return a; };
    } catch (e) {}
    try {
        var CP = Java.use('okhttp3.CertificatePinner');
        CP.check.overloads.forEach(function (o) { o.implementation = function () { return; }; });
    } catch (e) {}

    // ── The rewrite: targeted, JSON-key based (safe, not a blind replace) ──
    var FUTURE = "2099-12-31T23:59:59Z";
    function rewrite(body) {
        if (!body || body.length > 2000000) return body;
        var out = body;
        try {
            // boolean entitlement flags: false -> true
            out = out.replace(/("(?:isPremium|isPro|isVip|premium|pro|isSubscribed|subscribed|isActive|active|hasSubscription|entitled|isPaid|unlocked|isMember|adFree)"\s*:\s*)false/gi, "$1true");
            // negative flags: true -> false
            out = out.replace(/("(?:isFree|isExpired|expired|isTrial|trial|isFreeTier|needsUpgrade|showAds)"\s*:\s*)true/gi, "$1false");
            // plan / tier / status strings -> "premium"
            out = out.replace(/("(?:plan|tier|subscription|subscriptionType|subscription_type|accountType|account_type|membership|level|status|subscriptionStatus|subscription_status|role|planName|productId)"\s*:\s*)"[^"]*"/gi, '$1"premium"');
            // numeric wallets -> large
            out = out.replace(/("(?:points|credits|coins|balance|tokens|gems|stars|remainingDays|daysLeft|quota)"\s*:\s*)\d+/gi, "$1999999");
            // expiry dates -> far future
            out = out.replace(/("(?:expiry|expiresAt|expires_at|expiration|expireDate|expiry_date|subscriptionEnd|subscription_end|validUntil|valid_until)"\s*:\s*)"[^"]*"/gi, '$1"' + FUTURE + '"');
        } catch (e) {}
        return out;
    }

    function report(url, before, after) {
        if (before === after) return;
        console.log("\n==============================================");
        console.log("🔓 [CLOUD ENTITLEMENT REWRITTEN → PREMIUM] 🔓");
        console.log("URL: " + url);
        console.log("AFTER: \n" + after.substring(0, 1500));
        console.log("==============================================\n");
    }

    // ── Hook OkHttp3 ResponseBody.string() (most apps read JSON this way) ──
    try {
        var ResponseBody = Java.use("okhttp3.ResponseBody");
        ResponseBody.string.implementation = function () {
            var orig = this.string();
            var url = "";
            try { url = "(okhttp)"; } catch (e) {}
            var mod = rewrite(orig);
            report(url, orig, mod);
            return mod;
        };
        console.log("[+] Hooked okhttp3.ResponseBody.string()");
    } catch (e) {}

    // ── Also hook the raw Response.body() path (logs + covers other readers) ──
    try {
        var Response = Java.use("okhttp3.Response");
        var Charset = Java.use("java.nio.charset.Charset");
        Response.body.overload().implementation = function () {
            var body = this.body();
            try {
                if (body != null) {
                    var src = body.source(); src.request(9223372036854775807);
                    var raw = src.buffer().clone().readString(Charset.forName("UTF-8"));
                    var mod = rewrite(raw);
                    report(this.request().url().toString(), raw, mod);
                }
            } catch (e) {}
            return body;
        };
        console.log("[+] Hooked okhttp3.Response.body()");
    } catch (e) {}

    console.log("\n🟢 Ready. Log in / open the paid feature — server 'free' will be rewritten to 'premium'.\n");
});

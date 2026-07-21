/*
 * DeepSeek Core — payload_billing_hook.js  (PHASE 1.2)
 * MOCK purchase injection for AUTHORIZED testing of client-side subscription
 * enforcement (MASVS-AUTH / business-logic). No real payment is ever made — these
 * hooks only make the app *believe* it is premium so we can test whether premium
 * gating is enforced client-side (a real vulnerability) vs server-side.
 * Every action is emitted for the brain + the exploitation report.
 */
"use strict";
var _seen={};
function once(k){ if(_seen[k]) return false; _seen[k]=true; return true; }
function emit(o){ try{ send(o); }catch(e){} }

function hookGooglePlayBilling(){
  Java.perform(function(){
    // Force Purchase.getPurchaseState() -> PURCHASED(1) and acknowledged/auto-renew true
    try{ var Purchase=Java.use("com.android.billingclient.api.Purchase");
      Purchase.getPurchaseState.implementation=function(){ emit({event:"billing_override", what:"Purchase.getPurchaseState=PURCHASED"}); return 1; };
      try{ Purchase.isAcknowledged.implementation=function(){ return true; }; }catch(e){}
      try{ Purchase.isAutoRenewing.implementation=function(){ return true; }; }catch(e){}
    }catch(e){}
    // launchBillingFlow -> pretend it launched OK (BillingResponseCode.OK = 0)
    try{ var BC=Java.use("com.android.billingclient.api.BillingClient");
      BC.launchBillingFlow.overloads.forEach(function(ov){ try{ ov.implementation=function(){
        emit({event:"billing_override", what:"launchBillingFlow intercepted (mock success)"});
        try{ var BR=Java.use("com.android.billingclient.api.BillingResult");
          return BR.newBuilder().setResponseCode(0).build(); }catch(e){ return ov.apply(this, arguments); }
      }; }catch(e){} });
    }catch(e){}
    // queryPurchasesAsync / queryPurchases -> log so brain knows a query happened
    try{ var BC2=Java.use("com.android.billingclient.api.BillingClient");
      ["queryPurchasesAsync","queryPurchases"].forEach(function(mn){
        if(BC2[mn]){ BC2[mn].overloads.forEach(function(ov){ try{ ov.implementation=function(){
          if(once("qp-"+mn)) emit({event:"billing_query", method:mn});
          return ov.apply(this, arguments);
        }; }catch(e){} }); }
      });
    }catch(e){}
    // Force every boolean isPremium/isPro/isSubscribed across app classes -> true
    try{
      var METHODS=["isPremium","hasPremium","isSubscribed","hasActiveSubscription","isProUser","isPaidUser","isVip","isPro","checkPremium"];
      Java.enumerateLoadedClassesSync().forEach(function(cn){
        if(!(cn.indexOf("com.")===0 || cn.indexOf("io.")===0 || cn.indexOf("org.")===0)) return;
        var C; try{ C=Java.use(cn); }catch(e){ return; }
        METHODS.forEach(function(mn){ try{ if(C[mn]){ C[mn].overloads.forEach(function(ov){
          try{ if(ov.returnType && /boolean|Boolean/.test(ov.returnType.className)){ ov.implementation=function(){
            if(once("prem-"+cn+mn)) emit({event:"premium_forced", klass:cn, method:mn}); return true; }; }
          }catch(e){} }); } }catch(e){} });
      });
    }catch(e){}
  });
}

// Flutter MethodChannel billing bridges — best-effort: log calls on billing-ish
// channels so the brain can replay/override at the tool layer.
function hookFlutterBilling(){
  Java.perform(function(){
    try{ var MC=Java.use("io.flutter.plugin.common.MethodChannel");
      MC.invokeMethod.overloads.forEach(function(ov){ try{ ov.implementation=function(){
        try{ var method=arguments.length>0?String(arguments[0]):"";
          if(/purchas|billing|premium|subscription|pro/i.test(method) && once("fmc-"+method))
            emit({event:"flutter_billing", method:method}); }catch(e){}
        return ov.apply(this, arguments);
      }; }catch(e){} });
    }catch(e){}
  });
}

setTimeout(function(){ hookGooglePlayBilling(); hookFlutterBilling(); emit({event:"ready", module:"billing_hook"}); }, 0);

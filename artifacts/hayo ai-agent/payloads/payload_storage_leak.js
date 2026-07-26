/*
 * DeepSeek Core — payload_storage_leak.js  (PHASE 1.5)
 * Dumps everything the app writes/reads locally: SharedPreferences (incl.
 * EncryptedSharedPreferences after decryption) and SQLite/sqflite queries.
 * The brain harvests tokens/keys/flags (e.g. isPro) straight out of storage.
 */
"use strict";
var SENS=/token|password|passwd|pwd|secret|api[_-]?key|auth|bearer|session|refresh|jwt|premium|pro|plan|subscription|isPaid|credit|balance|AIza|sk_live/i;
var _seen={};
function once(k){ if(_seen[k]) return false; _seen[k]=true; return true; }
function emit(o){ try{ send(o); }catch(e){} }

function hookPrefs(){
  Java.perform(function(){
    try{ var Ed=Java.use("android.app.SharedPreferencesImpl$EditorImpl");
      Ed.putString.implementation=function(k,v){ try{ if((SENS.test(String(k))||SENS.test(String(v))) && once("pf-put-"+k))
        emit({event:"storage", store:"SharedPreferences", op:"put", key:String(k), value:String(v).slice(0,400)}); }catch(e){} return this.putString(k,v); };
      ["commit","apply"].forEach(function(mn){ try{ if(Ed[mn]) Ed[mn].implementation=function(){ return this[mn](); }; }catch(e){} });
    }catch(e){}
    try{ var SP=Java.use("android.app.SharedPreferencesImpl");
      SP.getString.implementation=function(k,d){ var v=this.getString(k,d);
        try{ if(v && (SENS.test(String(k))||SENS.test(String(v))) && once("pf-get-"+k))
          emit({event:"storage", store:"SharedPreferences", op:"get", key:String(k), value:String(v).slice(0,400)}); }catch(e){}
        return v; };
    }catch(e){}
    // EncryptedSharedPreferences — captured AFTER decryption
    try{ var ESP=Java.use("androidx.security.crypto.EncryptedSharedPreferences");
      ESP.getString.implementation=function(k,d){ var v=this.getString(k,d);
        try{ if(v && once("esp-"+k)) emit({event:"storage", store:"EncryptedSharedPreferences", op:"get", key:String(k), value:String(v).slice(0,400)}); }catch(e){}
        return v; };
    }catch(e){}
  });
}

function hookSqlite(){
  Java.perform(function(){
    try{ var DB=Java.use("android.database.sqlite.SQLiteDatabase");
      DB.execSQL.overloads.forEach(function(ov){ try{ ov.implementation=function(){ try{
        var sql=String(arguments[0]||""); if(once("sql-x-"+sql.slice(0,40)))
          emit({event:"sqlite", op:"execSQL", sql:sql.slice(0,400)}); }catch(e){} return ov.apply(this, arguments); }; }catch(e){} });
      DB.rawQuery.overloads.forEach(function(ov){ try{ ov.implementation=function(){ try{
        var sql=String(arguments[0]||""); if(once("sql-q-"+sql.slice(0,40)))
          emit({event:"sqlite", op:"rawQuery", sql:sql.slice(0,400)}); }catch(e){} return ov.apply(this, arguments); }; }catch(e){} });
    }catch(e){}
  });
}

setTimeout(function(){ hookPrefs(); hookSqlite(); emit({event:"ready", module:"storage_leak"}); }, 0);

"use strict";
var INFINITE_TOKENS = { injectionsPerformed: 0, balancesModified: [], totalValueInjected: 0, startTime: Date.now() };
function log_token(kind, data) { send({type:"token_injection",kind:kind,detail:JSON.stringify(data).substring(0,300)}); }
function isTokenKey(k){var pats=["coin","gem","token","point","credit","balance","gold","star","diamond","score","xp","level","energy","life","stamina","cash","money","currency","reward","bonus","premium_currency","wallet","fund","chip"];for(var i=0;i<pats.length;i++){if(k.indexOf(pats[i])>-1)return true;}return false;}
try{var SP=Java.use("android.content.SharedPreferences");var Ed=Java.use("android.content.SharedPreferences$Editor");
Ed.putInt.implementation=function(k,v){if(isTokenKey(k.toLowerCase())){INFINITE_TOKENS.injectionsPerformed++;INFINITE_TOKENS.balancesModified.push(k);INFINITE_TOKENS.totalValueInjected+=999999999-(v>0?v:0);return this.putInt(k,999999999);}return this.putInt(k,v);};
Ed.putLong.implementation=function(k,v){if(isTokenKey(k.toLowerCase())){INFINITE_TOKENS.injectionsPerformed++;return this.putLong(k,999999999);}return this.putLong(k,v);};
Ed.putFloat.implementation=function(k,v){if(isTokenKey(k.toLowerCase())){INFINITE_TOKENS.injectionsPerformed++;return this.putFloat(k,999999999.99);}return this.putFloat(k,v);};
SP.getInt.implementation=function(k,dv){if(isTokenKey(k.toLowerCase())){return 999999999;}return this.getInt(k,dv);};
SP.getLong.implementation=function(k,dv){if(isTokenKey(k.toLowerCase())){return 999999999;}return this.getLong(k,dv);};
SP.getFloat.implementation=function(k,dv){if(isTokenKey(k.toLowerCase())){return 999999999.99;}return this.getFloat(k,dv);};
SP.getString.implementation=function(k,dv){if(k.toLowerCase().indexOf("balance")>-1||k.toLowerCase().indexOf("amount")>-1){return "999999999";}return this.getString(k,dv);};}catch(e){}
try{var DB=Java.use("android.database.sqlite.SQLiteDatabase");DB.execSQL.overload("java.lang.String").implementation=function(sql){if(sql.toLowerCase().indexOf("update")>-1){var m=sql;var pats=["coin","gem","token","point","credit","balance","gold","score","xp","level","stamina","energy"];for(var i=0;i<pats.length;i++){var re=new RegExp(""+pats[i]+"\s*=\s*\d+","gi");if(re.test(m)){m=m.replace(re,pats[i]+"=999999999");}}if(m!==sql){return this.execSQL(m);}}return this.execSQL(sql);};}catch(e){}
try{var CV=Java.use("android.content.ContentValues");CV.put.overload("java.lang.String","java.lang.Integer").implementation=function(k,v){if(isTokenKey(k.toLowerCase())){INFINITE_TOKENS.injectionsPerformed++;return this.put(k,999999999);}return this.put(k,v);};}catch(e){}
try{var BW=Java.use("java.io.BufferedWriter");BW.write.overload("java.lang.String").implementation=function(str){if(str.indexOf('"coins"')>-1||str.indexOf('"tokens"')>-1||str.indexOf('"points"')>-1||str.indexOf('"gems"')>-1||str.indexOf('"credits"')>-1||str.indexOf('"balance"')>-1){var m=str.replace(/"(\d+)"/g,function(mt,num){if(parseInt(num)<999999999)return '"999999999"';return mt;});if(m!==str){return this.write(m);}}return this.write(str);};}catch(e){}
console.log("[INFINITE_TOKENS] Engine active - injecting unlimited tokens/points");
send({type:"log",message:"INFINITE_TOKENS: Infinite tokens engine loaded"});

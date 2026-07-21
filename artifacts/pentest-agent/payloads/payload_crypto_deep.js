/*
 * DeepSeek Core — payload_crypto_deep.js  (PHASE 1.1)
 * Surgical crypto interception: captures keys/IVs, plaintext in, ciphertext out,
 * and native AES/RSA in libflutter/librsa_bridge/libcrypto. Every observation is
 * emitted as a structured send({event,...}) so core/brain.py can dispatch tools
 * (e.g. decryptor.py) against it. Crash-safe: each hook is isolated in try/catch.
 */
"use strict";
var _seen = {};
function once(k){ if(_seen[k]) return false; _seen[k]=true; return true; }
function hex(bytes, max){ if(!bytes) return ""; var n=Math.min(bytes.length, max||64), h=""; for(var i=0;i<n;i++){ var b=(bytes[i]&0xff).toString(16); h+=(b.length<2?"0":"")+b; } return h; }
function abhex(ab, max){ if(!ab) return ""; var u=new Uint8Array(ab); return hex(u, max); }
function toStr(bytes, max){ var s="", n=Math.min(bytes.length, max||512); for(var i=0;i<n;i++) s+=String.fromCharCode(bytes[i]&0xff); return s; }
function emit(o){ try{ send(o); }catch(e){} }

function hookJavaCrypto(){
  Java.perform(function(){
    // Cipher.init(int, Key, [params]) -> capture key + IV
    try{
      var Cipher = Java.use("javax.crypto.Cipher");
      Cipher.init.overloads.forEach(function(ov){ try{ ov.implementation=function(){
        try{
          for(var i=0;i<arguments.length;i++){
            var a=arguments[i];
            if(a && a.getEncoded){ var enc=a.getEncoded(); if(enc){ var kh=hex(enc,64);
              if(once("ck-"+kh)) emit({event:"crypto_key", source:"Cipher.init", algo:(this.getAlgorithm?this.getAlgorithm():""), key_hex:kh}); } }
            if(a && a.getIV){ try{ var iv=a.getIV(); if(iv){ var ih=hex(iv,32); if(once("iv-"+ih)) emit({event:"crypto_iv", iv_hex:ih}); } }catch(e){} }
          }
        }catch(e){}
        return ov.apply(this, arguments);
      }; }catch(e){} });
      // Cipher.doFinal(byte[]) -> plaintext in + ciphertext out + algo
      Cipher.doFinal.overloads.forEach(function(ov){ try{ ov.implementation=function(){
        try{ if(arguments.length>0 && arguments[0] && arguments[0].length){ var pin=toStr(arguments[0],512);
          if(once("pt-"+pin.slice(0,40))) emit({event:"plaintext", algo:(this.getAlgorithm?this.getAlgorithm():""), data:pin.slice(0,600)}); } }catch(e){}
        var out=ov.apply(this, arguments);
        try{ if(out && out.length){ var oh=hex(out,64), os=toStr(out,512);
          emit({event:"ciphertext", algo:(this.getAlgorithm?this.getAlgorithm():""), out_hex:oh, out_str:os.slice(0,300), len:out.length}); } }catch(e){}
        return out;
      }; }catch(e){} });
    }catch(e){}
    // SecretKeySpec(byte[], String) -> raw key material
    try{ var SKS=Java.use("javax.crypto.spec.SecretKeySpec");
      SKS.$init.overload("[B","java.lang.String").implementation=function(k,a){ try{ var kh=hex(k,64);
        if(once("sks-"+kh)) emit({event:"crypto_key", source:"SecretKeySpec", algo:String(a), key_hex:kh}); }catch(e){}
        return this.$init(k,a); };
    }catch(e){}
    try{ var IV=Java.use("javax.crypto.spec.IvParameterSpec");
      IV.$init.overload("[B").implementation=function(b){ try{ var ih=hex(b,32);
        if(once("ivs-"+ih)) emit({event:"crypto_iv", source:"IvParameterSpec", iv_hex:ih}); }catch(e){} return this.$init(b); };
    }catch(e){}
  });
}

function hookNativeCrypto(){
  var LIB=/lib(flutter|rsa_bridge|crypto|ssl|conscrypt|boring|native|secur|mbedtls)/i;
  var FN=/^(AES_(encrypt|decrypt)|AES_set_(en|de)crypt_key|RSA_(public|private)_(encrypt|decrypt)|EVP_(Encrypt|Decrypt)(Init|Update|Final))/;
  try{
    Process.enumerateModules().forEach(function(m){
      if(!LIB.test(m.name)) return;
      var exps; try{ exps=Module.enumerateExports(m.name); }catch(e){ return; }
      exps.forEach(function(e){
        if(e.type!=="function" || !FN.test(e.name)) return;
        try{ Interceptor.attach(e.address, {
          onEnter:function(a){ try{
            // best-effort: log first two ptr args as short hex windows
            var w1=""; try{ w1=abhex(Memory.readByteArray(a[0],16),16); }catch(x){}
            var w2=""; try{ w2=abhex(Memory.readByteArray(a[1],16),16); }catch(x){}
            if(once("nc-"+m.name+e.name+w1)) emit({event:"native_crypto", lib:m.name, fn:e.name, arg0:w1, arg1:w2});
          }catch(x){} }
        }); }catch(x){}
      });
    });
  }catch(e){}
}

setTimeout(function(){ hookJavaCrypto(); hookNativeCrypto(); emit({event:"ready", module:"crypto_deep"}); }, 0);

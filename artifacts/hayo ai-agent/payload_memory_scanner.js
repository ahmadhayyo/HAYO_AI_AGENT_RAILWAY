/* HAYO Cipher-7 — Aggressive Memory Scanner (payload_memory_scanner.js)
 * =================================================================== */
Java.perform(function () {
    console.log("[MEMSCAN] Aggressive memory scanner engaged...");
    var SCAN_INTERVAL = 15000;
    var SCAN_SIZE_LIMIT = 5000000;
    var findings = {};
    var patterns = [
        {name:"RSA_KEY", regex:/-----BEGIN\s?(RSA|EC|DSA)?\s?PRIVATE KEY-----[\s\S]{1,5000}?-----END\s?(RSA|EC|DSA)?\s?PRIVATE KEY-----/g},
        {name:"OPENSSH_KEY", regex:/-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]{1,5000}?-----END OPENSSH PRIVATE KEY-----/g},
        {name:"GOOGLE_API", regex:/AIza[0-9A-Za-z\-_]{35}/g},
        {name:"OPENAI_KEY", regex:/sk-[A-Za-z0-9]{20,50}/g},
        {name:"ANTHROPIC_KEY", regex:/sk-ant-[A-Za-z0-9]{20,}/g},
        {name:"AWS_ACCESS", regex:/AKIA[0-9A-Z]{16}/g},
        {name:"GITHUB_TOKEN", regex:/github_pat_[A-Za-z0-9_]{30,}/g},
        {name:"JWT", regex:/eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}/g},
        {name:"API_KEY_JSON", regex:/["']api[_-]?key["']\s*[:=]\s*["']([^"']+)["']/g},
        {name:"BEARER", regex:/bearer\s+[A-Za-z0-9_\-\.]{20,}/gi},
        {name:"ACCESS_TOKEN", regex:/["']access_token["']\s*[:=]\s*["']([^"']+)["']/g},
        {name:"REFRESH_TOKEN", regex:/["']refresh_token["']\s*[:=]\s*["']([^"']+)["']/g},
        {name:"PASSWORD", regex:/["']password["']\s*[:=]\s*["']([^"']{4,})["']/g},
        {name:"SECRET", regex:/["']secret["']\s*[:=]\s*["']([^"']{4,})["']/g},
        {name:"JDBC", regex:/jdbc:(mysql|postgresql|sqlserver|oracle):\/\/[^\s"']+/g},
        {name:"MONGO", regex:/mongodb(?:\+srv)?:\/\/[^\s"']+/g},
    ];
    function shannonEntropy(str){
        var freq={};for(var i=0;i<str.length;i++){var c=str.charAt(i);freq[c]=(freq[c]||0)+1;}
        var ent=0.0,len=str.length;for(var ch in freq){var p=freq[ch]/len;ent-=p*(Math.log(p)/Math.log(2));}
        return ent;
    }
    function scanMemory(module,address,size){
        try{
            if(size<=0||size>SCAN_SIZE_LIMIT)return;
            var bytes=Memory.readByteArray(address,Math.min(size,500000));if(!bytes)return;
            var uint8=new Uint8Array(bytes);var str="";
            for(var i=0;i<uint8.length;i++){var b=uint8[i];str+=(b>=32&&b<=126)?String.fromCharCode(b):".";}
            patterns.forEach(function(p){
                try{p.regex.lastIndex=0;var m;while((m=p.regex.exec(str))!==null){
                    var found=m[0].substring(0,120);
                    var key=p.name+":"+found;
                    if(!findings[key]){findings[key]={};console.log("[MEMSCAN] "+p.name+" @ "+module+": "+found);}
                }}catch(e){}
            });
            var tokens=str.split(/[.\s,;:!?(){}[\]<>"'=+\/|&%$#@~`\x00-\x1f]+/);
            tokens.forEach(function(token){
                if(token.length>=20&&token.length<=200&&/^[A-Za-z0-9+\/=_-]+$/.test(token)){
                    var ent=shannonEntropy(token);
                    if(ent>4.5&&!findings["ENTROPY:"+token]){
                        findings["ENTROPY:"+token]={};
                        console.log("[MEMSCAN] High entropy ("+ent.toFixed(2)+") in "+module+": "+token.substring(0,80));
                    }
                }
            });
        }catch(e){}
    }
    function doScan(){
        try{
            var modules=Process.enumerateModules();
            modules.forEach(function(mod){
                if(mod.size>100*1024*1024){
                    try{var ranges=Process.enumerateRanges('rw-');ranges.forEach(function(r){
                        if(r.base>=mod.base&&r.base.add(r.size)<=mod.base.add(mod.size))scanMemory(mod.name,r.base,r.size);
                    });}catch(e){}return;
                }
                scanMemory(mod.name,mod.base,mod.size);
            });
        }catch(e){}
        console.log("[MEMSCAN] Scan complete. Unique findings: "+Object.keys(findings).length);
    }
    function startScanner(){
        console.log("[MEMSCAN] Starting periodic scanner (interval: "+(SCAN_INTERVAL/1000)+"s)...");
        doScan();
        setInterval(doScan,SCAN_INTERVAL);
    }
    startScanner();
});

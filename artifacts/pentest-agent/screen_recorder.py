#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""HAYO Screen Recorder & Logcat Harvester"""
import argparse,os,re,subprocess,sys,threading,time
from datetime import datetime
G=chr(92)+"[92m";R=chr(92)+"[91m";Y=chr(92)+"[93m";C=chr(92)+"[96m";X=chr(92)+"[0m"
import re;PATS=[re.compile(r"(?i)(password|passwd|pwd)\s*[=:]\s*\S+"),re.compile(r"(?i)(token|api[_-]?key|secret|jwt)\s*[=:]\s*\S+"),re.compile(r"eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}"),re.compile(r"AIza[0-9A-Za-z\-_]{35}"),re.compile(r"AKIA[0-9A-Z]{16}")]
def find_adb():
    for c in ["C:/Users/PT/Downloads/platform-tools/adb.exe","adb"]:
        if c=="adb" or os.path.isfile(c):return c
    return "adb"
class Rec:
    def __init__(self,adb,out="loot",dur=60,rec=True,log=True,dev=None):
        self.adb=adb;self.out=out;self.dur=dur;self.rec=rec;self.log=log;self.hits=[];self.dev=dev
        os.makedirs(out,exist_ok=True)
        if self.dev: self.adb += f" -s {self.dev}"
    def record(self):
        if not self.rec:return
        ts=datetime.now().strftime("%Y%m%d_%H%M%S")
        dp="/sdcard/hayo_"+ts+".mp4";lp=os.path.join(self.out,"screen_"+ts+".mp4")
        try:
            subprocess.run(self.adb+" shell screenrecord --time-limit "+str(self.dur)+" --bit-rate 4000000 "+dp,shell=True,timeout=self.dur+30)
        except subprocess.TimeoutExpired:
            print("[!] screenrecord timed out — pulling whatever was captured so far.")
        rc=subprocess.run(self.adb+" pull "+dp+" "+chr(34)+lp+chr(34),shell=True,capture_output=True,text=True,timeout=60)
        if rc.returncode==0:print("Saved:",lp)
        subprocess.run(self.adb+" shell rm "+dp,shell=True)
    def harvest(self,pkg=None):
        if not self.log:return
        ts=datetime.now().strftime("%Y%m%d_%H%M%S")
        lp=os.path.join(self.out,"logcat_"+ts+".txt")
        # stable name the brain/report always looks for (PHASE 4)
        dyn=os.path.join(self.out,"logcat_dynamic.txt")
        sp=os.path.join(self.out,"logcat_sensitive_"+ts+".txt")
        subprocess.run(self.adb+" logcat -c",shell=True,capture_output=True)
        proc=None
        try:
            with open(lp,"w",encoding="utf-8",errors="replace")as lf,\
                 open(dyn,"w",encoding="utf-8",errors="replace")as df,\
                 open(sp,"w",encoding="utf-8",errors="replace")as sf:
                proc=subprocess.Popen(self.adb+" logcat -v time",shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                start=time.time();count=0;sc=0
                while time.time()-start<self.dur:
                    line=proc.stdout.readline()
                    if not line:time.sleep(0.1);continue
                    count+=1;lf.write(line);df.write(line)
                    for pat in PATS:
                        if pat.search(line):sf.write(line);self.hits.append(line.strip());sc+=1;break
        finally:
            # graceful termination (PHASE 4): terminate → wait → kill fallback
            if proc is not None:
                try:proc.terminate();proc.wait(timeout=5)
                except Exception:
                    try:proc.kill()
                    except Exception:pass
        print("Lines:",count,"Sensitive:",sc,"-> loot/logcat_dynamic.txt")
    def run(self,pkg=None):
        ts=[]
        if self.rec:t=threading.Thread(target=self.record);t.daemon=True;ts.append(t)
        if self.log:t=threading.Thread(target=self.harvest,args=(pkg,));t.daemon=True;ts.append(t)
        for t in ts:t.start()
        for t in ts:t.join()
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--duration","-d",type=int,default=60)
    p.add_argument("--output","-o",default="loot")
    p.add_argument("--package","-p")
    p.add_argument("--device","-dvc")
    p.add_argument("--no-screen",action="store_true")
    p.add_argument("--no-logcat",action="store_true")
    args=p.parse_args()
    adb_path = find_adb()
    check_cmd = adb_path
    if args.device: check_cmd += f" -s {args.device}"
    rc=subprocess.run(check_cmd+" devices",shell=True,capture_output=True,text=True)
    if "device" not in rc.stdout:print("No device");sys.exit(1)
    r=Rec(adb_path,args.output,args.duration,not args.no_screen,not args.no_logcat, dev=args.device)
    r.run(args.package)
if __name__=="__main__":main()

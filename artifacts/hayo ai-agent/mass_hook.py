#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""HAYO Mass Hook Injector"""
import argparse,json,os,subprocess,sys
from concurrent.futures import ThreadPoolExecutor,as_completed
G=chr(92)+"[92m";R=chr(92)+"[91m";Y=chr(92)+"[93m";C=chr(92)+"[96m";X=chr(92)+"[0m"
BASE=os.path.dirname(os.path.abspath(__file__))
PL=["payload_universal.js","payload_native_ssl.js","instrument_deep.js","payload_evasion.js","payload_memory_scanner.js"]
def find_adb():
    for c in ["C:/Users/PT/Downloads/platform-tools/adb.exe","adb"]:
        if c=="adb" or os.path.isfile(c):return c
    return "adb"
class MH:
    def __init__(self,adb,pls=None,w=3,f=None,dev=None):
        self.adb=adb;self.pls=pls or PL;self.w=w;self.f=f;self.res={};self.dev=dev
        # frida device selector: explicit -D <id> is REQUIRED when more than one
        # device is attached, so we never inject into the wrong (e.g. real) phone.
        self.fsel=("-D "+dev) if dev else "-U"
        if dev: self.adb += " -s "+dev
    def enum(self):
        rc,out,_=self._sh(self.adb+" shell pm list packages -3")
        if rc:rc,out,_=self._sh(self.adb+" shell pm list packages")
        pkgs=[l[8:]for l in out.split("\n")if l.startswith("package:")]
        if self.f:pkgs=[p for p in pkgs if self.f in p]
        return sorted(p for p in pkgs if not p.startswith(("android.","com.android.","com.google.android.")))
    def _sh(self,cmd,t=120):
        try:r=subprocess.run(cmd,shell=True,capture_output=True,text=True,timeout=t);return r.returncode,r.stdout.strip(),r.stderr.strip()
        except:return -1,"",""
    def run(self):
        pkgs=self.enum()
        if not pkgs:print("No targets");return
        print("Targets:",len(pkgs))
        def inj(p):
            for pl in self.pls:
                pp=os.path.join(BASE,pl)
                if not os.path.isfile(pp):continue
                rc,out,err=self._sh("frida "+self.fsel+" -f "+p+" -l "+chr(34)+pp+chr(34)+" 2>&1",t=20)
                blob=(out or "")+(err or "")
                # A loaded hook prints its banner; returncode alone is unreliable
                # because frida (spawn+auto-resume) keeps the process alive until
                # our timeout.
                hooked="[+]" in blob or "Hooked" in blob or "SSL" in blob
                if not hooked:
                    rc,out,err=self._sh("frida "+self.fsel+" -n "+p+" -l "+chr(34)+pp+chr(34)+" 2>&1",t=20)
                    blob=(out or "")+(err or "")
                    hooked="[+]" in blob or "Hooked" in blob or "SSL" in blob
                self.res[p+":"+pl]="OK"if(rc==0 or hooked)else"FAIL"
        with ThreadPoolExecutor(max_workers=self.w)as ex:list(ex.map(inj,pkgs))
        os.makedirs("loot",exist_ok=True)
        with open("loot/mass_hook.json","w")as j:json.dump(self.res,j,indent=2)
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--workers","-w",type=int,default=3)
    p.add_argument("--filter","-f")
    p.add_argument("--device","-D")
    p.add_argument("--list",action="store_true")
    args=p.parse_args()
    adb=find_adb()
    # Safety guard: if several devices are attached and none was named, refuse to
    # run — otherwise frida -U could inject into a real personal phone by mistake.
    dev=args.device
    if not dev:
        r=subprocess.run(adb+" devices",shell=True,capture_output=True,text=True)
        online=[l.split()[0] for l in r.stdout.splitlines()[1:] if l.strip().endswith("device")]
        if len(online)>1:
            print("Multiple devices attached: "+", ".join(online))
            print("Refusing to run without an explicit target. Re-run with:  --device <id>")
            sys.exit(2)
        if len(online)==1:dev=online[0]
    m=MH(adb,PL,args.workers,args.filter,dev)
    if args.list:
        for pkg in m.enum():print(" ",pkg)
    else:m.run()
if __name__=="__main__":main()

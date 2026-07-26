#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""HAYO Data Cloner - extract app data from Android device."""
import argparse, os, subprocess, sys, time
G=chr(92)+"[92m";R=chr(92)+"[91m";X=chr(92)+"[0m"
def find_adb():
    for c in ["C:/Users/PT/Downloads/platform-tools/adb.exe","adb"]:
        if c=="adb" or os.path.isfile(c):return c
    return "adb"
def sh(cmd,timeout=120):
    try:
        r=subprocess.run(cmd,shell=True,capture_output=True,text=True,timeout=timeout)
        return r.returncode,r.stdout.strip(),r.stderr.strip()
    except:return -1,"",""
def extract(adb,pkg,out,root=False,dev=None):
    os.makedirs(out,exist_ok=True)
    adb_cmd = adb
    if dev: adb_cmd += f" -s {dev}"
    
    rc,out_msg,_=sh(adb_cmd+" shell pm path "+pkg)
    if rc or "package:" not in out_msg:print("Pkg not found");return
    dd="/data/data/"+pkg
    rc,_,_=sh(adb_cmd+" shell ls "+dd)
    if rc:
        if root:rc,_,_=sh(adb_cmd+" shell su -c "+chr(39)+"ls "+dd+chr(39))
        if rc:rc,_,_=sh(adb_cmd+" shell run-as "+pkg+" ls . 2>/dev/null")
        if rc:print("Cannot access data");return
    ts=time.strftime("%Y%m%d_%H%M%S");a="/data/local/tmp/"+pkg+"_data_"+ts+".tar"
    if root:rc,_,_=sh(adb_cmd+" shell su -c "+chr(39)+"tar cf "+a+" "+dd+" 2>/dev/null"+chr(39))
    else:rc,_,_=sh(adb_cmd+" shell tar cf "+a+" "+dd+" 2>/dev/null")
    if rc:rc,_,_=sh(adb_cmd+" shell run-as "+pkg+" tar cf "+a+" . 2>/dev/null")
    if rc:print("Archive failed");return
    lt=os.path.join(out,pkg+"_data_"+ts+".tar")
    rc,_,_=sh(adb_cmd+" pull "+a+" "+chr(34)+lt+chr(34))
    if rc==0:print("Data saved:",lt)
    sh(adb_cmd+" shell rm "+a)
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--package","-p",required=True)
    p.add_argument("--output","-o",default="loot")
    p.add_argument("--device","-d",default=None)
    p.add_argument("--root",action="store_true")
    args=p.parse_args()
    extract(find_adb(),args.package,os.path.join(args.output,args.package+"_clone_"+str(int(time.time()))), root=args.root, dev=args.device)
if __name__=="__main__":main()

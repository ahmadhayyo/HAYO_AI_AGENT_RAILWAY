#!/usr/bin/env python3
import argparse, base64, hashlib, json, os, sqlite3, time, uuid
from datetime import datetime
from pathlib import Path
from xml.etree import ElementTree
G="[92m";R="[91m";Y="[93m";C="[96m";X="[0m"
class TokenForger:
    def __init__(self,out="loot/token_forge"):
        self.o=Path(out);self.o.mkdir(parents=True,exist_ok=True)
    def gen_jwt(self,bt=None):
        p={"sub":str(uuid.uuid4()),"iat":int(time.time()),"premium":True,"pro":True,"vip":True,"plan":"enterprise","tier":"premium","role":"admin","status":"active","expires":"2099-12-31","tokens":999999999,"coins":999999999,"credits":999999999}
        if bt:
            try:
                parts=bt.split('.');h=json.loads(base64.urlsafe_b64decode(parts[0]+'=='));p2=json.loads(base64.urlsafe_b64decode(parts[1]+'=='))
                p={**p2,**p}
            except:pass
        hdr=base64.urlsafe_b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).decode().rstrip('=')
        pld=base64.urlsafe_b64encode(json.dumps(p,default=str).encode()).decode().rstrip('=')
        t=f"{hdr}.{pld}.";open(self.o/'premium_jwt.txt','w').write(t);print(f"{G}JWT -> {self.o}/premium_jwt.txt{X}");return t
    def forge_receipt(self,pkg="com.target.app",prod="premium"):
        import random
        r={"orderId":f"GPA.{random.randint(1000,9999)}-{random.randint(1000,9999)}-{random.randint(10000,99999)}","packageName":pkg,"productId":prod,"purchaseTime":int(time.time()*1000),"purchaseState":0,"purchaseToken":f"hayo-{uuid.uuid4().hex[:16]}","autoRenewing":True,"acknowledged":True}
        s=base64.b64encode(hashlib.sha256(json.dumps(r).encode()).digest()).decode()
        json.dump({"receipt":r,"signature":s},open(self.o/'receipt.json','w'),indent=2);print(f"{G}Receipt -> {self.o}/receipt.json{X}");return r
    def spoof_rules(self):
        rules={"endpoints":{"google":{"pattern":"androidpublisher.*/purchases","spoof":{"purchaseState":0,"acknowledgementState":1}},"revenuecat":{"pattern":"api.revenuecat.com","spoof":{"subscriber":{"entitlements":{"premium":{"expires_date":"2099-12-31T23:59:59Z"}}}}},"stripe":{"pattern":"api.stripe.com","spoof":{"paid":True,"status":"paid","amount_paid":0}}}}
        json.dump(rules,open(self.o/'spoof_rules.json','w'),indent=2);print(f"{G}Rules -> {self.o}/spoof_rules.json{X}");return rules
    def inject_prefs(self,path):
        if not os.path.isfile(path):print(f"{R}Not found{X}");return
        t=ElementTree.parse(path);r=t.getroot()
        for e in r.findall('.//*[@name]'):
            n=e.get('name','').lower()
            if any(p in n for p in['premium','pro','vip','subscribed','purchased','unlocked']):e.tag='boolean';e.text='true'
            if any(p in n for p in['coin','gem','token','point','credit','balance']):e.tag='int';e.text='999999999'
        t.write(path,encoding='utf-8',xml_declaration=True);print(f"{G}Injected {path}{X}")
    def inject_db(self,path):
        if not os.path.isfile(path):print(f"{R}Not found{X}");return
        c=sqlite3.connect(str(path)).cursor()
        c.execute("SELECT name FROM sqlite_master WHERE type='table'")
        for t in c.fetchall():
            c.execute(f'PRAGMA table_info("{t[0]}")')
            cols=c.fetchall()
            for col in cols:
                if any(p in col[1].lower() for p in['coin','gem','token','point','credit','balance']):
                    c.execute(f'UPDATE "{t[0]}" SET "{col[1]}" = 999999999')
        c.connection.commit();c.connection.close();print(f"{G}Injected DB {path}{X}")
if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--package','-p');ap.add_argument('--premium-jwt',action='store_true');ap.add_argument('--receipt',action='store_true')
    ap.add_argument('--inject-prefs',nargs='+');ap.add_argument('--inject-db',nargs='+');ap.add_argument('--output','-o',default='loot/token_forge')
    a=ap.parse_args();f=TokenForger(a.output)
    if a.premium_jwt:f.gen_jwt()
    if a.receipt:f.forge_receipt(a.package)
    if a.inject_prefs:
        for p in a.inject_prefs: f.inject_prefs(p)
    if a.inject_db:
        for d in a.inject_db: f.inject_db(d)

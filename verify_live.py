# -*- coding: utf-8 -*-
"""배포된 map.html 을 내려받아 복호화하고 아이콘이 실제로 들어갔는지 확인한다."""
import os, sys, json, base64, re, urllib.request, hashlib
sys.stdout.reconfigure(encoding='utf-8')
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

URL = "https://say-bot.github.io/cheonha-archive/map.html?v=" + os.urandom(4).hex()
pw = os.environ.get("CHEONHA_PW") or sys.exit("CHEONHA_PW 필요")

req = urllib.request.Request(URL, headers={"Cache-Control": "no-cache"})
html = urllib.request.urlopen(req).read().decode("utf-8")
m = re.search(r'<script id="payload" type="application/json">(.*?)</script>', html, re.S)
P = json.loads(m.group(1))

key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                 salt=base64.b64decode(P["salt"]), iterations=P["it"]).derive(pw.encode())
plain = AESGCM(key).decrypt(base64.b64decode(P["iv"]),
                            base64.b64decode(P["ct"]), None).decode("utf-8")
print(f"복호화 성공: {len(plain):,} chars")

icons = json.loads(re.search(r'window\.WICONS=(\{.*?\});', plain, re.S).group(1))
local = json.load(open(os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "map", "icons_datauri.json"), encoding="utf-8"))
for k in ("city", "gate", "fort"):
    live_h = hashlib.sha256(icons[k].encode()).hexdigest()[:12]
    loc_h = hashlib.sha256(local[k].encode()).hexdigest()[:12]
    print(f"  {k:<5} live {len(icons[k]):>6}B {live_h}  {'일치' if live_h == loc_h else '불일치!'}")

for pat, label in [(r"drawIcon\('city', null", "성지 틴트 제거"),
                   (r"drawIcon\('gate', null", "관문 틴트 제거"),
                   (r"drawIcon\('fort', null", "부두 틴트 제거"),
                   (r"누끼로 딴 실물 구조물", "새 아이콘 주석")]:
    print(f"  {label}: {'있음' if re.search(pat, plain) else '없음!'}")

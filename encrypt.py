#!/usr/bin/env python3
"""천하결전 아카이브 암호화 빌드 스크립트.

source.html(평문 아카이브)을 AES-256-GCM으로 암호화해
암호 게이트가 달린 index.html을 생성한다. 브라우저는 Web Crypto로 복호화한다.

사용법:
    CHEONHA_PW='암호' python3 encrypt.py            # source.html -> index.html
    CHEONHA_PW='암호' python3 encrypt.py in.html out.html
"""
import os, sys, base64, json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

ITERATIONS = 200_000

SRC = sys.argv[1] if len(sys.argv) > 1 else "source.html"
OUT = sys.argv[2] if len(sys.argv) > 2 else "index.html"

pw = os.environ.get("CHEONHA_PW")
if not pw:
    sys.exit("환경변수 CHEONHA_PW 에 암호를 넣어주세요.")

raw = open(SRC, encoding="utf-8").read()

# 완전한 HTML 문서로 감싸기 (아티팩트 조각이면 head/body 래핑)
head = raw.lstrip()[:60].lower()
if head.startswith("<!doctype") or head.startswith("<html"):
    full = raw
else:
    idx = raw.find('<div class="app"')
    if idx == -1:
        idx = 0
    full = (
        '<!doctype html>\n<html lang="ko">\n<head>\n'
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        + raw[:idx]
        + '</head>\n<body>\n'
        + raw[idx:]
        + '\n</body>\n</html>\n'
    )

salt = os.urandom(16)
iv = os.urandom(12)
key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                 iterations=ITERATIONS).derive(pw.encode("utf-8"))
ct = AESGCM(key).encrypt(iv, full.encode("utf-8"), None)  # ct||tag

payload = json.dumps({
    "salt": base64.b64encode(salt).decode(),
    "iv":   base64.b64encode(iv).decode(),
    "ct":   base64.b64encode(ct).decode(),
    "it":   ITERATIONS,
}, separators=(",", ":"))

GATE = '''<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>천하결전 아카이브 · 잠금</title>
<style>
  :root{color-scheme:dark;}
  *{box-sizing:border-box;}
  body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0d1417;
    font-family:"Apple SD Gothic Neo","Pretendard","Malgun Gothic",system-ui,sans-serif;color:#ece6d6;
    background-image:radial-gradient(120% 80% at 80% -10%,rgba(111,194,164,.10),transparent 60%),
      radial-gradient(90% 60% at -5% 5%,rgba(221,86,72,.07),transparent 55%);}
  .card{width:min(90vw,380px);padding:34px 30px 30px;border:1px solid #294048;border-radius:18px;
    background:rgba(20,36,43,.85);box-shadow:0 24px 60px rgba(0,0,0,.45);text-align:center;}
  .seal{width:54px;height:54px;margin:0 auto 16px;display:grid;place-items:center;font-size:24px;
    border:1px solid #2f6151;border-radius:13px;background:#16302b;}
  h1{margin:0 0 6px;font-family:"Nanum Myeongjo","AppleMyungjo",Batang,serif;font-size:22px;letter-spacing:-.01em;}
  p{margin:0 0 20px;color:#94a6a6;font-size:13px;letter-spacing:.02em;}
  form{display:flex;gap:8px;}
  input{flex:1;min-width:0;padding:11px 13px;border:1px solid #294048;border-radius:10px;background:#0f1719;
    color:#ece6d6;font-size:15px;outline:none;}
  input:focus{border-color:#6fc2a4;box-shadow:0 0 0 3px rgba(111,194,164,.15);}
  button{padding:11px 16px;border:1px solid #2f6151;border-radius:10px;background:#16302b;color:#6fc2a4;
    font-weight:700;font-size:14px;cursor:pointer;white-space:nowrap;}
  button:hover{background:#1c3b34;}
  .err{margin-top:14px;min-height:18px;font-size:12.5px;color:#dd5648;letter-spacing:.02em;}
  .foot{margin-top:18px;font-size:11px;color:#5c7073;letter-spacing:.06em;font-family:ui-monospace,monospace;}
</style>
</head>
<body>
<main>
  <div class="card">
    <div class="seal">🔒</div>
    <h1>천하결전 아카이브</h1>
    <p>낙월 동맹 전용 · 암호를 입력하세요</p>
    <form id="f">
      <input id="pw" type="password" autocomplete="current-password" placeholder="암호" autofocus>
      <button type="submit">열기</button>
    </form>
    <div class="err" id="err"></div>
    <div class="foot">AES-256-GCM · 암호 없이는 열람 불가</div>
  </div>
</main>
<script id="payload" type="application/json">__PAYLOAD__</script>
<script>
(function(){
  var P=JSON.parse(document.getElementById('payload').textContent);
  var b64d=function(s){return Uint8Array.from(atob(s),function(c){return c.charCodeAt(0);});};
  var f=document.getElementById('f'),pw=document.getElementById('pw'),err=document.getElementById('err'),btn=f.querySelector('button');
  f.addEventListener('submit',function(e){
    e.preventDefault(); err.textContent=''; btn.disabled=true; btn.textContent='여는 중…';
    var enc=new TextEncoder();
    crypto.subtle.importKey('raw',enc.encode(pw.value),'PBKDF2',false,['deriveKey'])
    .then(function(km){
      return crypto.subtle.deriveKey(
        {name:'PBKDF2',salt:b64d(P.salt),iterations:P.it,hash:'SHA-256'},
        km,{name:'AES-GCM',length:256},false,['decrypt']);
    })
    .then(function(key){
      return crypto.subtle.decrypt({name:'AES-GCM',iv:b64d(P.iv)},key,b64d(P.ct));
    })
    .then(function(buf){
      var html=new TextDecoder().decode(buf);
      document.open(); document.write(html); document.close();
    })
    .catch(function(){
      err.textContent='암호가 올바르지 않습니다.'; btn.disabled=false; btn.textContent='열기'; pw.select();
    });
  });
})();
</script>
</body>
</html>
'''

open(OUT, "w", encoding="utf-8").write(GATE.replace("__PAYLOAD__", payload))
print(f"OK  {SRC} -> {OUT}  (plaintext {len(full):,} bytes, ciphertext {len(ct):,} bytes)")

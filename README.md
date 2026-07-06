# 천하결전 작전 아카이브

낙월 동맹 전용 정적 아카이브. 배포되는 `index.html`은 **AES-256-GCM으로 암호화된 암호 게이트**이며,
올바른 암호를 입력해야만 브라우저(Web Crypto)에서 내용을 복호화해 볼 수 있다.

- 저장소는 공개지만 **평문 내용은 저장소에 없다** — 암호문 blob만 커밋된다.
- 평문 원본 `source.html` 은 `.gitignore` 처리되어 커밋되지 않는다.

## 다시 빌드 (내용 수정·암호 변경 시)

```bash
CHEONHA_PW='새암호' python3 encrypt.py source.html index.html
git add index.html && git commit -m "update" && git push
```

의존성: `python3` + `cryptography` (`pip3 install --user cryptography`).

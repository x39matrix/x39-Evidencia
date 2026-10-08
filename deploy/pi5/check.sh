#!/usr/bin/env bash
# check.sh — estado de X-39 Evidencia API en la Pi 5. Uso: bash deploy/pi5/check.sh
# Verifica lo tocado o afirmado en la auditoría del 01/09/2026. Gasta el cupo de verify 60 s.
set -u
H=api.x39matrix.org; R="--resolve $H:443:127.0.0.1"; B="https://$H"
AID=31e1cf09a5b2a74cd978
HASH=eda1fa21b0a3c67ddaede7f84bd2641810594670a1438cd955f88fa6098d6967
pass=0; fail=0
t(){ if [ "$1" -eq 0 ]; then echo "PASS  $2"; pass=$((pass+1)); else echo "FAIL  $2"; fail=$((fail+1)); fi; }
code(){ curl -s -o /dev/null -w '%{http_code}' $R "$@"; }
echo "== X-39 check $(date -Is) =="
[ "$(systemctl is-active x39-api)" = active ]; t $? "servicio x39-api activo"
sudo journalctl -u x39-api --no-pager --since "$(systemctl show x39-api -p ActiveEnterTimestamp --value)" | grep '\[COLD\]' | tail -1 | grep -q 'OK'; t $? "ultimo autoexamen COLD: OK"
[ "$(code $B/api/health)" = 200 ]; t $? "health 200"
for p in /docs /redoc /openapi.json /api/docs; do [ "$(code $B$p)" = 404 ]; t $? "$p oculto (404)"; done
[ "$(code -X POST -H 'Content-Type: application/json' -d '{"public_key_b64":"AA=="}' $B/api/notaria/admin/cold_key)" = 403 ]; t $? "admin exige token (403 sin token, desde localhost)"
grep -q 'not remote_ip 127.0.0.1 ::1' /etc/caddy/Caddyfile; t $? "Caddy: admin bloqueado desde fuera (regla presente)"
! curl -sI $R $B/api/health | grep -qi '^server:'; t $? "sin cabecera Server"
curl -sI $R $B/api/health | grep -qi 'strict-transport-security'; t $? "HSTS presente"
PIN=$(grep -oE 'COLD_FP_PINNED = "[0-9a-f]{64}"' /opt/x39/api/backend/notaria.py | grep -oE '[0-9a-f]{64}')
FP=$(curl -s $R $B/api/notaria/cold_key | python3 -c 'import sys,json; print(json.load(sys.stdin).get("fingerprint",""))')
[ -n "$PIN" ] && [ "$PIN" = "$FP" ]; t $? "COLD registrada == huella fijada en codigo (${PIN:0:16}...)"
V=$(curl -s $R -X POST $B/api/notaria/verify -H 'Content-Type: application/json' -d "{\"hash\":\"$HASH\"}")
echo "$V" | python3 -c 'import sys,json; d=json.load(sys.stdin); sys.exit(0 if d.get("found") and d.get("cold_valid") is True else 1)'; t $? "acuerdo $AID: found y cold_valid"
echo "$V" | python3 -c 'import sys,json; d=json.load(sys.stdin); sys.exit(0 if d.get("ots_status")=="anchored_btc" and d.get("btc_block")==964449 else 1)'; t $? "acuerdo: anchored_btc en 964449"
curl -s $R -o /tmp/chk.pdf -w '%{http_code} %{content_type}' $B/api/notaria/certificate/$AID.pdf | grep -q '^200 application/pdf'; t $? "certificado PDF"
curl -s $R -o /tmp/chk.zip $B/api/notaria/proof/$AID.zip && python3 -c 'import zipfile,sys; z=zipfile.ZipFile("/tmp/chk.zip"); sys.exit(0 if z.testzip() is None else 1)'; t $? "bundle zip integro"
EXT=$(sudo ss -tlnH | grep -v -E '127\.0\.0\.1|::1' | awk '{print $4}' | grep -oE '[0-9]+$' | sort -un | grep -v -x -E '22|80|443|8333' | tr '\n' ' ')
[ -z "$EXT" ]; t $? "puertos externos solo 22/80/443/8333 (extra: ${EXT:-ninguno})"
L=$(sudo ss -tlnH | awk '{print $4}' | grep ':27017$'); echo "$L" | grep -q '^127\.0\.0\.1:27017$' && ! echo "$L" | grep -q -v '^127\.0\.0\.1:27017$'; t $? "Mongo solo en 127.0.0.1"
grep -q -- '--proxy-headers --forwarded-allow-ips=127.0.0.1' /etc/systemd/system/x39-api.service; t $? "uvicorn con --proxy-headers"
grep -q 'docs_url=None' /opt/x39/api/backend/server.py; t $? "docs apagados tambien en FastAPI"
[ -z "$(sudo -u x39api git -C /opt/x39/api status --short)" ]; t $? "repositorio limpio"
c=0; for i in $(seq 1 24); do [ "$(code -X POST -H 'Content-Type: application/json' -d '{"hash":"00"}' $B/api/notaria/verify)" = 429 ] && c=$((c+1)); done
[ "$c" -ge 1 ]; t $? "limite por IP en verify (429 vistos: $c)"
echo "== $pass PASS / $fail FAIL =="
[ "$fail" -eq 0 ]

# Endurecimiento y auditoría — 1 de septiembre de 2026

## Resultado
- Superficie pública medida desde tres nodos externos: **solo 80 y 443** abiertos. 22, 8000, 8333 y 27017 cerrados. UPnP apagado. Shodan sin ficha de la IP.
- Dependencias del backend: de 165 paquetes (plantilla Emergent) a **40 reales**; `pip-audit`: **110 vulnerabilidades → 0**. `pqcrypto 0.4.0` y `opentimestamps-client 0.7.2` sin cambios.
- Historial git: 24 commits, 291 MB, **cero secretos** (gitleaks 8.30.1).
- Acuerdo de referencia `31e1cf09a5b2a74cd978`: `cold_valid: True`, `anchored_btc`, bloque 964449 antes y después de cada cambio.

## Cambios desplegados (8 commits)
1. **Caddy** — /docs, /redoc y /openapi.json ocultos; `/api/notaria/admin/*` solo desde localhost; tope de cuerpo 20 MB; sin cabecera Server; X-Forwarded-For sobrescrito con la IP real.
2. **COLD fijada en código** (`COLD_FP_PINNED`) — autoexamen al arranque que aborta si Mongo tiene otra llave; `register_cold_key` rechaza otra huella; `cold_valid` exige huella fijada además de firma válida. Docs apagados también en FastAPI.
3. **Límites por IP** (slowapi) — global 300/min; verify 20, auth 10, join 10, ots/refresh 6, crear 20, payment_status 30. uvicorn con `--proxy-headers`.
4. **Dependencias mínimas** — `requirements-min.txt` (curada) → `requirements.txt` (freeze). Runbook en `deploy/pi5/README.md`.
5. **`_refresh_ots`** — nunca persiste un estado OTS peor que el guardado; captura fallos de `ots_upgrade` (antes: 500 en la verificación pública si faltaba el binario `ots`). Probado con `HWG_OTS_BIN` inexistente.
6. **Frontend** — react-router-dom 7.18.3, axios 1.20.0 (compilado, pendiente de desplegar al canister).
7. Pi: rpcbind deshabilitado; `/etc/x39/api.env` root:x39api 640 (verificado).
8. **Emergent** — exportados al T7 (`x39-llaves/emergent-export-20260901`, con SHA256SUMS) la prueba pública, `.ots`, `.zip` y certificado del demo `demo0000demo0001` (bloque 957242; COLD misma huella). Borrado de cuenta programado para el **16/10/2026**; solicitud RGPD art. 17 enviada a support@emergent.sh; apagado del despliegue **pendiente de confirmación**.

## Revisado y correcto sin cambios
Reto de login de 256 bits, 5 min, ligado a la llave, consumo atómico; sesión 256 bits/7 días con caducidad comprobada; cookie HttpOnly+Secure+SameSite=Lax; CSRF por token doble; logout borra la sesión en servidor; CORS explícito. `agreement_id` 80 bits; `invite_token` 144 bits con comparación constante y 409 si ya hay parte B. `sig_key` de escritura única por rol; llaves E2E solo en el hueco propio. `cold_signature` exige token de operador y verifica antes de guardar.

## Pendientes con fecha
- ~08/09: borrar `/opt/x39/api/.venv-old-20260901`.
- Fase E (04–07/09): desplegar el frontend con dependencias nuevas (con rollback), subdominios www y evidences, textos frente a capacidades en el bundle desplegado, revisar service worker.
- Confirmar apagado de Emergent cuando responda el soporte.
- Octubre, auditoría E2E con el frontend delante: firmar y fijar la llave P-256; verificar `xwing_pub_sig_b64` en servidor y bloquear cambio de pubkey X-Wing tras el ciphertext de B; identidad con sha256 completo (con migración); incluir el host en el texto firmado del reto; migrar de CRA a Vite; código en solo lectura (root) con `ReadWritePaths` acotado.

## Despliegue web (01/09/2026, 16:15)
- Canister tvkfy actualizado desde `frontend/` con las dependencias de runtime nuevas y `public/verify_bundle.py` (huella COLD clavada): bundle `main.86428dd0.js`, `/verify_bundle.py` 200, `/verificar` 200, ic-domains OK. Rollback en `~/home_viejo/x39web/dist.rollback-20260901-1613`.
- Service worker `x39matrix-v13-20260828` revisado: navegacion red-primero, assets con hash cache-primero; no requiere bump por despliegue.
- Pendiente Fase E: `security_policy` en `.ic-assets.json5` (con prueba), subdominios www y evidences, huella WARM historica en verificadores.

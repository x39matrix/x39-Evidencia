# X-39 Notaría API — despliegue en la Pi 5

- **Código**: `/opt/x39/api` (checkout git, rama `textos-honestos`, propietario `x39api`). Commits en la Pi con `sudo -u x39api git …`; traer a WSL con `git pull --rebase x39pi@192.168.1.46:/opt/x39/api textos-honestos`.
- **Servicio**: `x39-api.service` (copia en esta carpeta). uvicorn en 127.0.0.1:8000 con `--proxy-headers --forwarded-allow-ips=127.0.0.1`. Secretos en `/etc/x39/api.env` (root:x39api, 640).
- **Proxy**: Caddy nativo, `/etc/caddy/Caddyfile` (copia aquí). Oculta /docs, /redoc y /openapi.json; `/api/notaria/admin/*` solo desde localhost; tope de cuerpo 20 MB; sin cabecera Server; sobrescribe X-Forwarded-For con la IP real.
- **Mongo**: contenedor `x39-mongo` (mongo:7) publicado solo en 127.0.0.1:27017.
- **Límites por IP**: slowapi (`backend/ratelimit.py`). `headers_enabled` debe seguir desactivado.
- **Dependencias**: `backend/requirements-min.txt` (lista curada) → `backend/requirements.txt` (freeze fijado). `pqcrypto` y `opentimestamps-client` NO se actualizan sin decisión expresa: son cadena de verificación.

## Autoexamen al arranque
El servidor aborta si la clave COLD registrada en Mongo no coincide con `COLD_FP_PINNED` (`backend/notaria.py`). Comprobar `[COLD] OK` en `journalctl -u x39-api`.

## Actualizar dependencias (procedimiento probado el 01/09/2026)
1. Como x39api, con `HOME=/opt/x39/api/home`: `python3 -m venv .venv-new` y `.venv-new/bin/pip install -r backend/requirements-min.txt`.
2. Probar en el puerto 8001 con el PATH y HOME de la unidad: health, cold_key, verify del acuerdo `31e1cf09a5b2a74cd978` (debe dar `anchored_btc`, bloque 964449), `certificate/….pdf` y `proof/….zip`.
3. Congelar: `pip freeze` → `backend/requirements.txt`.
4. Intercambio: `systemctl stop x39-api`; `mv .venv .venv-old-FECHA`; `mv .venv-new .venv`; **corregir rutas**: `grep -lI '/opt/x39/api/.venv-new' .venv/bin/* .venv/pyvenv.cfg | xargs sed -i 's|/opt/x39/api/.venv-new|/opt/x39/api/.venv|g'` (los scripts del venv llevan la ruta absoluta del intérprete; sin esto el servicio no arranca); `systemctl start x39-api`.
5. Vuelta atrás: stop; `mv .venv .venv-new`; `mv .venv-old-FECHA .venv`; start.
6. Borrar `.venv-old-FECHA` una semana después.

## Web (frontend)

Antes de compilar, copiar los ficheros del release en frontend/public/app/ (x39-<versión>-release.apk + 7 ficheros + x39.apk). No están en git: la copia canónica es el release de GitHub.

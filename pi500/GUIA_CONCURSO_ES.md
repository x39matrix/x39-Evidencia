# X-39 Notaría — Guía histórica de preparación del flujo COLD con Raspberry Pi 500

Esta guía describe la preparación prevista antes de la ceremonia del 16/07/2026.
La secuencia se conserva como antecedente, no como procedimiento operativo vigente.
No ejecutar sus pasos de instalación, generación o registro sobre la instalación
actual ni sustituir la clave existente siguiendo este borrador. Los marcadores
`<AID>`, `$API` y `$ADMIN` de los ejemplos no son valores listos para ejecutar.

El registro de la ceremonia y de la retirada de WARM está en
[`RUNBOOK_CEREMONIA_COLD.md`](RUNBOOK_CEREMONIA_COLD.md); las condiciones de
rotación están en [`POLITICA_HUELLAS_COLD.md`](POLITICA_HUELLAS_COLD.md). Estos
enlaces son referencias documentales, no una nueva verificación del despliegue.

====================================================================
QUÉ ES ESTO Y POR QUÉ
====================================================================
Estado documentado del flujo de firmas:
  - WARM: retirada el 16/07/2026 (SEC-003). El sellado ya no genera esa firma
    automática; las firmas históricas conservan su clave pública para verificarse.
  - COLD: co-firma opcional ML-DSA-87, producida por el firmante separado. No todos
    los acuerdos sellados llevan una co-firma COLD. El servidor la verifica contra
    la huella pública fijada en el código.

Mantener la clave privada fuera del servidor reduce su exposición si ese servidor
es comprometido. No elimina las demás vulnerabilidades: siguen importando la
seguridad del firmante, los USB, los respaldos y la revisión del contenido firmado.
Una firma válida vincula el payload con una clave; no demuestra por sí sola el
aislamiento físico del equipo, la identidad de una persona ni la verdad del documento.

La custodia prevista mantiene la clave y sus respaldos cifrados fuera de equipos
con red. La clave privada no se sube al servidor ni se envía por chat. Al equipo
conectado solo se trasladan la clave pública y las firmas.

## Secuencia histórica (no ejecutar como procedimiento vigente)

====================================================================
QUÉ NECESITAS (checklist físico)
====================================================================
[ ] Raspberry Pi 500 + fuente USB-C (viene en el kit)
[ ] Monitor o TV con HDMI + cable micro-HDMI→HDMI (cable viene en el kit)
[ ] microSD 32GB con Raspberry Pi OS (viene en el kit)
[ ] 3 USB Kingston 64GB, verificados con H2testw, etiquetados:
      · SNEAKERNET   (único que toca máquinas con red)
      · COLD-KEY     (backup de la sk cifrada; nunca toca red)
      · PEM-VAULT    (2ª copia del PEM legacy; nunca toca red)

====================================================================
FASE 0 — PREPARAR EL PI (CON RED, UNA SOLA VEZ)
====================================================================
Enciende el Pi con el monitor conectado. Abre un terminal. Con red (WiFi/ethernet):

    sudo apt update && sudo apt install -y build-essential python3-pip
    pip install pqcrypto cryptography

Copia pi500_cold_signer.py al Pi con el USB SNEAKERNET.
Comprueba que importa SIN errores estando aún online:

    python3 pi500_cold_signer.py --help

Si sale la ayuda sin errores -> listo para desconectar.

CORTE DE RED (definitivo):
    - Quita el cable ethernet si lo hay.
    - Desactiva WiFi y Bluetooth (icono arriba a la derecha, o):
        sudo rfkill block wifi
        sudo rfkill block bluetooth
    A partir de aquí el Pi NO se reconecta nunca. NADA de SSH.

====================================================================
FASE 1 — GENERAR LA CLAVE COLD (EN EL PI, OFFLINE)
====================================================================
Antes del keygen, desactiva el swap (evita que la sk descifrada pueda
caer a disco; Raspberry Pi OS lo trae activado por defecto):

    sudo dphys-swapfile swapoff
    sudo systemctl disable dphys-swapfile

Después:

    python3 pi500_cold_signer.py keygen

    - Te pide una passphrase para cifrar la sk (recomendado). APÚNTALA en papel.
      Sin esa passphrase, la sk es inservible. No la guardes en digital.
    - Genera: mldsa87.sk (cifrada, permisos 600) y mldsa87.pk (pública).
    - Muestra un FINGERPRINT (sha256 de la pubkey). APÚNTALO en papel. Es tu ancla
      de identidad: sirve para detectar si un USB corrompe la clave.

Copia al USB COLD-KEY: mldsa87.sk (backup offline de la privada cifrada).
Copia al USB SNEAKERNET: mldsa87.pk (la pública, para registrarla online).

====================================================================
FASE 2 — REGISTRAR LA PUBKEY (ONLINE)
====================================================================
El borrador proponía registrar la clave a través del dominio público o delegar el
registro en un agente. Esas instrucciones se retiran: el Caddy del repositorio
restringe `/api/notaria/admin/*` a localhost y el backend solo admite la huella
`COLD_FP_PINNED`. Un POST administrativo no permite sustituir esa autoridad.

El registro corresponde al operador autorizado, sin compartir su token con un
agente. Para una clave nueva se requiere la ceremonia y el cambio versionado que
establece `POLITICA_HUELLAS_COLD.md`, no repetir este alta inicial.

Una huella distinta exige detenerse y comprobar el origen de la clave y del
fichero. No demuestra por sí sola corrupción del USB: puede ser otra clave o una
sustitución.

====================================================================
FASE 3 — CO-FIRMAR UN ACUERDO SELLADO (SNEAKERNET)
====================================================================
1. ONLINE: descarga el payload anclado del acuerdo sellado:
       curl -s "$API/api/notaria/proof/<AID>.json" -o proof-<AID>.json
   Llévalo al Pi con el USB SNEAKERNET.

2. PI (offline): firma
       python3 pi500_cold_signer.py sign \
         --sk mldsa87.sk --pk mldsa87.pk \
         --payload proof-<AID>.json --out sig.b64
   - El script muestra sha256(payload), agreement_id y proof_hash.
   - Compáralos con el certificado del acuerdo (en la web).
   - Solo si coinciden, teclea: FIRMAR
   - Re-verifica la firma offline y genera sig.b64.
   Lleva sig.b64 al online con el USB SNEAKERNET.

3. ONLINE: subida por el operador autorizado (ejemplo histórico; no compartir el token):
       SIG=$(cat sig.b64)
       curl -s -X POST "$API/api/notaria/agreements/<AID>/cold_signature" \
         -H "X-Admin-Token: $ADMIN" -H "Content-Type: application/json" \
         -d "{\"signature_b64\":\"$SIG\"}"
   200 -> co-firma verificada y guardada.  400 -> payload/clave mal, repite Fase 3.

====================================================================
FASE 4 — VERIFICAR (ONLINE)
====================================================================
    curl -s "$API/api/notaria/public/<AID>" | python3 -m json.tool | grep -A6 '"cold"'
También aparece en el certificado PDF y en el verificador independiente de la web.
El bundle de evidencia (.zip) incluirá la firma COLD en signatures.json.

====================================================================
PARÁMETROS DEL FLUJO DESCRITO (no certifican la instalación actual)
====================================================================
    Algoritmo:   ML-DSA-87 (FIPS-204) — Dilithium nivel 5, categoría de seguridad máxima
    Pubkey:      2592 bytes
    Firma:       4627 bytes
    Módulo:      pqcrypto.sign.ml_dsa_87 (mismo que verifica el servidor)
    Cifrado sk:  AES-256-GCM + scrypt (n=2^15) sobre la clave privada en el Pi

====================================================================
SI ALGO SALE MAL
====================================================================
- "passphrase incorrecta": la sk está cifrada; teclea la que apuntaste en Fase 1.
- 400 al subir la firma: el payload que firmaste no es el anclado. Vuelve a descargar
  proof-<AID>.json y repite Fase 3. No toques la clave.
- Perdiste la sk: comprobar primero la existencia de un respaldo cifrado válido
  y su passphrase. Si no es recuperable, una clave nueva requiere la ceremonia y
  los cambios versionados de POLITICA_HUELLAS_COLD.md. No basta con generarla y
  registrarla: el backend rechaza una huella distinta de COLD_FP_PINNED. Conservar
  las claves públicas históricas para poder verificar las firmas anteriores.
- NUNCA reconectes el Pi a la red "para ir más rápido". Eso anula todo el propósito.

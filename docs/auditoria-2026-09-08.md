# Acta de auditoría interna — 8 de septiembre de 2026
## Manifiesto de ficheros en el bundle de evidencia

Alcance: `verify_bundle.py` (referencia), `bundleVerify.js` (navegador) y el sellado en
`backend/notaria.py`. Todo el trabajo se hizo sobre copias desechables en /tmp; producción no se
tocó hasta que las pruebas estuvieron en verde. Commit: 8d030d39 (rama textos-honestos).

### Hallazgos
1. `README.md` dentro del bundle no estaba cubierto por hash ni firma: un README manipulado daba
   VALID. El verificador cumplía su especificación (el README no es evidencia), pero el README es lo
   primero que lee una persona y podía contradecir a `proof.json` sin que nada saltara.
2. `frontend/public/verify_bundle.py` (el que se descarga de x39matrix.org) iba 7 líneas por detrás
   del canónico de la raíz: le faltaba la comprobación estricta de hilos v3 (contadores de
   `msg_sigs` contra la cadena real; ningún mensaje sin firmar).
3. El bloque chino de `i18n.js` no tenía ninguna etiqueta de los checks del verificador (caía al
   castellano por el fallback de `t()`).
4. Método: en la `pqcrypto` instalada, `verify(pk, msg, sig)` devuelve `None` en el éxito; un
   `assert verify(...)` rechaza firmas buenas. `verify_bundle.py` ya lo normaliza; queda revisar
   `_mldsa_ok` en `backend/notaria.py` en la auditoría pendiente.

### Corrección
- Sellado: el README se genera una sola vez al sellar, con texto fijo (sin `proof_hash` incrustado,
  para evitar circularidad; la co-firma COLD descrita como "si existe", porque llega después).
  Su sha256 entra en `proof["files"]` antes de canonicalizar el payload: queda anclado en Bitcoin
  y cubierto por la co-firma COLD sin llave nueva ni ceremonia adicional. El README se guarda con
  el acuerdo y la descarga entrega el congelado. Acuerdos anteriores: README legacy, sin cubrir
  (un `proof.json` ya anclado no admite campos nuevos); el verificador lo avisa.
- `signatures.json` queda fuera del manifiesto a propósito: cambia al añadir la co-firma COLD y ya
  se verifica por criptografía (`proof_hash` recalculado, firmas contra huella pineada).
- `verify_bundle.py`: `verify_manifest` — cada fichero listado debe existir y coincidir byte a byte
  (FAIL[1] si falta o no cuadra). Resumen de cobertura: verificados / omitidos / NO cubiertos.
- `bundleVerify.js`: check `manifest`, no informativo (tumba el veredicto). Etiquetas en 5 idiomas.
- Un solo verificador: la raíz es el canónico y `frontend/public/` es copia exacta; el guion de
  despliegue la copia antes de compilar.

### Pruebas (laboratorio; clave ML-DSA-87 de pega pineada solo en la copia de /tmp)
- Bundle con manifiesto, README intacto → VALID; `README.md` entre los verificados.
- README con un bit cambiado → FAIL[1] `manifiesto: README.md sha256 mismatch`.
- README eliminado del ZIP → FAIL[1] `manifiesto: falta README.md`.
- Bundle anterior (sin manifiesto) → VALID con aviso "NO cubiertos: README.md" (sin cambios).
- El bundle de pega contra el verificador real → FAIL[2] huella no confiable: la clave de
  laboratorio no entró en producción.

### Despliegue y comprobación desde fuera
- Pi 5: afd7eada → 8d030d39; `x39-api` activo; `/api/health` ok; autoexamen `[COLD] OK`.
- Web: `https://x39matrix.org/verify_bundle.py` con sha256
  3ae9e7252df3424da3ead115017494b2c4e2047a2b6ad607aa17e31df5d468b8, igual a la raíz del repo.
  JS desplegado main.b1cf7950.js con el check `manifest`. check.sh: 22 PASS / 1 FAIL (Emergent).

### Límites
- La protección aplica a los acuerdos sellados a partir de este despliegue.
- El sellado real con `proof.files` se confirmará con el primer acuerdo nuevo en producción.
- El fuzzing por bytes aporta poco aquí (el CRC del ZIP rechaza cualquier byte cambiado antes de
  llegar a la lógica); el siguiente paso es un fuzzer estructural, en proceso y con cobertura.

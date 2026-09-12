# Politica del conjunto de huellas COLD (raiz de confianza soberana de X-39)
Version 1 - 2026-09-12. Este documento se sella con OpenTimestamps; cada version nueva se sella aparte. No se edita tras sellar.

## Que gobierna
El conjunto TRUSTED_COLD_FINGERPRINTS (verify_bundle.py) y la constante COLD_FP_PINNED (backend/notaria.py): las huellas sha256 de las claves publicas ML-DSA-87 cuya co-firma acredita autoridad soberana de X-39. Ampliar este conjunto amplia la autoridad; por eso existe esta politica.

## Estado vigente
Huella activa UNICA: 8453a25a41d6fe8fcb5647600f042a7c303daaca79b80928534025711981c6a1
- Origen: ceremonia del 2026-07-16 en la Raspberry Pi 500 aislada (sin red), keygen #2, documentada en RUNBOOK_CEREMONIA_COLD.md.
- La keygen #1 (3a026e152eee14284480e992879a736fc634045733ed32845d04851eae05c4b9) fue ROTADA el mismo dia por passphrase irrecuperable; nunca firmo nada en produccion.
- Registrada en el servidor el 2026-07-16T09:58:44Z con recalculo independiente del fingerprint (coincidencia bit a bit). Unica autoridad de firma del sistema desde esa fecha (SEC-003: la clave WARM de servidor fue retirada y eliminada).
- FE DE ERRATAS: el comentario de verify_bundle.py que dice "en servicio desde 2026-08" es impreciso; la fecha correcta es 2026-07-16. Este documento prevalece; la correccion del comentario viaja en el proximo commit ordinario.

## Reglas para anadir (o retirar) una huella
1. Solo mediante ceremonia documentada en un runbook propio (mismo formato que RUNBOOK_CEREMONIA_COLD.md), ejecutada en una maquina aislada que nunca haya tocado una red. La clave privada no sale de esa maquina; solo la publica y las firmas cruzan por USB.
2. Un alta requiere, en el MISMO cambio: (a) el runbook de la ceremonia; (b) la huella nueva anadida a TRUSTED_COLD_FINGERPRINTS y, si pasa a ser la de servicio, actualizada en COLD_FP_PINNED; (c) version nueva de este documento; (d) sello OTS del runbook y de la version nueva; (e) mencion en el README.
3. Las huellas anteriores NO se retiran al rotar: los sellos historicos siguen verificables. Una retirada solo procede por compromiso demostrado o sospecha fundada, y se documenta con causa y fecha en version nueva de este documento.
4. Autoridad para ejecutar esta politica: el operador soberano de X-39 (hoy, una unica persona fisica). Un cambio de operador exige ceremonia y documento propios.

## Canal independiente
Quien verifique un bundle debe contrastar la huella por al menos un canal DISTINTO del propio bundle: este documento sellado, el runbook sellado, el codigo versionado en git, o GET /api/notaria/cold_key del servicio en vivo. Si no se contrasta, no se ha verificado: se ha confiado.

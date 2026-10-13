# Perfil ZIP cerrado — ronda 9b

Fuente normativa leída: `verify_bundle.py`, SHA-256
`6f134372093b11265b1f68ac790c35af4368c46fc88134aad804801887ba52bf`.
Esta especificación deriva de `physical_member_name`, `core_name_skeleton`,
`safe_member_name`, `validate_zip_container`, `load_zip` y la decisión de `_main`.
Ante cambios de esa huella debe revisarse la especificación y su
[referencia JS](zip-profile-reference.mjs). La referencia es documentación
ejecutable para Node; no modifica ni integra `frontend/src/notaria/bundleVerify.js`.

## Bytes y campos (antes de JSON y firmas)

Todos los enteros ZIP son unsigned little-endian; offsets absolutos desde byte 0.
No buscar un ZIP interior ni corregir offsets como algunos lectores ZIP.
Todo incumplimiento estructural de esta sección produce INVALID[1].

- Longitud máxima 33554432 bytes; mínimo 22. Firma local `50 4b 03 04` en 0.
  EOCD `50 4b 05 06` exactamente en `E = longitud - 22`: nada antes ni después
  del archivo contabilizado, sin comentario final.
- EOCD: disco +4 u16, disco central +6 u16, miembros en disco +8 u16,
  miembros totales +10 u16, tamaño central +12 u32, offset central +16 u32,
  longitud comentario +20 u16. Discos y comentario cero; recuentos iguales;
  `1 <= count <= 256`; `cd_start < E`; `cd_start + cd_size == E`.
- Recorrer `count` registros centrales, cada uno con firma `50 4b 01 02`,
  46 bytes fijos: made +4 u16, needed +6 u16, flags +8 u16, método +10 u16,
  hora DOS +12 u16, fecha DOS +14 u16, CRC +16 u32, csize +20 u32,
  usize +24 u32, nlen +28 u16, xlen +30 u16, clen +32 u16,
  disco +34 u16, atributo interno +36 u16, externo +38 u32, offset local +42 u32.
  Siguen nlen bytes de nombre y xlen de extras. `clen == disco == 0`.
  El cursor final debe ser E. Made, atributo interno y fechas no reciben
  validación semántica; las fechas se comparan con el header local.
- Needed solo 10 o 20. Método 0 (STORED) u 8 (DEFLATE raw).
  `flags & ~0x080e == 0`: solo bits 1, 2, 3 y 11; cifrado prohibido.
  STORED exige bits 1 y 2 cero; DEFLATE exige needed 20.
  `((external >>> 16) & 0xf000)` solo 0, 0x8000 (regular), 0x4000
  (directorio); enlaces y otros tipos prohibidos. El bit DOS 0x10 también
  señala atributo de directorio. Nombre sin `/` final con cualquiera de esos
  atributos de directorio es INVALID. Un nombre con `/` final se considera
  directorio aunque sus atributos sean 0 o regular; exige usize cero.
- Ordenar por offset local; cursor inicial 0; cada offset debe coincidir con
  cursor. Firma local, 30 bytes fijos: needed +4 u16, flags +6 u16,
  método +8 u16, hora +10 u16, fecha +12 u16, CRC +14 u32,
  csize +18 u32, usize +22 u32, nlen +26 u16, xlen +28 u16.
  Nombre y extras deben terminar en o antes de cd_start (`<=`). Nombre idéntico byte a
  byte al central; needed/flags/método/hora/fecha idénticos. Los extras
  locales y centrales se validan por separado; no tienen que ser iguales.
- Datos en `local + 30 + nlen + xlen`, longitud csize CENTRAL. Su final
  no puede superar el siguiente offset local (o cd_start para el último).
  Sin bit 3: CRC/csize/usize locales iguales a centrales y datos terminan
  exactamente en el siguiente offset. Con bit 3: cada campo local es cero
  o su correspondiente valor central; después del payload hay exactamente
  12 bytes (CRC/csize/usize u32) o 16 (`50 4b 07 08` + esos 12 bytes),
  valores iguales al central. No se admite otra firma, longitud ni hueco.
  Último cursor igual a cd_start. Esto excluye prefijos, sufijos, concatenación,
  solapamientos, huecos y headers no contabilizados; no interpreta firmas
  que aparezcan dentro del payload.

## Extras: lista blanca y clasificación exacta

Cada área extra es una secuencia de TLV: tag u16, longitud u16, cuerpo de
esa longitud. Header de menos de 4 bytes o cuerpo fuera del área es
INVALID[1], no 4. Un cuerpo de tag admitido malformado o repetido, con TLV
bien delimitado, acumula «contenedor no soportado» (4). Los tags vistos se
reinician para cada área local/central; solo un tag admitido con cuerpo válido
se añade al conjunto. Ninguna fecha, UID/GID ni reservado NTFS se autentica.

| Tag | Validación exacta del cuerpo |
| --- | --- |
| UT 0x5455 | Longitud L >= 1; flags cuerpo[0] solo bits 0..2 (`flags & ~7 == 0`); `(L-1) % 4 == 0`; `(L-1)/4 <= popcount(flags)`. Por tanto admite menos tiempos que bits activos, incluso L=1; no exige igualdad. Tiempos de 4 bytes sin validación de valores. |
| ux 0x7875 | Cuerpo vacío válido. Si no vacío: L >= 3, byte 0 = versión 1; byte 1 = longitud UID entre 1 y 8; `g = 2 + cuerpo[1]`, `g < L`; cuerpo[g] = longitud GID entre 1 y 8; `L == g + 1 + cuerpo[g]`. Bytes UID/GID sin validación numérica adicional. |
| NTFS 0x000a | L exactamente 32; u16 en +4 = 1 y u16 en +6 = 24. Bytes +0..3 reservados sin exigir cero; +8..31 son tres tiempos de 8 bytes sin validación de valores. No hay otros atributos. |

Unicode Path 0x7075 solo se admite una vez por área: cuerpo de al menos 5
bytes, versión 1, CRC-32 del nombre central en +1 y nombre desde +5
byte-idéntico al central. Toda diferencia, versión/CRC incorrectos o repetición
acumula 4. ZIP64 0x0001 y todos los demás tags acumulan 4, incluso repetidos. No usar Unicode Path para reinterpretar nombres ni ZIP64
para sustituir offsets/tamaños. El formato ZIP64 real queda además excluido
por las restricciones estructurales ZIP32. Las razones se deduplican y ordenan; se separan con punto y coma.
Si una carpeta envolvente tiene nombre de núcleo y además colisiona con un
miembro, se conserva solo el motivo específico de nombre de núcleo.
Con `unsupported_out` se continúa el diagnóstico del contenido para detectar
INVALID; sin ese acumulador `validate_zip_container` termina con 4 después
de resolver los nombres. Un 4 NO implica genuinidad.

## Nombres físicos, Unicode y nombres resueltos

Decodificar nombre central como UTF-8 estricto con bit 11, CP437 sin él.
No exigir ASCII ni NFC original. El nombre local se compara como bytes.
Para cada ruta física, quitar exactamente una `/` final si es directorio;
rechazar vacío, `/` inicial, `\\`, `:`, puntos de código <32 o 127 y componentes
vacíos, `.` o `..`. La clave es `NFC(nombre).casefold()` de Python.
Claves repetidas son INVALID, incluso fichero/directorio con la misma clave.
NFC/NFD equivalentes y diferencias de mayúsculas colisionan. No sustituir
casefold por toLowerCase en JS; usar tablas Unicode equivalentes a Python.
La referencia incluye tablas casefold/combining de Unicode 16.0.0 del Python
local; NFC/NFKD deben usar esa misma versión para garantizar paridad en
puntos de código añadidos después. El motor JS puede tener una versión
más reciente: esta dependencia debe resolverse al portar a navegador.

Los directorios explícitos validan los componentes restantes tras quitar
la carpeta envolvente, antes de ignorarlos.

Después de resolver envoltorio/macOS, para cada miembro no ignorado aplicar
`safe_member_name` a su nombre RESUELTO: mismas reglas de ruta y clave NFC +
casefold, sin exigir que la escritura original sea NFC. Para cada componente:

- Rechazar punto o espacio ASCII final.
- Rechazar alias 8.3 que coincida COMPLETAMENTE con
  `[^.~]{1,6}~[0-9]+(?:\.[^.]{1,3})?` (modo ASCII).
- Tomar texto antes del primer punto, quitar puntos/espacios ASCII finales,
  convertir a mayúsculas y rechazar CON, PRN, AUX, NUL, CONIN$, CONOUT$,
  CLOCK$, COM0..COM9 y LPT0..LPT9.

Reservados exactos: `proof.json`, `proof.json.ots`, `signatures.json`,
`README.md`, `chat_chain.json`. Para detectar alias, el esqueleto traduce
U+041C→M, 043C→m, 043E→o, 041E→O, 0440→p, 0420→P, 0435→e,
0415→E, 0430→a, 0410→A, 0441→c, 0421→C, 0456→i, 0406→I,
039C→M, 039F→O, 03BF→o, 03A1→P, 03C1→p, 0395→E, 0391→A,
0399→I, 03B9→i; después NFKD, eliminar caracteres con clase combinante
Unicode no cero y casefold. Si el esqueleto de un nombre completo coincide
con un reservado en minúsculas, exigir escritura exacta del reservado.
No es una prohibición general de todos los homóglifos Unicode.
`safe_member_name` con `allow_nested=False` también rechaza cualquier
componente reservado (comparación lower) en rutas de más de un componente;
se usa así para el manifiesto. La resolución de entradas usa `allow_nested=True`.

## AppleDouble, directorios y envoltorio (en este orden)

1. Construir `present` con todos los nombres físicos que NO empiezan por
   `__MACOSX/` exacto, sin barras finales, y todos sus prefijos de componentes.
   La búsqueda de sombreado es exacta, sin NFC/casefold, y también puede
   encontrar un directorio explícito o implícito.
2. Marcar macosx solo si empieza por `__MACOSX/` (sensible a mayúsculas).
   Para un fichero allí, separar padre y basename tras ese prefijo. Es
   AppleDouble tolerado solo si basename empieza `._`, tiene más de 2
   caracteres, y `padre + '/' + basename[2:]` (sin '/' si padre vacío)
   está en `present`, y los primeros 4 bytes descomprimidos son
   `00 05 16 07`. Para DEFLATE se consume el flujo ENTERO hasta EOF sin error,
   conservando solo cuatro bytes en JS. Un error DEFLATE implica INVALID[1],
   incluso después del magic y dentro de los primeros 64 bytes: antes Python
   podía reconocer los cuatro bytes mientras el bloque JS de 64 fallaba,
   cambiando la decisión. No se detiene el flujo al reconocer la cabecera.
   La API `validateZipContainer` devuelve una Promise y requiere `await`.
   No valida el resto de la estructura AppleDouble. La lectura completa,
   tamaño y CRC se comprueban posteriormente incluso para miembros ignorados.
3. Calcular envoltorio usando SOLO ficheros que no sean directorio ni macosx.
   Hay envoltorio si hay alguno, todos contienen `/` y comparten exactamente
   el primer componente. Quitar UNA carpeta de esas entradas. Su nombre
   se resuelve UNA vez desde ese prefijo, haya o no entrada explícita de
   directorio. Las reglas Windows se aplican al nombre resuelto: final en
   punto/espacio o dispositivo reservado acumula 4 con motivo, nunca aprobación.
   `evidencia `, `evidencia.`, `CON` y `aux` dan 4 con y sin directorio;
   `CON1` sigue admitido. Si el nombre envolvente resuelto colisiona (NFC/casefold)
   con un miembro resuelto, acumula 4; la carpeta nunca causa INVALID por sí
   sola. También acumulan 4 los nombres del núcleo y sus homóglifos. INVALID
   se reserva a colisiones entre dos miembros ya resueltos.
   Directorios bajo ese prefijo validan los componentes restantes, también
   el reflejo `__MACOSX/<envolvente>/` sin volver a validar el envolvente.
   Los directorios vacíos y AppleDouble se ignoran como metadatos;
   se enumeran con nombre y tamaño, junto con recuentos AppleDouble/directorios
   y suma de bytes descomprimidos. No son evidencia; «NO cubiertos: ninguno»
   solo aparece si no hay ignorados, nombres/contenedor rechazados ni otros miembros sin cobertura.
4. Cualquier otro fichero macosx conserva TODA su ruta, nunca se quita
   envoltorio. Si el esqueleto de su basename, o del basename quitando `._`
   cuando corresponda, es reservado: INVALID[1]. Así `__MACOSX/proof.json`
   y un `._proof.json` sin cabecera o sombreado válido no desaparecen.
   Los otros pasan `safe_member_name(..., allow_nested=True)` y entran en
   el mundo cerrado: sin declaración son NO cubiertos (5).
5. Para los otros ficheros, si el esqueleto del basename resuelto es
   reservado, validar ese basename y exigir nombre exacto. Registrar su
   padre resuelto (cadena vacía en raíz). Si todavía tiene padre, acumular
   4 por más de una carpeta envolvente/ruta de miembro núcleo y usar el
   basename como nombre lógico para diagnóstico. Esto también se aplica
   a README.md y chat_chain.json. Dos claves lógicas iguales son INVALID;
   más de un padre distinto de candidatos reservados es INVALID.
   Una doble carpeta con núcleo inequívoco permite diagnóstico para revelar
   INVALID, pero nunca 0/5. No es una prohibición de toda ruta auxiliar
   profunda: las rutas auxiliares pueden conservar subdirectorios.
6. Aplicar reglas de nombres resueltos y detectar colisiones de sus claves,
   incluyendo miembros macosx no ignorados. Por ejemplo `a/proof.json` y
   `b/proof.json` son dos candidatos y producen INVALID, nunca se elige uno.

## Descompresión, mundo cerrado y veredicto

Por cada entrada, incluso directorios y AppleDouble, leer exactamente csize.
DEFLATE raw (-15) con límite de salida `usize + 1`; exigir EOF, sin
`unused_data` ni `unconsumed_tail`. STORED usa esos bytes directamente.
Longitud descomprimida exactamente usize, CRC-32 ZIP exactamente central.
EOF/cola/tamaño incorrectos producen INVALID[1]. En `load_zip` con lista
anomalies, error CRC o zlib en núcleo es INVALID[1]; en auxiliar se registra
aviso y no se incorpora su contenido. Si el auxiliar era obligatorio por
cadena o manifiesto, las etapas siguientes rechazan su ausencia. Errores
OSError/RuntimeError/NotImplementedError en núcleo son 4; en auxiliar,
aviso bajo esa misma llamada. Sin lista anomalies, esos fallos se rechazan.

Límites declarados antes de descomprimir, contando TODAS las entradas:
256 miembros; 16777216 bytes usize por miembro; suma usize <= 33554432;
`usize <= 100 * max(1, csize)`; archivo completo <= 33554432 bytes.
Se limita además la salida DEFLATE a usize+1 para detectar tamaños falsos.

El contenedor no autentica el contenido. El mundo cerrado exige el núcleo
proof.json, signatures.json y proof.json.ots: su ausencia da 4.
La cadena chat_chain.json es obligatoria en v2/v3: su ausencia da INVALID[1];
v1 con chat_chain.json es INVALID[1]. `proof.files` declara nombres y SHA-256:
validar nombres, colisiones y bytes exactos, sin inventar cobertura de extras.
README heredado solo reconocido por catálogo SHA-256 exacto es declarado por
referencia local y puede permitir 0; no fuerza 5. README.md no declarado y fuera del catálogo heredado da INVALID[1].
Los otros auxiliares no declarados producen avisos 5, si el núcleo supera
todas las comprobaciones.

Precedencia de decisión: INVALID (1 integridad, 2 firma, 3 OTS/incompleto)
> 4 uso/contenedor/E-S > 5 VALID CON AVISOS > 0 VALID limpio. Los fallos
INVALID interrumpen, no se capturan para degradarlos a 4. Las restricciones
no soportadas y errores de uso recuperables se acumulan mientras se busca
manipulación. Falta proof.json: 4 inmediato, sin núcleo para diagnosticar.
0/5 requieren COLD reconocida, documento --content, cadena obligatoria y
OTS Bitcoin confirmado. En el orden exacto de `_main`, --skip-ots comprueba
el perfil/hash OTS local; si hay errores de uso/contenedor acumulados termina
4 antes del cierre; de otro modo termina incompleto 3, nunca VALID.
Un éxito de esta referencia JS solo describe el contenedor, nunca evidencia.

Salida: valores citados máximo 1024 bytes UTF-8 con marcador de truncado;
identidad/cobertura esencial se representa sin truncar, máximo 4096 bytes
por valor. `emit` cuenta UTF-8 incluyendo salto de línea: detalles tienen
cupo 32768-8192=24576, líneas esenciales no finales 32768-2048=30720,
finales 32768. El aviso único de salida limitada puede usar la reserva.
Tope absoluto total 32768 bytes. Exceso esencial impide aprobación y da 4;
fallo de escritura conserva INVALID ya decidido y convierte 0/5 en E/S 4.
La cola marca las líneas de aprobación; tras un fallo previo las omite.
La línea «VALID 0 acredita» comparte la bandera de aprobación: solo se
emite con código 0/5 y se retira con 4 por la bandera, nunca buscando texto.
Los veredictos 0, 5, 4, 1, 2 y 3 se emiten por stdout. Los errores conservan
también su mensaje histórico en stderr. En los códigos 0 y 5 stderr queda
intencionadamente vacío: la aprobación completa pertenece únicamente a stdout;
duplicarla en stderr permitiría confundir una salida parcial de stdout con
una aprobación independiente. No se escribe en stderr para comprobar su estado.
La salida y --help explican la necesidad del cierre sin reproducir su cadena
literal. La marca literal aparece exactamente una vez en toda salida completa,
como última línea de stdout. Los valores elegidos por el autor del ZIP
(incluidos nombres y título) escapan también los corchetes: `VALID \[0\]`
es legible y no coincide con un veredicto ni con un grep sin anclar. Los veredictos completos terminan en `VALID [0]\n[FIN VEREDICTO]` o
`VALID CON AVISOS [5]\n[FIN VEREDICTO]`, sin salto tras el cierre.
Perder solo el `\n` que antes cerraba `VALID [0]` dejaba una aprobación
aparente con exit 4. Ahora un corte en ese límite pierde el cierre explícito;
una línea VALID sin cierre no constituye veredicto completo. Se detectan
escrituras cortas y se hace flush; manda el código de salida.

```sh
node docs/zip-profile-reference.mjs /tmp/prueba.zip
```

La referencia devuelve entradas físicas/resueltas y razones no soportadas;
el CLI sale 4 para estas razones y 1 para estructura/nombres inválidos.
No sustituye `load_zip`, mundo cerrado, firmas ni OTS. Para portar a navegador
se debe aplicar este perfil sobre los bytes originales antes del lector ZIP y
conservar la precedencia al ejecutar todas las etapas obligatorias.

## Límites de la evidencia de compatibilidad

Windows («Enviar a carpeta comprimida», tar.exe/libarchive) y AppleDouble
reales de macOS solo se han probado por emulación, no en esos sistemas.
No se valida la estructura interna AppleDouble (ATTR/resource fork incluidos).
Los bytes libres admitidos en UT/ux/NTFS (12, 16 y 28 en los casos de ataque)
no cambian nombre ni contenido. El mojibake de Info-ZIP sin bandera UTF-8
depende del creador del ZIP: el perfil interpreta esos bytes como CP437.

## Validación de ronda 9b (offline)

- Regresiones nuevas: 12/12, incluyendo cortes de salida para 0/5, ignorados,
  nombres de directorio, Unicode Path y 16 MB de bloques DEFLATE vacíos.
  Este último caso tardó aproximadamente 29 ms en Node en esta máquina.
- Arnés externo `~/x39-redteam/`, según LEEME.txt: lote t8 48/48 según
  códigos de las etiquetas; 645 casos históricos ejecutados, sin controles
  en salida. Las etiquetas antiguas no constituyen expectativas actualizadas
  para todas las rondas posteriores.
- Barrido io_sweep.sh: 720/720. os_io.py: 44/48; los cuatro desacuerdos
  ya ocurren con el SHA inicial: stderr en /dev/full o tubería cerrada sin
  ninguna escritura en stderr no genera error. El arnés espera 4 igualmente.
- Suite Python amplia: 196 aprobadas, 28 fallidas. Los 28 identificadores
  fallidos también fallan con el canónico inicial SHA 595a1cf6 (reconstruido
  y comprobado por SHA-256); incluyen expectativas antiguas de WARM, textos
  escapados y clasificación de uso, además de simulaciones incompatibles
  con las comprobaciones actuales. No se presenta esta suite como verde.

En la ronda 9b, sin deploy, publicación, merge ni Mainnet. `frontend/` y
`/home/x39matrix/home_viejo/x39web/dist` permanecen intactos respecto al
inicio de esta ronda. No se añadieron archivos sin seguimiento respecto
al estado inicial; los preexistentes se conservaron.


## Correcciones H1–H4 (validación estricta)

Aviso y ayuda sin la marca literal; corchetes escapados en valores externos;
stderr vacío en 0/5; motivo único para envoltorios PROOF.JSON/proof.json.
Las tres copias del verificador (canónico, public y build) son idénticas.
Pruebas offline: `pytest -q tests/test_verificador_cierre_estricto.py tests/test_verificador_f1_f5.py`:
207 aprobadas, incluidas 47 nuevas (códigos 0–5, ayuda, valores hostiles,
motivos de carpeta, 32 cortes de bytes y comparación de las tres copias).
Los cortes se sitúan en el salto anterior y en cada byte incompleto del cierre;
no fijan offsets absolutos que cambian con la longitud de las rutas impresas.
OTS se simula; no se contacta con red ni Mainnet. Sin commit, merge,
publicación ni despliegue.

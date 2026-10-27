#!/usr/bin/env python3
"""
verify_bundle.py - verificador de referencia offline de X-39 Notaria.

Verifica un bundle de evidencia (x39-evidencia-<aid>.zip) SIN confiar en X-39:
  1. Integridad     : sha256(proof.json) == signatures.proof_hash
  2. Campos cruzados: agreement_id / content_hash / sealed_at coinciden
  3. Cadena de chat : (X39-NOTARIA-2/3) continuidad + msg_hash + tip == chat_merkle_root
  4. Firmas mensaje : (X39-NOTARIA-3) Ed25519 por mensaje, pubkeys ancladas en proof.json
  5. Firma soberana : ML-DSA-87 (FIPS-204) COLD sobre los bytes de proof.json, con la
                      clave PINEADA en TRUSTED_COLD_FINGERPRINTS (ver abajo)
                      (WARM heredada: clave en linea retirada el 2026-07-16;
                       no aporta atestacion independiente)
  6. Ancla Bitcoin  : ots verify proof.json.ots -f proof.json
                      (--bitcoin-node URL: contrasta contra TU nodo, cero terceros)

El mensaje firmado por ML-DSA-87 son los BYTES CRUDOS de proof.json (no proof_hash).
proof.json NO contiene el campo proof_hash: vive en signatures.json y es sha256(proof.json).

VALID acredita el nucleo COLD + documento + cadena + ancla Bitcoin, no que cada
byte del ZIP sea nuestro. Reempaquetado ZIP del perfil estricto y whitespace de JSON externos son
legitimos. Se tolera una carpeta envolvente comun y directorios vacios (con barra
final). En __MACOSX/ solo se ignoran ficheros ._<nombre> AppleDouble (00 05 16 07)
de un miembro existente; cualquier otro contenido es miembro no cubierto (5), o
INVALID si lleva nombre reservado. Extras de marca de tiempo UT, ux y NTFS se
admiten; Unicode Path solo redundante (version 1, CRC y bytes del nombre identicos); ZIP64 y otros extras no. No se cambia el perfil de bytes ni se aceptan candidatos ambiguos. Una segunda
carpeta solo permite comprobar para detectar INVALID; nunca aprobar (4).
proof.json si se autentica byte a byte. WARM ausente/null y
message_signatures ausente/null en v1 son normales. verified_at es opcional y
externo: una fecha plausible sin referencia historica local produce aviso 5.
WARM presente debe verificar con el perfil historico exacto: algorithm, tier,
public_key_b64 y signature_b64 obligatorios; fingerprint opcional pero debe
coincidir si aparece, note opcional pero de literal cerrado. COLD tiene los
mismos campos criptograficos obligatorios, fingerprint y verified_at opcionales.
En signatures.json son obligatorios proof_hash, agreement_id, content_hash y
sealed_at; title puede omitirse. message_signatures es obligatorio en v3 cuando
proof.msg_sigs lo declara; v1 permite ausente/null. README nuevo sigue proof.files.
Los textos propios son ASCII. Los valores citados permiten solo ASCII y una
lista explicita de puntos de codigo latinos; controles, barras inversas y otros
Unicode se escapan sin NFKC. El marcador de truncado queda fuera del valor.
Detalles limitados a 1024 bytes por valor, salida total a 32768 bytes. Identidad
y cobertura se imprimen antes de avisos, completas; si exceden recursos no se
emite aprobacion (4). La reserva final preserva el veredicto.
La precedencia es INVALID > uso/contenedor/E-S (4) > CONSISTENTE sin COLD (6) > avisos (5) > limpio (0).
Contenedores con otros extras o mas de una carpeta envolvente, estructuralmente seguros, se comprueban solo
para escalar a INVALID, nunca para obtener 0/5. Un 4 no implica genuinidad. README
heredado con referencia SHA-256 exacta es miembro declarado y permite 0.
Extras fuera de la lista blanca, o malformados: contenedor no soportado (4), salvo
manipulacion detectada en contenido, que prevalece como INVALID. Un fallo de
escritura conserva un INVALID ya determinado; para una aprobacion implica E/S 4,
sin inventar un fallo de integridad.
Las referencias locales de verified_at no son fechas firmadas ni anclas de tiempo;
Bitcoin aporta una cota superior: proof.json existia antes del bloque confirmado,
no una fecha exacta ni la fecha de la co-firma COLD.
VALID exige COLD reconocida, --content y OTS verificado. Sin bloque COLD (ausente o
null), con las comprobaciones obligatorias correctas y OTS verificado: CONSISTENTE (6).
No es VALID: falta la atestacion COLD en este paquete; puede haber anomalias externas.
La co-firma se aplica despues del sellado. Una COLD presente
pero vacia, falsa o no reconocida sigue siendo INVALID[2]. --skip-ots solo permite
diagnostico offline: nunca emite VALID ni CONSISTENTE ni devuelve cero.
Exit codes: 0 VALID limpio  -  1 integridad  -  2 firma  -  3 OTS/Bitcoin incompleto
             -  4 uso/IO  -  5 VALID CON AVISOS (anomalias fuera de la aprobacion COLD)
             -  6 CONSISTENTE sin co-firma COLD (no es aprobacion)
Ayuda: -h/--help devuelve 4, nunca VALID. Rutas que empiezan por guion:
verify_bundle.py --content documento -- -h
El veredicto se determina antes de escribir; un fallo de salida conserva INVALID,
y convierte una aprobacion sin salida completa en E/S 4.
Dependencias opcionales: pip install pqcrypto opentimestamps-client
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import io
import os
import json
import math
import re
import stat
import struct
import subprocess
import sys
import tempfile
import zipfile
import unicodedata
import zlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ML_DSA_87_PK_LEN = 2592
ML_DSA_87_SIG_LEN = 4627
EXIT_OK, EXIT_INTEGRITY, EXIT_SIG, EXIT_OTS, EXIT_IO = 0, 1, 2, 3, 4
EXIT_WARNINGS = 5
EXIT_CONSISTENT = 6  # sin co-firma COLD; no es aprobacion
MAX_ZIP_BYTES = 32 * 1024 * 1024
MAX_MEMBER_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
MAX_COMPRESSION_RATIO = 100
MAX_MEMBERS = 256
CORE_MEMBERS = {"proof.json", "proof.json.ots", "signatures.json"}
RESERVED_MEMBERS = CORE_MEMBERS | {"README.md", "chat_chain.json"}
# Metadatos de macOS: solo "__MACOSX/<ruta>/._<nombre>" AppleDouble de un miembro existente.
MACOSX_PREFIX = "__MACOSX/"
APPLEDOUBLE_MAGIC = b"\x00\x05\x16\x07"
TRUSTED_WARM_FINGERPRINTS = {
    # Clave publica WARM del bundle historico testdata/bundle_v1_prod.zip.
    "75996cd1ed2e016009f44ea1081c2de6a427e8283a7c25fda849d9ff506178f1",
}
LEGACY_METADATA = {
    # Referencias publicas fijas; nunca se obtienen del bundle presentado.
    "9cb107d9260460f260aead0514bdcdc94bcb372fd02742fbe5d59ad25ad59fd9": {
        "README.md": "a18f6a32dc7b4de5391bb798ecac88a06fbf6cc5e9b0e2341d8dc2740b2ae819",
        "proof.json.ots": "943e7ccd0885e375f214bbf18d458cda4cbc0c5dd4654b089647515a2ea5e96f",
    },
    "7e897e5b6a8dcdd2ef2a8411365e02e88c9f58407fd84e14f6fdefa5c2a32cf6": {
        "README.md": "d850d03098fcc63a5b984cbb5409d2fdf1c01d02b86079002382a35da3f4dbf2",
        "proof.json.ots": "4b396c8bc6c4b023c6adfaf9e8af613c6331684fa96cc7a0017c3e7ef8ead8f3",
    },
    # 76901ac6458bb0613e16 (28/08/2026) — bundle anterior al README congelado
    "73e46b57769444e5aba7177482303091d8dfecaa6304196ac39f69ca2383027a": {
        "README.md": "9dafe51ca9aa87b4a51ea420a7e5cafd812a660d72b2dbfd61662d18f4c57caa",
    },
    # 6ede1b77d889acd9b02a (28/08/2026) — bundle anterior al README congelado
    "99709c4d2f90a2c7029c112b3458250280a85b2e1f53e7493e3ca6daf0fd708d": {
        "README.md": "233616ce01a9732e224daf806ef1be320373dd453d57c38f27afdc5dd9ac685b",
    },
}
LEGACY_WARM_NOTE = (
    "clave de operador retirada 2026-07-16 (SEC-003); firma historica verificable / "
    "operator key retired; historical signature remains verifiable"
)
ISO_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]"
    r"(?:\.[0-9]{1,6})?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])\Z"
)
# Fecha de ceremonia de la unica clave COLD actualmente pineada. No afirma hora.
COLD_CEREMONY_NOT_BEFORE = datetime(2026, 7, 16, tzinfo=timezone.utc)

# ---------------------------------------------------------------------------
# RAIZ DE CONFIANZA DE LA CO-FIRMA SOBERANA
#
# Huellas sha256 de las claves publicas ML-DSA-87 generadas en la Raspberry Pi
# 500 aislada (sin red). Una co-firma "cold" SOLO acredita autoridad soberana de
# X-39 si la clave publica que la verifica reduce a una de estas huellas.
#
# Por que esta pineado y no se lee del bundle: signatures.json NO esta cubierto
# por el ancla OpenTimestamps. Comprobar la huella contra la clave que viene en
# el mismo fichero es circular — cualquiera puede generar su par de claves,
# firmar un proof.json falso, incluir su clave y su huella, anclarlo el mismo, y
# obtener un "VALID" con co-firma aparentemente soberana.
#
# Es un CONJUNTO a proposito: permite rotar la clave COLD anadiendo la nueva sin
# invalidar los sellos ya emitidos con la anterior.
#
# Verifica esta huella por un canal independiente de este fichero antes de
# confiar en el. Si no la has contrastado, no has verificado nada: te has fiado.
# ---------------------------------------------------------------------------
TRUSTED_COLD_FINGERPRINTS = {
    # Pi 500 aislada — clave COLD (ceremonia 2026-07-16, keygen #2 tras rotacion honesta; unica autoridad desde esa fecha)
    "8453a25a41d6fe8fcb5647600f042a7c303daaca79b80928534025711981c6a1",
}


class RenderedValueError(ValueError):
    """Diagnostico propio: sus valores ya estan citados una sola vez."""


class SigError(Exception):
    """Fallo en una co-firma. El llamante decide si es fatal (COLD) o informativo (WARM)."""


class SignatureEnvironmentError(SigError):
    """La biblioteca no permite una comprobacion criptografica fiable."""


# Referencias locales de bundles publicos existentes, indexadas por el hash
# del proof firmado. Reconocer esta fecha NO la convierte en fecha firmada.
HISTORICAL_COLD_VERIFIED_AT = {
    "9cb107d9260460f260aead0514bdcdc94bcb372fd02742fbe5d59ad25ad59fd9":
        "2026-07-16T13:11:52.367686+00:00",
    "7e897e5b6a8dcdd2ef2a8411365e02e88c9f58407fd84e14f6fdefa5c2a32cf6":
        "2026-08-30T10:25:02.296158+00:00",
}
MAX_TERMINAL_VALUE = 1024
MAX_TOTAL_OUTPUT = 32768
OUTPUT_RESERVE = 8192  # diagnostico final y veredicto no se suprimen
_output_bytes = 0
_output_limited = False
_capture_output = False
_output_queue = []
_output_resource_error = False


class OutputIOError(Exception):
    """Fallo de salida, independiente de la integridad de la evidencia."""


# Lista cerrada de puntos de codigo, no categorias Unicode.
DISPLAY_CODEPOINTS = frozenset([
    0xe1, 0xe9, 0xed, 0xf3, 0xfa, 0xfc, 0xf1, 0xe7,
    0xe0, 0xe8, 0xec, 0xf2, 0xf9, 0xe2, 0xea, 0xee, 0xf4, 0xfb,
    0xe4, 0xf6, 0xc1, 0xc9, 0xcd, 0xd3, 0xda, 0xdc, 0xd1, 0xc7,
    0xc0, 0xc8, 0xcc, 0xd2, 0xd9, 0xc2, 0xca, 0xce, 0xd4, 0xdb,
    0xc4, 0xd6,
])


def terminal_text(value: Any, *, truncate: bool = True) -> str:
    """Valor citado e inyectivo; el marcador queda fuera de las comillas."""
    if isinstance(value, (SigError, RenderedValueError, VerifierUsageError)):
        return str(value)  # Mensajes propios ya compuestos con valores seguros.
    chunks = []
    size = 2
    truncated = False
    for c in str(value):
        if c in ("\\", "'", "[", "]"):
            escaped = "\\" + c
        elif 32 <= ord(c) <= 126 or ord(c) in DISPLAY_CODEPOINTS:
            escaped = c
        elif ord(c) <= 0xffff:
            escaped = "\\u%04x" % ord(c)
        else:
            escaped = "\\U%08x" % ord(c)
        if truncate and size + len(escaped.encode("utf-8")) > MAX_TERMINAL_VALUE - len(" [TRUNCADO]"):
            truncated = True
            break
        chunks.append(escaped)
        size += len(escaped.encode("utf-8"))
    return "'" + "".join(chunks) + "'" + (" [TRUNCADO]" if truncated else "")


class VerifierUsageError(Exception):
    pass


# Precedencia: INVALID (1/2/3) > uso/contenedor/E-S (4) > CONSISTENTE (6) > avisos (5) > limpio (0).
# El 6 no entra en candidates: se decide al final de main(), cuando ya no hay INVALID ni 4.
VERDICT_PRECEDENCE = {EXIT_INTEGRITY: 3, EXIT_SIG: 3, EXIT_OTS: 3,
                      EXIT_IO: 2, EXIT_CONSISTENT: 1, EXIT_WARNINGS: 1, EXIT_OK: 0}


def essential_text(value: Any) -> str:
    result = terminal_text(value, truncate=False)
    if len(result.encode("utf-8")) > 4096:
        if _capture_output:
            global _output_resource_error
            _output_resource_error = True
            return "'[identidad/cobertura excede el limite de recursos]'"
        raise VerifierUsageError("identidad/cobertura excede el limite de salida esencial; no hay veredicto")
    return result


_DEFAULT_STDOUT = object()


def emit(message: str, *, file: Any = _DEFAULT_STDOUT, essential: bool = False, final: bool = False,
         approval: bool = False, closure: bool = False) -> None:
    """approval marca la linea de veredicto 0/5/6: se retira por bandera, nunca por su texto."""
    global _output_bytes, _output_limited, _output_resource_error
    stream = sys.stdout if file is _DEFAULT_STDOUT else file
    safe = message + "\n"
    if closure:
        safe += "[FIN VEREDICTO]"
    limit = (MAX_TOTAL_OUTPUT if final else MAX_TOTAL_OUTPUT - 2048
             if essential else MAX_TOTAL_OUTPUT - OUTPUT_RESERVE)
    if _output_bytes + len(safe.encode("utf-8")) > limit:
        if essential:
            if _capture_output:
                _output_resource_error = True
                return
            raise VerifierUsageError("salida esencial excede el cupo; no hay veredicto")
        elif not _output_limited:
            safe = "SALIDA LIMITADA: se omiten detalles; las comprobaciones y el codigo final se mantienen\n"
            _output_limited = True
        else:
            return
    if _output_bytes + len(safe.encode("utf-8")) > MAX_TOTAL_OUTPUT:
        raise OutputIOError
    if _capture_output:
        _output_queue.append((stream, safe, approval, closure))
        _output_bytes += len(safe.encode("utf-8"))
        return
    if stream is None:
        raise OutputIOError
    try:
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="backslashreplace")
        written = stream.write(safe)
        if written != len(safe):
            raise OutputIOError
        stream.flush()  # detectar E/S aqui, no al terminar con exit 120
    except (OSError, UnicodeError, ValueError, AttributeError) as e:
        # Evitar un segundo fallo de flush durante el cierre de Python.
        try:
            fd = stream.fileno()
            null_fd = os.open(os.devnull, os.O_WRONLY)
            try:
                os.dup2(null_fd, fd)
            finally:
                os.close(null_fd)
        except (OSError, ValueError, AttributeError, io.UnsupportedOperation):
            pass
        raise OutputIOError from e
    _output_bytes += len(safe.encode("utf-8"))


def io_failure() -> None:
    """No confundir una salida fallida con INVALID; incluso stderr puede fallar."""
    try:
        os.write(2, b"\nERROR E/S [4]: no se pudo completar la entrada/salida; no se emite veredicto\n")
    except OSError:
        pass
    raise SystemExit(EXIT_IO)


def same_destination(a: Any, b: Any) -> bool:
    """True si ambos flujos escriben en el mismo terminal o fichero (p.ej. stderr y stdout en consola)."""
    try:
        sa, sb = os.fstat(a.fileno()), os.fstat(b.fileno())
    except (OSError, ValueError, AttributeError, io.UnsupportedOperation):
        return False
    return (sa.st_dev, sa.st_ino) == (sb.st_dev, sb.st_ino)


def emit_verdict(message: str) -> None:
    # Mantener el canal histórico y añadir un veredicto completo a stdout.
    # Si stderr y stdout van al mismo destino, la copia de stderr solo duplicaria la linea.
    if not same_destination(sys.stderr, sys.stdout):
        emit(message, file=sys.stderr, essential=True, final=True)
    emit(message, essential=True, final=True, closure=True)


def die(code: int, msg: str) -> None:
    if code == EXIT_IO:
        raise VerifierUsageError(msg)
    emit_verdict(f"INVALID[{code}]: {msg}")
    sys.exit(code)


class VerifierArgumentParser(argparse.ArgumentParser):
    def exit(self, status: int = 0, message: str | None = None) -> None:
        # Ninguna ruta de argparse, incluida ayuda, puede dar aprobacion 0.
        die(EXIT_IO, "ayuda/uso no verifica evidencia" if status == 0 else (message or "uso incorrecto"))

    def error(self, message: str) -> None:
        die(EXIT_IO, terminal_text(message))


def physical_member_name(name: str) -> str:
    if (not name or name.startswith("/") or "\\" in name or ":" in name
            or any(ord(c) < 32 or ord(c) == 127 for c in name)
            or any(p in ("", ".", "..") for p in name.split("/"))):
        die(EXIT_INTEGRITY, f"ruta fisica insegura: {terminal_text(name)}")
    return unicodedata.normalize("NFC", name).casefold()


def core_name_skeleton(name: str) -> str:
    # Solo deteccion de aliases; nunca se imprime ni se usa como nombre aceptado.
    table = str.maketrans({0x041c: "M", 0x043c: "m", 0x043e: "o", 0x041e: "O",
                          0x0440: "p", 0x0420: "P", 0x0435: "e", 0x0415: "E",
                          0x0430: "a", 0x0410: "A", 0x0441: "c", 0x0421: "C",
                          0x0456: "i", 0x0406: "I", 0x039c: "M", 0x039f: "O", 0x03bf: "o",
                          0x03a1: "P", 0x03c1: "p", 0x0395: "E", 0x0391: "A",
                          0x0399: "I", 0x03b9: "i"})
    return "".join(c for c in unicodedata.normalize("NFKD", name.translate(table))
                   if not unicodedata.combining(c)).casefold()


def portable_member_name(name: str) -> bool:
    devices = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "CLOCK$"}
    devices |= {f"{prefix}{i}" for prefix in ("COM", "LPT") for i in range(10)}
    parts = name.split("/")
    for part in parts:
        if (part.endswith((".", " "))
                or re.fullmatch(r"[^.~]{1,6}~[0-9]+(?:\.[^.]{1,3})?", part, re.ASCII)
                or part.split(".", 1)[0].rstrip(" .").upper() in devices):
            return False
    return True


def safe_member_name(name: str, *, allow_nested: bool = False) -> str:
    # Reglas de nombres resueltos: NFC/casefold, portabilidad y aliases de
    # miembros reservados. Auxiliares con acento no se confunden con el nucleo.
    normalized = unicodedata.normalize("NFC", name)
    if (not normalized
            or any(ord(c) < 32 or ord(c) == 127 for c in name)
            or "\\" in name or ":" in name or name.startswith("/")
            or any(p in ("", ".", "..") for p in name.split("/"))):
        die(EXIT_INTEGRITY, f"nombre ZIP inseguro o no canonico: {terminal_text(name)}")
    key = normalized.casefold()
    parts = name.split("/")
    if not portable_member_name(name):
        die(EXIT_INTEGRITY, f"nombre ZIP no portable en Windows: {terminal_text(name)}")
    if not allow_nested and len(parts) > 1 and any(part.lower() in {n.lower() for n in RESERVED_MEMBERS} for part in parts):
        die(EXIT_INTEGRITY, f"nombre reservado anidado: {terminal_text(name)}")
    if any(core_name_skeleton(name) == n.lower() and name != n for n in RESERVED_MEMBERS):
        die(EXIT_INTEGRITY, f"colision con nombre reservado: {terminal_text(name)}")
    return key


def validate_zip_container(raw: bytes, unsupported_out: list[str] | None = None) -> list[dict[str, Any]]:
    """ZIP32 cerrado; especificacion y referencia JS en docs/zip-profile.md.

    No usar offsets corregidos por zipfile/JSZip: todos son absolutos desde 0.
    Sin comentarios, ZIP64, cifrado ni volumenes multiples; extras UT/ux/UNIX/NTFS
    y Unicode Path redundante.
    STORED/DEFLATE, con descriptor opcional de 12/16 bytes, son el perfil soportado.
    """
    def require(ok: bool, msg: str) -> None:
        if not ok:
            die(EXIT_INTEGRITY, f"contenedor ZIP: {msg}")
    require(len(raw) <= MAX_ZIP_BYTES, "supera el limite de tamano comprimido")
    require(len(raw) >= 22 and raw[:4] == b"PK\x03\x04", "no empieza en byte 0 con header local")
    end = len(raw) - 22
    require(raw[end:end + 4] == b"PK\x05\x06", "EOCD no ocupa exactamente el final; bytes anexos/comentario")
    _, disk, cd_disk, on_disk, count, cd_size, cd_start, comment = struct.unpack_from("<4s4H2IH", raw, end)
    require(disk == cd_disk == comment == 0 and on_disk == count, "volumenes/comentarios no soportados")
    require(0 < count <= MAX_MEMBERS, "numero de miembros no permitido")
    require(cd_start + cd_size == end and cd_start < end, "directorio central no cubre el fichero completo")
    entries, seen, pos, total = [], set(), cd_start, 0
    unsupported = []
    def timestamp_extra_ok(tag: int, body: bytes) -> bool:
        # Solo marcas de tiempo y uid/gid: no cambian nombre ni contenido.
        if tag == 0x5455:  # Info-ZIP UT: flags + hasta 3 tiempos de 4 bytes
            return (len(body) >= 1 and body[0] & ~7 == 0 and (len(body) - 1) % 4 == 0
                    and (len(body) - 1) // 4 <= bin(body[0]).count("1"))
        if tag == 0x7875:  # Info-ZIP ux: version 1, uid y gid de longitud declarada
            if not body:
                return True
            if len(body) < 3 or body[0] != 1 or not 1 <= body[1] <= 8:
                return False
            gid_at = 2 + body[1]
            return (gid_at < len(body) and 1 <= body[gid_at] <= 8
                    and len(body) == gid_at + 1 + body[gid_at])
        if tag == 0x000a:  # NTFS: reservado + un unico atributo 1 de 24 bytes
            return len(body) == 32 and struct.unpack_from("<HH", body, 4) == (1, 24)
        return False
    def extra_profile(data: bytes, name_bytes: bytes, *, local: bool = False) -> bytes | None:
        unix_times = None
        cursor, tags = 0, set()
        while cursor < len(data):
            if (cursor + 4 > len(data) and data[cursor:cursor + 2] == b"\x55\x58"):
                unsupported.append("extra Info-ZIP UNIX truncado (0x5855)")
                break
            require(cursor + 4 <= len(data), "campo extra truncado")
            tag, length = struct.unpack_from("<HH", data, cursor)
            cursor += 4
            if tag == 0x5855 and cursor + length > len(data):
                unsupported.append("extra Info-ZIP UNIX truncado (0x5855)")
                break
            require(cursor + length <= len(data), "campo extra fuera de limites")
            body = data[cursor:cursor + length]
            cursor += length
            labels = {0x5455: "Info-ZIP UT", 0x7875: "Info-ZIP UX", 0x000a: "NTFS",
                      0x7075: "Unicode Path", 0x0001: "ZIP64"}
            if tag == 0x5855:  # Informativo: nunca aporta nombres, tamanos ni offsets.
                if tag not in tags and len(body) == (12 if local else 8):
                    struct.unpack("<IIHH" if local else "<II", body)
                    unix_times = body[:8]
                    tags.add(tag)
                else:
                    unsupported.append("extra Info-ZIP UNIX malformado o repetido (0x5855)")
                continue
            if tag in (0x5455, 0x7875, 0x000a):
                if tag not in tags and timestamp_extra_ok(tag, body):
                    tags.add(tag)
                    continue
                unsupported.append("extra " + labels[tag] + " malformado o repetido (0x%04x)" % tag)
                continue
            if tag == 0x7075 and tag not in tags and len(body) >= 5 and body[0] == 1:
                if (struct.unpack_from("<I", body, 1)[0] == zlib.crc32(name_bytes)
                        and body[5:] == name_bytes):
                    tags.add(tag)
                    continue
            # Unicode Path no redundante cambia el nombre del extractor; ZIP64 y
            # cualquier otro extra quedan fuera del perfil.
            unsupported.append("extra " + labels.get(tag, "desconocido") + " (0x%04x)" % tag)
        return unix_times
    name_encodings: dict[bytes, bool] = {}
    for _ in range(count):
        require(pos + 46 <= end and raw[pos:pos + 4] == b"PK\x01\x02", "registro central invalido")
        values = struct.unpack_from("<4s6H3I5H2I", raw, pos)
        (_, made, needed, flags, method, time, date, crc, csize, usize,
         nlen, xlen, clen, member_disk, internal, external, offset) = values
        require(needed in (10, 20) and member_disk == clen == 0, "version, ZIP64, extra o comentario no soportado")
        require(method in (0, 8) and flags & ~0x080E == 0,
                "metodo, cifrado o flags no soportados")
        require(method == 8 or flags & 6 == 0, "flags de DEFLATE en miembro STORED")
        require(method == 0 or needed == 20, "version incompatible con DEFLATE")
        attr_directory = stat.S_IFMT(external >> 16) == stat.S_IFDIR or bool(external & 0x10)
        require(stat.S_IFMT(external >> 16) in (0, stat.S_IFREG, stat.S_IFDIR),
                "tipo de miembro no regular/enlace prohibido")
        require(pos + 46 + nlen + xlen <= end, "nombre/extra central truncado")
        name_bytes = raw[pos + 46:pos + 46 + nlen]
        unix_times = extra_profile(raw[pos + 46 + nlen:pos + 46 + nlen + xlen], name_bytes)
        try:
            # ditto escribe UTF-8 sin bit 11; preferirlo si los bytes son validos.
            # CP437 se conserva solo cuando no hay una interpretacion UTF-8 valida.
            try:
                name = name_bytes.decode("utf-8")
            except UnicodeError:
                if flags & 0x800:
                    raise
                name = name_bytes.decode("cp437")
        except UnicodeError:
            die(EXIT_INTEGRITY, "nombre ZIP ilegible")
        # Un prefijo no ASCII compartido debe usar la misma convencion de bandera:
        # extractores que obedecen bit 11 no deben dividir una ruta aparente unica.
        parts = name_bytes.rstrip(b"/").split(b"/")
        for depth in range(1, len(parts) + 1):
            prefix = b"/".join(parts[:depth])
            if any(byte >= 128 for byte in prefix):
                utf8_flag = bool(flags & 0x800)
                require(prefix not in name_encodings or name_encodings[prefix] == utf8_flag,
                        "convenciones de nombre incompatibles en ruta compartida")
                name_encodings[prefix] = utf8_flag
        # Directorio = nombre con barra final, como lo entienden los extractores.
        # Un atributo de directorio sin barra se extraeria como fichero invisible aqui.
        directory = name.endswith("/")
        require(directory or not attr_directory,
                f"atributo de directorio sin barra final: {terminal_text(name)}")
        key = physical_member_name(name[:-1] if directory else name)
        require(key not in seen, f"nombre duplicado/colision: {terminal_text(name)}")
        seen.add(key)
        require(usize <= MAX_MEMBER_BYTES, f"{terminal_text(name)}: limite descomprimido por miembro")
        total += usize
        require(total <= MAX_TOTAL_BYTES, "limite descomprimido total")
        require(usize <= MAX_COMPRESSION_RATIO * max(1, csize), f"{terminal_text(name)}: ratio de compresion excesivo")
        entries.append(dict(name=name, directory=directory, name_bytes=name_bytes, needed=needed,
                            flags=flags, method=method, time=time, date=date, crc=crc,
                            csize=csize, usize=usize, offset=offset, unix_times=unix_times))
        pos += 46 + nlen + xlen
    require(pos == end, "bytes/headers extra en directorio central")
    entries.sort(key=lambda e: e["offset"])
    pos = 0
    for i, entry in enumerate(entries):
        require(entry["offset"] == pos and pos + 30 <= cd_start,
                "prefijo, hueco, solapamiento o offset local no contiguo")
        require(raw[pos:pos + 4] == b"PK\x03\x04", "header local ausente")
        (_, needed, flags, method, time, date, crc, csize, usize,
         nlen, xlen) = struct.unpack_from("<4s5H3I2H", raw, pos)
        require(pos + 30 + nlen + xlen <= cd_start, "extra local o nombre truncado")
        local_unix_times = extra_profile(raw[pos + 30 + nlen:pos + 30 + nlen + xlen],
                                         entry["name_bytes"], local=True)
        if (local_unix_times is not None and entry["unix_times"] is not None
                and local_unix_times != entry["unix_times"]):
            unsupported.append("extra Info-ZIP UNIX local/central incoherente (0x5855)")
        require(raw[pos + 30:pos + 30 + nlen] == entry["name_bytes"], "nombre local/central difiere")
        require((needed, flags, method, time, date) == tuple(entry[k] for k in
                ("needed", "flags", "method", "time", "date")), "header local/central difiere")
        start = pos + 30 + nlen + xlen
        data_end = start + entry["csize"]
        next_offset = entries[i + 1]["offset"] if i + 1 < len(entries) else cd_start
        require(data_end <= next_offset, "datos solapados o truncados")
        expected = (entry["crc"], entry["csize"], entry["usize"])
        if flags & 8:
            require(all(v in (0, e) for v, e in zip((crc, csize, usize), expected)), "descriptor/local difiere")
            descriptor = raw[data_end:next_offset]
            if len(descriptor) == 16 and descriptor[:4] == b"PK\x07\x08":
                descriptor = descriptor[4:]
            require(len(descriptor) == 12 and struct.unpack("<3I", descriptor) == expected,
                    "descriptor invalido o hueco tras datos")
        else:
            require((crc, csize, usize) == expected and data_end == next_offset,
                    "tamano/CRC local difiere o hay hueco tras datos")
        entry["data_start"] = start
        pos = next_offset
    require(pos == cd_start, "bytes no contabilizados antes del directorio central")
    # Un unico criterio para __MACOSX, fijado ANTES de calcular el envoltorio:
    # - "appledouble": metadato tolerado e ignorado (no es evidencia);
    # - "macosx" sin appledouble: miembro normal con su ruta completa, nunca
    #   dentro del envoltorio; con nombre reservado es INVALID.
    present = set()
    for e in entries:
        if not e["name"].startswith(MACOSX_PREFIX):
            parts = e["name"].rstrip("/").split("/")
            present.update("/".join(parts[:i]) for i in range(1, len(parts) + 1))
    for e in entries:
        e["macosx"] = e["name"].startswith(MACOSX_PREFIX)
        e["appledouble"] = False
        if e["macosx"] and not e["directory"]:
            parent, _, base = e["name"][len(MACOSX_PREFIX):].rpartition("/")
            target = (parent + "/" if parent else "") + base[2:]
            compressed = raw[e["data_start"]:e["data_start"] + e["csize"]]
            try:
                if e["method"] == 0:
                    head = compressed[:4]
                else:
                    decoder = zlib.decompressobj(-15)
                    decoded = decoder.decompress(compressed, MAX_MEMBER_BYTES + 1)
                    require(decoder.eof and not decoder.unconsumed_tail,
                            "flujo AppleDouble DEFLATE truncado o excede recursos")
                    head = decoded[:4]
            except zlib.error as exc:
                die(EXIT_INTEGRITY, "flujo AppleDouble DEFLATE invalido: " + terminal_text(exc))
            e["appledouble"] = (base.startswith("._") and len(base) > 2
                                and target in present and head == APPLEDOUBLE_MAGIC)
    file_entries = [e for e in entries if not e["directory"] and not e["macosx"]]
    prefixes = {e["name"].split("/", 1)[0] for e in file_entries}
    wrapped = (bool(file_entries) and len(prefixes) == 1
               and all("/" in e["name"] for e in file_entries))
    wrapper = next(iter(prefixes)) if wrapped else None
    if wrapped:
        reason = None
        if wrapper.endswith("."):
            reason = "su nombre termina en un punto"
        elif wrapper.endswith(" "):
            reason = "su nombre termina en un espacio"
        elif not portable_member_name(wrapper):
            if "~" in wrapper:
                reason = "su nombre parece un alias corto 8.3 de Windows"
            else:
                reason = "su nombre es reservado de Windows (como AUX, CON, PRN o LPT1)"
        elif core_name_skeleton(wrapper) in {n.lower() for n in RESERVED_MEMBERS}:
            reason = "su nombre coincide con un fichero del núcleo o se parece a él"
        if reason:
            unsupported.append("La carpeta " + terminal_text(wrapper) + ": " + reason +
                               ". Vuelva a comprimir los ficheros sin carpeta, o renombre la carpeta")
    logical_seen = set()
    core_parents = set()
    reserved_skeletons = {n.lower() for n in RESERVED_MEMBERS}
    for e in entries:
        e["ignored"] = e["directory"] or e["appledouble"]
        if e["directory"]:
            require(e["usize"] == 0, "directorio con contenido")
            directory_name = e["name"][:-1]
            if wrapped and (directory_name == wrapper or directory_name.startswith(wrapper + "/")):
                directory_name = directory_name[len(wrapper):].lstrip("/")
            if wrapped and directory_name.startswith(MACOSX_PREFIX):
                shadow = directory_name[len(MACOSX_PREFIX):]
                if shadow == wrapper or shadow.startswith(wrapper + "/"):
                    directory_name = MACOSX_PREFIX.rstrip("/") + shadow[len(wrapper):]
            if directory_name:
                safe_member_name(directory_name, allow_nested=True)
        if e["ignored"]:
            continue
        if e["macosx"]:
            base = e["name"].rsplit("/", 1)[-1]
            bare = base[2:] if base.startswith("._") else base
            require(core_name_skeleton(base) not in reserved_skeletons
                    and core_name_skeleton(bare) not in reserved_skeletons,
                    f"miembro reservado en __MACOSX sin AppleDouble valido: {terminal_text(e['name'])}")
            logical = e["name"]
            key = safe_member_name(logical, allow_nested=True)
            require(key not in logical_seen, "colision/ambiguedad de miembros resueltos")
            logical_seen.add(key)
            e["logical_name"] = logical
            continue
        logical = e["name"].split("/", 1)[1] if wrapped else e["name"]
        base = logical.rsplit("/", 1)[-1]
        if core_name_skeleton(base) in reserved_skeletons:
            # Todo candidato a miembro reservado debe ser exacto e inequivoco.
            safe_member_name(base)
            if base in RESERVED_MEMBERS:
                core_parents.add(logical.rsplit("/", 1)[0] if "/" in logical else "")
                if "/" in logical:
                    unsupported.append("mas de una carpeta envolvente/ruta de miembro nucleo")
                logical = base
        key = safe_member_name(logical, allow_nested=True)
        require(key not in logical_seen, "colision/ambiguedad de miembros resueltos")
        logical_seen.add(key)
        e["logical_name"] = logical
    if wrapped and not reason and unicodedata.normalize("NFC", wrapper).casefold() in logical_seen:
        unsupported.append("La carpeta " + terminal_text(wrapper) +
                           " tiene el mismo nombre que un fichero. Vuelva a comprimir los ficheros sin carpeta, o renombre la carpeta")
    require(len(core_parents) <= 1, "miembros nucleo repartidos en rutas ambiguas")
    if unsupported:
        reasons = sorted(set(unsupported))
        if unsupported_out is None:
            die(EXIT_IO, "CONTENEDOR NO SOPORTADO: " + "; ".join(reasons) +
                "; NO implica que el bundle sea genuino")
        unsupported_out.extend(reasons)
    return entries


def load_zip(path: Path, anomalies: list[str] | None = None,
             member_names: set[str] | None = None,
             unsupported: list[str] | None = None,
             ignored_out: list[dict[str, Any]] | None = None) -> dict[str, bytes]:
    if not path.is_file():
        die(EXIT_IO, f"no existe: {terminal_text(path)}")
    try:
        if path.stat().st_size > MAX_ZIP_BYTES:
            die(EXIT_INTEGRITY, "ZIP supera el limite de tamano comprimido")
        with path.open("rb") as source:
            raw = source.read(MAX_ZIP_BYTES + 1)
        reasons = [] if unsupported is None else unsupported
        emit(f"  bundle_sha256: {essential_text(hashlib.sha256(raw).hexdigest())}", essential=True)
        entries = validate_zip_container(raw, reasons)
        if ignored_out is not None:
            ignored_out.extend(e for e in entries if e["ignored"])
        names = {entry["logical_name"] for entry in entries if not entry["ignored"]}
        if member_names is not None:
            member_names.update(names)
        files = {}
        for entry in entries:
            name = entry.get("logical_name", entry["name"])
            try:
                compressed = raw[entry["data_start"]:entry["data_start"] + entry["csize"]]
                if entry["method"] == 8:
                    decoder = zlib.decompressobj(-15)
                    data = decoder.decompress(compressed, entry["usize"] + 1)
                    if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
                        die(EXIT_INTEGRITY, f"{terminal_text(name)}: flujo DEFLATE no coincide con el contenedor")
                else:
                    data = compressed
                if len(data) != entry["usize"]:
                    die(EXIT_INTEGRITY, f"{terminal_text(name)}: tamano descomprimido difiere")
                if zlib.crc32(data) != entry["crc"]:
                    raise zipfile.BadZipFile("CRC no coincide")
                if not entry["ignored"]:
                    files[name] = data
            except (zipfile.BadZipFile, zlib.error, OSError, RuntimeError, NotImplementedError) as e:
                if name in CORE_MEMBERS or anomalies is None:
                    code = EXIT_INTEGRITY if isinstance(e, (zipfile.BadZipFile, zlib.error)) else EXIT_IO
                    die(code, f"no se puede leer {terminal_text(name)}: {terminal_text(e)}")
                # Si es necesario para la cadena o figura en el manifiesto,
                # las etapas obligatorias rechazaran su ausencia despues.
                anomalies.append(f"{terminal_text(name)}: fichero auxiliar ilegible: {terminal_text(e)}")
        return files
    except (zipfile.BadZipFile, OSError, RuntimeError) as e:
        die(EXIT_IO, f"ZIP invalido: {terminal_text(e)}")


def _unique_json_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RenderedValueError(f"campo JSON duplicado: {terminal_text(key)}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise RenderedValueError(f"constante JSON no permitida: {terminal_text(value)}")


def _finite_json_float(value: str) -> float:
    result = float(value)
    if not math.isfinite(result):
        raise RenderedValueError(f"numero JSON no finito: {terminal_text(value)}")
    return result


def json_strict(raw: bytes) -> Any:
    return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_json_fields,
                      parse_constant=_reject_json_constant, parse_float=_finite_json_float)


def parse_json_bytes(raw: bytes, label: str) -> dict[str, Any]:
    try:
        obj = json_strict(raw)
    except Exception as e:
        die(EXIT_INTEGRITY, f"{terminal_text(label)} no es JSON UTF-8 valido: {terminal_text(e)}")
    if not isinstance(obj, dict):
        die(EXIT_INTEGRITY, f"{terminal_text(label)} no es objeto JSON")
    return obj


def is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def verify_proof_schema(proof: dict[str, Any]) -> None:
    if not proof:
        die(EXIT_INTEGRITY, "proof.json vacio")
    if proof.get("v") not in ("X39-NOTARIA-1", "X39-NOTARIA-2", "X39-NOTARIA-3"):
        die(EXIT_INTEGRITY, "version de proof.json ausente o no soportada")
    for field in ("agreement_id", "content_hash", "sealed_at"):
        if not isinstance(proof.get(field), str) or not proof[field].strip():
            die(EXIT_INTEGRITY, f"proof.json sin {terminal_text(field)} valido")
    ch = proof["content_hash"]
    if len(ch) != 64 or any(c not in "0123456789abcdef" for c in ch):
        die(EXIT_INTEGRITY, "content_hash no es SHA-256 hexadecimal")
    if proof["v"] == "X39-NOTARIA-3" and not isinstance(proof.get("msg_sigs"), dict):
        die(EXIT_SIG, "v3 requiere msg_sigs para comprobar todas las firmas Ed25519")
    if proof.get("msg_sigs") is not None:
        ms = proof["msg_sigs"]
        if (not isinstance(ms, dict) or set(ms) != {"algorithm", "signed", "total"}
                or ms.get("algorithm") != "Ed25519"
                or any(type(ms.get(k)) is not int or ms[k] < 0 for k in ("signed", "total"))
                or ms["signed"] > ms["total"]):
            die(EXIT_SIG, "proof.msg_sigs no cumple el esquema Ed25519")
    if proof.get("sig_keys") is not None:
        if not isinstance(proof["sig_keys"], dict) or set(proof["sig_keys"]) - {"A", "B"}:
            die(EXIT_SIG, "proof.sig_keys no cumple el esquema de roles A/B")
        for role, value in proof["sig_keys"].items():
            b64_decode_exact(f"sig_keys.{role}", value, 32)


def verify_proof_hash(proof_bytes: bytes, sigs: dict[str, Any]) -> None:
    claimed = sigs.get("proof_hash")
    if not isinstance(claimed, str) or len(claimed) != 64:
        die(EXIT_INTEGRITY, "proof_hash mal formado en signatures.json")
    recomputed = hashlib.sha256(proof_bytes).hexdigest()
    if recomputed != claimed:
        die(EXIT_INTEGRITY, f"proof_hash mismatch: claimed={terminal_text(claimed)} recomputed={terminal_text(recomputed)}")


def verify_cross_fields(proof: dict[str, Any], sigs: dict[str, Any]) -> None:
    for field in ("agreement_id", "content_hash", "sealed_at", "title"):
        pv, sv = proof.get(field), sigs.get(field)
        if field != "title" and sv is None:
            die(EXIT_INTEGRITY, f"signatures.json sin {terminal_text(field)}")
        if pv is not None and sv is not None and pv != sv:
            die(EXIT_INTEGRITY, f"{terminal_text(field)} difiere: proof={terminal_text(pv)} signatures={terminal_text(sv)}")


def b64_decode_strict(label: str, b64: str, expected_len: int) -> bytes:
    """Igual que b64_decode_exact pero lanza SigError en vez de terminar el proceso."""
    try:
        if not isinstance(b64, str):
            raise ValueError("base64 debe ser una cadena")
        raw = base64.b64decode(b64, validate=True)
    except Exception as e:
        raise SigError(f"{terminal_text(label)}: base64 invalido: {terminal_text(e)}")
    if len(raw) != expected_len:
        raise SigError(f"{terminal_text(label)}: tamano {terminal_text(len(raw))} bytes, esperado {terminal_text(expected_len)}")
    if base64.b64encode(raw).decode("ascii") != b64:
        raise SigError(f"{terminal_text(label)}: base64 no canonico (bits de relleno)")
    return raw


def b64_decode_exact(label: str, b64: str, expected_len: int) -> bytes:
    try:
        return b64_decode_strict(label, b64, expected_len)
    except SigError as e:
        die(EXIT_SIG, terminal_text(e))


def mldsa_verify_ok(pk: bytes, msg: bytes, sig: bytes) -> bool:
    """Verifica ML-DSA-87 normalizando las convenciones de pqcrypto.

    Las versiones no coinciden en como reportan el resultado:
      - pqcrypto 1.0.0 : devuelve None si la firma es valida y LANZA
                         InvalidSignatureError si no lo es.
      - versiones previas: devuelven True/False.

    Un `if not verify(...)` rechaza las firmas BUENAS bajo la primera convencion.
    Solo se aceptan True o None; cualquier otro resultado o excepcion falla.
    El llamante ejecuta ademas un control negativo con una firma alterada.
    """
    try:
        from pqcrypto.sign import ml_dsa_87
    except ImportError:
        raise SignatureEnvironmentError("pqcrypto no disponible. Instala: pip install pqcrypto")
    try:
        result = ml_dsa_87.verify(pk, msg, sig)
    except Exception:
        return False
    return result is True or result is None


def check_ml_dsa_signature(label: str, block: dict[str, Any], proof_bytes: bytes,
                           trusted: set[str] | None = None) -> str:
    """Verifica una co-firma ML-DSA-87 sobre los bytes crudos de proof.json.

    Si `trusted` es un conjunto de huellas, la clave publica del bundle solo se
    acepta cuando sha256(pk) pertenece a ese conjunto: ahi esta la diferencia
    entre "la firma es consistente consigo misma" y "la firma es de X-39".

    Devuelve la huella sha256 de la clave publica usada. Lanza SigError.
    """
    algo = block.get("algorithm")
    expected_algorithm = "ML-DSA-87 (FIPS-204)" if label == "warm" else "ML-DSA-87"
    if algo != expected_algorithm:
        raise SigError(f"{terminal_text(label)}: algoritmo inesperado: {terminal_text(algo)}")
    if block.get("tier") != label.upper():
        raise SigError(f"{terminal_text(label)}: tier debe ser {terminal_text(label.upper())}")
    pk_b64, sig_b64 = block.get("public_key_b64"), block.get("signature_b64")
    if not pk_b64 or not sig_b64:
        raise SigError(f"{terminal_text(label)}: falta public_key_b64 o signature_b64")
    pk = b64_decode_strict(f"{label}.public_key", pk_b64, ML_DSA_87_PK_LEN)
    sig = b64_decode_strict(f"{label}.signature", sig_b64, ML_DSA_87_SIG_LEN)

    fp_computed = hashlib.sha256(pk).hexdigest()
    fp_claimed = block.get("fingerprint")
    if "fingerprint" in block and (not is_sha256(fp_claimed) or fp_computed != fp_claimed):
        # Coherencia interna del bundle. NO acredita nada por si sola: ambos
        # valores salen del mismo fichero no anclado.
        raise SigError(f"{terminal_text(label)}: fingerprint mismatch: claimed={terminal_text(fp_claimed)} computed={terminal_text(fp_computed)}")
    if trusted is not None and fp_computed not in trusted:
        raise SigError(
            f"{terminal_text(label)}: clave NO reconocida. La huella {terminal_text(fp_computed)} no figura en "
            f"TRUSTED_COLD_FINGERPRINTS. La firma puede ser valida sobre si misma, "
            f"pero NO procede de la autoridad soberana de X-39."
        )
    if not mldsa_verify_ok(pk, proof_bytes, sig):
        raise SigError(f"{terminal_text(label)}: ML-DSA-87.verify FALLO")
    # Control negativo obligatorio: la libreria instalada DEBE rechazar una firma
    # alterada. Si acepta las dos, no esta verificando nada y su "valida" no vale.
    tampered = bytearray(sig)
    tampered[0] ^= 0x01
    if mldsa_verify_ok(pk, proof_bytes, bytes(tampered)):
        raise SignatureEnvironmentError(
            f"{label}: la instalacion de pqcrypto acepta una firma ALTERADA. "
            "No se puede confiar en su veredicto: revisa la libreria.")
    return fp_computed


def extra_fields(obj: dict[str, Any], allowed: set[str], label: str, anomalies: list[str],
                 *, reject: bool = False) -> None:
    for field in sorted(set(obj) - allowed):
        if reject:
            die(EXIT_INTEGRITY, f"{terminal_text(label)}: campo no reconocido {terminal_text(field)!r}")
        anomalies.append(f"{terminal_text(label)}: campo no reconocido {terminal_text(field)!r}")


def strict_timestamp(value: Any, label: str, code: int) -> datetime:
    if not isinstance(value, str) or ISO_TIMESTAMP.fullmatch(value) is None:
        die(code, f"{terminal_text(label)}: timestamp ISO-8601 estricto requerido")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except (ValueError, OverflowError):
        die(code, f"{terminal_text(label)}: timestamp ISO-8601 invalido")


def validate_verified_at(cold: dict[str, Any], proof: dict[str, Any]) -> None:
    if "verified_at" not in cold:
        return  # Campo historico opcional; su ausencia no afirma una fecha.
    verified = strict_timestamp(cold["verified_at"], "cold.verified_at", EXIT_SIG)
    sealed = strict_timestamp(proof["sealed_at"], "proof.sealed_at", EXIT_INTEGRITY)
    bounds = [sealed, COLD_CEREMONY_NOT_BEFORE]
    for field in ("created_at", "signed_a", "signed_b"):
        if proof.get(field) is not None:
            bounds.append(strict_timestamp(proof[field], f"proof.{field}", EXIT_INTEGRITY))
    if verified < max(bounds) or verified > datetime.now(timezone.utc):
        die(EXIT_SIG, "cold.verified_at anterior a creacion/sellado/ceremonia COLD o futuro")


def validate_signature_schema(sigs: dict[str, Any], proof: dict[str, Any], anomalies: list[str]) -> None:
    extra_fields(sigs, {"agreement_id", "title", "proof_hash", "content_hash", "sealed_at",
                        "cold", "warm", "message_signatures", "estado"}, "signatures.json", anomalies, reject=True)
    for field in ("agreement_id", "title", "proof_hash", "content_hash", "sealed_at"):
        if field in sigs and not isinstance(sigs[field], str):
            die(EXIT_INTEGRITY, f"signatures.json.{terminal_text(field)} no es texto")
    if "estado" in sigs or "estado" in proof:
        if sigs.get("estado") != proof.get("estado"):
            die(EXIT_INTEGRITY, "signatures.json.estado contradice proof.json")
    ms, expected = sigs.get("message_signatures"), proof.get("msg_sigs")
    if ms is None and expected is None:
        return
    if not isinstance(ms, dict) or not isinstance(expected, dict):
        die(EXIT_INTEGRITY, "message_signatures no coincide con proof.msg_sigs")
    extra_fields(ms, {"algorithm", "signed", "total", "keys"}, "signatures.json.message_signatures", anomalies, reject=True)
    if ms.get("algorithm") != "Ed25519" or expected.get("algorithm") != "Ed25519":
        die(EXIT_INTEGRITY, "message_signatures: algorithm debe ser Ed25519")
    for field in ("signed", "total"):
        if type(ms.get(field)) is not int or ms[field] != expected.get(field):
            die(EXIT_INTEGRITY, f"message_signatures.{terminal_text(field)} contradice proof.json")
    if ms.get("keys") != proof.get("sig_keys"):
        die(EXIT_INTEGRITY, "message_signatures.keys contradice proof.sig_keys")


def verify_signatures(proof_bytes: bytes, sigs_raw: bytes,
                      anomalies: list[str] | None = None) -> tuple[list[str], str | None]:
    if anomalies is None:
        anomalies = []
    sigs = parse_json_bytes(sigs_raw, "signatures.json")
    verify_proof_hash(proof_bytes, sigs)
    proof = parse_json_bytes(proof_bytes, "proof.json")
    verify_proof_schema(proof)
    verify_cross_fields(proof, sigs)
    validate_signature_schema(sigs, proof, anomalies)
    notes: list[str] = []
    cold_fp: str | None = None
    cold = sigs.get("cold")
    if cold is None:
        # COLD AUSENTE (no mala): la co-firma llega despues del sellado, por sneakernet.
        # Sin ella no hay VALID; todo lo demas se comprueba igual y, si es correcto y el
        # OTS verifica, main() emite CONSISTENTE [6]. Presente pero invalida: INVALID[2].
        notes.append("SIN co-firma COLD: falta su atestacion en este paquete; no se emite VALID")
    elif not isinstance(cold, dict) or not cold:
        die(EXIT_SIG, "co-firma COLD presente pero vacia o malformada; no se puede emitir VALID")
    else:
        extra_fields(cold, {"algorithm", "tier", "fingerprint", "public_key_b64", "signature_b64", "verified_at"},
                     "signatures.json.cold", anomalies, reject=True)
        validate_verified_at(cold, proof)
        if "verified_at" in cold:
            historical = HISTORICAL_COLD_VERIFIED_AT.get(hashlib.sha256(proof_bytes).hexdigest())
            if cold["verified_at"] != historical:
                anomalies.append("signatures.json.cold.verified_at: fecha externa NO autenticada por COLD "
                                 "ni reconocida por referencia historica local")
            else:
                notes.append("COLD verified_at: referencia historica local; NO es fecha firmada por COLD")
        try:
            cold_fp = check_ml_dsa_signature("cold", cold, proof_bytes,
                                             trusted=TRUSTED_COLD_FINGERPRINTS)
        except SignatureEnvironmentError as e:
            die(EXIT_IO, terminal_text(e))
        except SigError as e:
            die(EXIT_SIG, terminal_text(e))
    warm = sigs.get("warm")
    if warm is not None:
        # WARM no aporta atestacion independiente y la COLD no autentica este
        # bloque: si no verifica es ANOMALIA (5), nunca INVALID, para que nadie
        # pueda degradar una evidencia autentica tocando signatures.json.
        # Ausente/null es legitimo. La COLD copiada en el hueco WARM sigue siendo
        # INVALID[2]; un campo extra o una nota alterada, INVALID[1].
        if isinstance(warm, dict):
            try:
                candidate_pk = b64_decode_strict("warm.public_key", warm.get("public_key_b64"), ML_DSA_87_PK_LEN)
            except SigError:
                candidate_pk = None
            if candidate_pk is not None and hashlib.sha256(candidate_pk).hexdigest() in TRUSTED_COLD_FINGERPRINTS:
                die(EXIT_SIG, "COLD copiada en el hueco WARM")
            extra_fields(warm, {"algorithm", "tier", "fingerprint", "public_key_b64", "signature_b64", "note"},
                         "signatures.json.warm", anomalies, reject=True)
            if "note" in warm and warm["note"] != LEGACY_WARM_NOTE:
                die(EXIT_INTEGRITY, "warm.note no coincide con el texto heredado cerrado")
        try:
            if not isinstance(warm, dict):
                raise SigError("el bloque WARM no es un objeto JSON")
            warm_pk = b64_decode_strict("warm.public_key", warm.get("public_key_b64"), ML_DSA_87_PK_LEN)
            warm_fingerprint = hashlib.sha256(warm_pk).hexdigest()
            if warm_fingerprint in TRUSTED_COLD_FINGERPRINTS:
                die(EXIT_SIG, "COLD copiada en el hueco WARM")
            if warm_fingerprint not in TRUSTED_WARM_FINGERPRINTS:
                raise SigError(f"clave WARM no reconocida: {terminal_text(warm_fingerprint)}")
            warm_fp = check_ml_dsa_signature("warm", warm, proof_bytes, trusted=TRUSTED_WARM_FINGERPRINTS)
            notes.append("WARM: firma heredada, clave en linea retirada el 2026-07-16; "
                         "no aporta atestacion independiente; si no verifica es anomalia, no invalida")
            notes.append(f"WARM: comprobacion heredada correcta ({terminal_text(warm_fp[:16])}...)")
        except (SigError, ValueError, TypeError, AttributeError) as e:
            anomalies.append(f"signatures.json / WARM: NO VERIFICA: {terminal_text(e)}; "
                             "no cuenta para el veredicto, que sostiene la COLD")
    return notes, cold_fp


def verify_content_hash(proof: dict[str, Any], content_path: Path | None) -> None:
    if content_path is None:
        die(EXIT_IO, "DOCUMENTO NO COMPROBADO: indica --content con el documento original")
    if not content_path.is_file():
        die(EXIT_IO, f"documento no encontrado: {terminal_text(content_path)}")
    digest = hashlib.sha256()
    try:
        with content_path.open("rb") as document:
            for chunk in iter(lambda: document.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as e:
        die(EXIT_IO, f"no se puede leer documento {terminal_text(content_path)}: {terminal_text(e)}")
    computed = digest.hexdigest()
    claimed = proof.get("content_hash")
    if computed != claimed:
        die(EXIT_INTEGRITY, f"content_hash mismatch: proof={terminal_text(claimed)} file={terminal_text(computed)}")


def verify_chat_chain_v2(files: dict[str, bytes], proof: dict[str, Any]) -> None:
    """Solo X39-NOTARIA-2. Recomputa cada msg_hash desde content_hash+ts+role,
    valida la continuidad prev_hash y que el tip == chat_merkle_root firmado."""
    if proof.get("v", "") not in ("X39-NOTARIA-2", "X39-NOTARIA-3"):
        if "chat_chain.json" in files:
            die(EXIT_INTEGRITY, "v1 no admite una cadena chat_chain.json inventada")
        return
    if "chat_chain.json" not in files:
        die(EXIT_INTEGRITY, "v2 requiere chat_chain.json en el ZIP")
    chain = parse_json_bytes(files["chat_chain.json"], "chat_chain.json")
    if set(chain) - {"v", "agreement_id", "entries"}:
        die(EXIT_INTEGRITY, "chat_chain.json: campos no reconocidos")
    if chain.get("v") != proof.get("v"):
        die(EXIT_INTEGRITY, "chat_chain.v no coincide con proof.v")
    if chain.get("agreement_id") != proof.get("agreement_id"):
        die(EXIT_INTEGRITY, "chat_chain agreement_id no coincide con proof")
    entries = chain.get("entries")
    if not isinstance(entries, list) or not entries:
        die(EXIT_INTEGRITY, "chat_chain vacia")
    prev = "0" * 64
    for i, e in enumerate(entries):
        if not isinstance(e, dict) or set(e) - {"index", "ts", "role", "content_hash", "prev_hash", "msg_hash", "sig_b64", "cts"}:
            die(EXIT_INTEGRITY, f"chat_chain indice {terminal_text(i)}: campos no reconocidos")
        if type(e.get("index")) is not int or e["index"] != i:
            die(EXIT_INTEGRITY, f"chat_chain indice {terminal_text(i)}: index no coincide con posicion")
        if e.get("sig_b64") is None and e.get("cts") is not None:
            die(EXIT_SIG if proof["v"] == "X39-NOTARIA-3" else EXIT_INTEGRITY,
                f"chat_chain indice {terminal_text(i)}: cts sin firma que lo autentique")
        for field in ("content_hash", "prev_hash", "msg_hash"):
            if not is_sha256(e.get(field)):
                die(EXIT_INTEGRITY, f"indice {terminal_text(i)}: {terminal_text(field)} debe ser SHA-256 hexadecimal")
        if e.get("prev_hash") != prev:
            die(EXIT_INTEGRITY, f"cadena rota en indice {terminal_text(i)}: prev_hash mismatch")
        role, ch, ts = e.get("role"), e.get("content_hash"), e.get("ts", "")
        if not isinstance(ts, str) or not ts:
            die(EXIT_INTEGRITY, f"indice {terminal_text(i)}: ts invalido")
        if role not in ("A", "B"):
            die(EXIT_INTEGRITY, f"indice {terminal_text(i)}: role invalido: {terminal_text(role)}")
        recomputed = hashlib.sha256(f"{prev}:{ch}:{ts}:{role}".encode()).hexdigest()
        if recomputed != e.get("msg_hash"):
            die(EXIT_INTEGRITY, f"indice {terminal_text(i)}: msg_hash no deriva de content_hash/ts/role")
        prev = e["msg_hash"]
    expected = proof.get("chat_merkle_root")
    if not is_sha256(expected):
        die(EXIT_INTEGRITY, "v2 sin chat_merkle_root en proof.json")
    if prev != expected:
        die(EXIT_INTEGRITY, f"tip de cadena {terminal_text(prev)} != proof.chat_merkle_root {terminal_text(expected)}")


def verify_msg_sigs(files: dict[str, bytes], proof: dict[str, Any]) -> None:
    """X39-NOTARIA-3: firmas Ed25519 por mensaje sobre x39msg:v3:<aid>:<content_hash>:<cts>.
    Pubkeys ancladas en proof.json (sig_keys). No-repudio de autoria por mensaje."""
    ms = proof.get("msg_sigs")
    if proof.get("v") == "X39-NOTARIA-1":
        return
    if proof.get("v") == "X39-NOTARIA-3" and not ms:
        die(EXIT_SIG, "v3 requiere msg_sigs para comprobar todas las firmas Ed25519")
    chain = parse_json_bytes(files["chat_chain.json"], "chat_chain.json")
    entries = chain.get("entries") or []
    if not ms:
        if proof.get("v") == "X39-NOTARIA-3":
            die(EXIT_SIG, "v3 requiere msg_sigs para comprobar todas las firmas Ed25519")
        if not any(e.get("sig_b64") is not None for e in entries):
            return
    keys = proof.get("sig_keys") or {}
    if not keys:
        die(EXIT_SIG, "msg_sigs presente pero sin sig_keys en proof.json")
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        die(EXIT_IO, "cryptography no disponible. Instala: pip install cryptography")
    pks = {}
    for role, b in keys.items():
        raw = b64_decode_exact(f"sig_keys.{role}", b, 32)
        pks[role] = Ed25519PublicKey.from_public_bytes(raw)
    aid = proof.get("agreement_id")
    checked = 0
    for i, e in enumerate(chain.get("entries") or []):
        s = e.get("sig_b64")
        if s is None:
            continue
        role, ch, cts = e.get("role"), e.get("content_hash"), e.get("cts")
        if role not in pks:
            die(EXIT_SIG, f"indice {terminal_text(i)}: firma presente sin pubkey para rol {terminal_text(role)}")
        if not isinstance(cts, str) or not cts:
            die(EXIT_SIG, f"indice {terminal_text(i)}: firma sin cts")
        raw_sig = b64_decode_exact(f"entries[{i}].sig", s, 64)
        try:
            pks[role].verify(raw_sig, f"x39msg:v3:{aid}:{ch}:{cts}".encode())
        except Exception:
            die(EXIT_SIG, f"indice {terminal_text(i)}: firma Ed25519 INVALIDA (rol {terminal_text(role)})")
        checked += 1
    if ms is not None and checked != ms.get("signed"):
        die(EXIT_SIG, f"msg_sigs.signed={terminal_text(ms.get('signed'))} pero verificadas={terminal_text(checked)}")
    # Los contadores de proof.json los escribe quien genera el bundle: se contrastan con la
    # cadena real. En v3 TODOS los mensajes deben ir firmados; uno sin firma es fallo.
    total = len(chain.get("entries") or [])
    if ms is not None and total != ms.get("total"):
        die(EXIT_SIG, f"msg_sigs.total={terminal_text(ms.get('total'))} pero la cadena trae {terminal_text(total)} mensajes")
    if proof.get("v") == "X39-NOTARIA-3" and checked != total:
        die(EXIT_SIG, f"hilo v3 con mensajes SIN firma: firmados={terminal_text(checked)} de {terminal_text(total)}")


def parse_ots_bitcoin_paths(proof_bytes: bytes, ots_bytes: bytes) -> tuple[Any, list[Any], bool]:
    """Perfil OTS cerrado: rutas Bitcoin y metadatos heredados referenciados."""
    try:
        from opentimestamps.core.timestamp import DetachedTimestampFile
        from opentimestamps.core.serialize import StreamDeserializationContext, BytesSerializationContext
        from opentimestamps.core.op import OpSHA256, OpAppend, OpPrepend
        from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation
    except ImportError:
        die(EXIT_IO, "libreria Python opentimestamps no importable desde este interprete "
                     "(pip install opentimestamps-client en el mismo entorno; un 'ots' instalado con pipx no basta)")
    try:
        stream = io.BytesIO(ots_bytes)
        detached = DetachedTimestampFile.deserialize(StreamDeserializationContext(stream))
        if (type(detached.file_hash_op) is not OpSHA256
                or detached.file_digest != hashlib.sha256(proof_bytes).digest()
                or stream.read(1)):
            die(EXIT_OTS, ".ots ajeno a proof.json o con bytes anexos")
        canonical = BytesSerializationContext()
        detached.serialize(canonical)
        if canonical.getbytes() != ots_bytes:
            die(EXIT_OTS, ".ots con codificacion redundante/no canonica")
        calendars = {
            "https://alice.btc.calendar.opentimestamps.org",
            "https://bob.btc.calendar.opentimestamps.org",
            "https://btc.calendar.catallaxy.com",
            "https://finney.calendar.eternitywall.com",
        }
        paths = []
        surplus = False
        nodes = 0
        def walk(node: Any, path: tuple[Any, ...]) -> bool:
            nonlocal surplus, nodes
            nodes += 1
            if nodes > 4096:
                die(EXIT_OTS, ".ots supera el limite de nodos")
            has_bitcoin = False
            for attestation in node.attestations:
                if type(attestation) is BitcoinBlockHeaderAttestation:
                    if type(attestation.height) is not int or attestation.height <= 0 or len(node.msg) != 32:
                        die(EXIT_OTS, "atestacion Bitcoin fuera del perfil")
                    paths.append((path, attestation, node.msg.hex()))
                    if len(paths) > 16:
                        die(EXIT_OTS, ".ots supera el limite de ramas Bitcoin")
                    has_bitcoin = True
                elif type(attestation) is PendingAttestation:
                    surplus = True
                    if attestation.uri not in calendars:
                        die(EXIT_OTS, "PendingAttestation no reconocida; no es contenido verificado")
                else:
                    die(EXIT_OTS, "UnknownAttestation/atestacion no reconocida prohibida")
            for operation, child in node.ops.items():
                if type(operation) not in (OpSHA256, OpAppend, OpPrepend):
                    die(EXIT_OTS, "operacion OTS no reconocida")
                child_has_bitcoin = walk(child, path + (operation,))
                if not child_has_bitcoin:
                    surplus = True
                has_bitcoin |= child_has_bitcoin
            return has_bitcoin
        if not walk(detached.timestamp, ()) or not paths:
            die(EXIT_OTS, ".ots sin rama Bitcoin")
        if surplus:
            proof_hash = hashlib.sha256(proof_bytes).hexdigest()
            reference = LEGACY_METADATA.get(proof_hash, {}).get("proof.json.ots")
            if hashlib.sha256(ots_bytes).hexdigest() != reference:
                die(EXIT_OTS, ".ots con ramas/appends sobrantes sin Bitcoin")
        return detached, paths, surplus
    except Exception as e:
        die(EXIT_OTS, f".ots vacio, ilegible o no verificable: {terminal_text(e)}")


def verify_ots(proof_bytes: bytes, ots_bytes: bytes, bitcoin_node: str | None = None) -> dict[str, Any]:
    detached, paths, legacy = parse_ots_bitcoin_paths(proof_bytes, ots_bytes)
    from opentimestamps.core.timestamp import Timestamp, DetachedTimestampFile
    from opentimestamps.core.serialize import BytesSerializationContext
    verified = []
    with tempfile.TemporaryDirectory() as td:
        p, o = Path(td) / "proof.json", Path(td) / "bitcoin-path.ots"
        p.write_bytes(proof_bytes)
        for path, attestation, merkle_root in paths:
            # Cada invocacion recibe UNA ruta y UNA atestacion Bitcoin. El CLI
            # no puede aceptar una rama buena y omitir otras ramas manipuladas.
            root = Timestamp(detached.file_digest)
            leaf = root
            for operation in path:
                leaf = leaf.ops.add(operation)
            leaf.attestations.add(attestation)
            selected = DetachedTimestampFile(detached.file_hash_op, root)
            ctx = BytesSerializationContext()
            selected.serialize(ctx)
            o.write_bytes(ctx.getbytes())
            cmd = ["ots"]
            if bitcoin_node:
                cmd += ["--bitcoin-node", bitcoin_node]
            cmd += ["verify", str(o), "-f", str(p)]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            except FileNotFoundError:
                die(EXIT_IO, "comando 'ots' no encontrado. Instala: pip install opentimestamps-client")
            except subprocess.TimeoutExpired:
                die(EXIT_OTS, "ots verify timeout (120s)")
            if result.returncode != 0:
                problem = bitcoin_node_problem(result.stderr)
                if problem:
                    # Sin nodo no se ha comprobado nada: decirlo claro, sin la traza de ots.
                    die(EXIT_OTS, f"ANCLA NO COMPROBADA: {problem}; la rama Bitcoin "
                        f"{terminal_text(attestation.height)} queda sin confirmar. Sin nodo no hay VALID; "
                        "esto no indica que la evidencia sea falsa. Use un nodo Bitcoin propio "
                        "(bitcoin.conf local) o --bitcoin-node URL")
                die(EXIT_OTS, f"rama Bitcoin {terminal_text(attestation.height)} no confirmada: "
                    f"stdout={terminal_text(result.stdout)}; stderr={terminal_text(result.stderr)}")
            verified.append({"height": attestation.height, "merkle_root": merkle_root})
    return {"bitcoin_paths": verified, "legacy_calendar_metadata": legacy}


def bitcoin_node_problem(stderr: str) -> str | None:
    """Reconoce en la salida de 'ots verify' que el nodo Bitcoin no se pudo consultar.

    Solo fallos de acceso al RPC (sin conexion, sin configuracion, credenciales
    rechazadas). Cualquier otro fallo, p.ej. un Merkle que no coincide, devuelve None
    y se informa con la salida completa de ots.
    """
    if "401 Unauthorized" in stderr:
        return "el nodo Bitcoin rechazo las credenciales RPC (401 Unauthorized)"
    unreachable = ("ConnectionRefusedError", "Connection refused", "TimeoutError", "timed out",
                   "socket.gaierror", "Name or service not known", "No route to host",
                   "bitcoin.conf", ".cookie")
    if any(marker in stderr for marker in unreachable):
        return "no hay nodo Bitcoin accesible (el RPC no responde o falta su configuracion)"
    return None


def verify_manifest(files: dict[str, bytes], proof: dict[str, Any]) -> list[str]:
    """proof['files'] = {nombre: sha256}: manifiesto de ficheros informativos (p.ej. README.md)
    congelados al sellar. Cada fichero listado debe existir en el ZIP y coincidir byte a byte.
    Sin manifiesto (bundles anteriores) no se exige nada; el resumen lo avisa."""
    man = proof.get("files")
    if man is None:
        return []
    if not isinstance(man, dict):
        die(EXIT_INTEGRITY, "proof.files no es un objeto {nombre: sha256}")
    ok: list[str] = []
    for name, h in man.items():
        safe_member_name(name)
        if name not in files:
            die(EXIT_INTEGRITY, f"manifiesto: falta {terminal_text(name)} en el ZIP")
        got = hashlib.sha256(files[name]).hexdigest()
        if not is_sha256(h) or got != h:
            die(EXIT_INTEGRITY, f"manifiesto: {terminal_text(name)} sha256 mismatch claimed={terminal_text(h)} recomputed={terminal_text(got)}")
        ok.append(name)
    return ok


def validate_member_world(files: dict[str, bytes], members: set[str], proof: dict[str, Any],
                          anomalies: list[str]) -> set[str]:
    expected = set(CORE_MEMBERS)
    if proof["v"] == "X39-NOTARIA-1" and "chat_chain.json" in members:
        die(EXIT_INTEGRITY, "v1 no admite una cadena chat_chain.json inventada")
    if proof["v"] in ("X39-NOTARIA-2", "X39-NOTARIA-3"):
        expected.add("chat_chain.json")
    manifest = proof.get("files")
    if manifest is not None and not isinstance(manifest, dict):
        die(EXIT_INTEGRITY, "proof.files no es un objeto")
    seen = {safe_member_name(name) for name in expected}
    for name in manifest or {}:
        key = safe_member_name(name)
        if name in CORE_MEMBERS or (name == "chat_chain.json" and proof["v"] == "X39-NOTARIA-1"):
            die(EXIT_INTEGRITY, f"manifiesto incluye miembro estructural: {terminal_text(name)}")
        if name == "chat_chain.json":
            continue  # Puede declararse ademas del compromiso de cadena v2/v3.
        if key in seen:
            die(EXIT_INTEGRITY, f"colision de nombres en manifiesto: {terminal_text(name)}")
        seen.add(key)
        expected.add(name)
    extra_fields(proof, {"v", "agreement_id", "content_hash", "title", "chat_hash", "chat_hash_alg",
                         "chat_merkle_root", "msg_sigs", "sig_keys", "files", "party_a", "party_b",
                         "party_a_fp", "party_b_fp", "payment", "signed_a", "signed_b", "sealed_at", "estado", "created_at"},
                 "proof.json", anomalies)
    uncovered = members - expected
    for name in sorted(tuple(uncovered)):
        if name == "README.md":
            proof_hash = hashlib.sha256(files["proof.json"]).hexdigest()
            reference = LEGACY_METADATA.get(proof_hash, {}).get("README.md")
            if name not in files or hashlib.sha256(files[name]).hexdigest() != reference:
                die(EXIT_INTEGRITY, "README heredado manipulado o formato no reconocido: "
                    "se requiere proof.files o referencia local exacta")
            expected.add(name)
            uncovered.discard(name)
            continue
        anomalies.append(f"{terminal_text(name)}: miembro no declarado/no validado por la prueba")
    # Miembros declarados pero ilegibles no pueden desaparecer del resumen.
    uncovered.update(members - set(files))
    return uncovered


def auxiliary_parse_anomalies(files: dict[str, bytes], proof: dict[str, Any],
                              uncovered: set[str] | None = None) -> list[str]:
    """Comprueba JSON y UTF-8 de auxiliares; no inventa parsers para binarios.

    Los ficheros esenciales se parsean en sus etapas obligatorias: sus errores
    siguen siendo INVALID, porque no se puede sostener la aprobacion por COLD.
    """
    essential = {"proof.json", "signatures.json"}
    if proof.get("v") in ("X39-NOTARIA-2", "X39-NOTARIA-3"):
        essential.add("chat_chain.json")
    anomalies = []
    for name, raw in sorted(files.items()):
        if name in essential:
            continue
        suffix = Path(name).suffix.lower()
        try:
            if suffix == ".json":
                json_strict(raw)
            elif suffix in (".md", ".txt", ".csv", ".html", ".htm"):
                raw.decode("utf-8")
        except (UnicodeError, ValueError, RecursionError) as e:
            anomalies.append(f"{terminal_text(name)}: fichero auxiliar no se puede parsear: {terminal_text(e)}")
            if uncovered is not None:
                uncovered.add(name)
    return anomalies


def main() -> None:
    global _output_bytes, _output_limited, _capture_output, _output_queue, _output_resource_error
    _output_bytes, _output_limited = 0, False
    _output_queue, _output_resource_error = [], False
    _capture_output = True
    code = EXIT_IO
    emit("Un veredicto solo vale si termina con su marca de cierre final.", essential=True)
    try:
        try:
            _main()
        except (ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError) as e:
            die(EXIT_INTEGRITY, f"entrada no verificable: {terminal_text(e)}")
    except SystemExit as e:
        code = e.code if isinstance(e.code, int) else EXIT_IO
    except VerifierUsageError as e:
        emit_verdict("ERROR USO/CONTENEDOR [4]: " + str(e))
        code = EXIT_IO
    except (OutputIOError, OSError) as e:
        emit_verdict("ERROR E/S [4]: " + terminal_text(e))
        code = EXIT_IO
    finally:
        _capture_output = False
    # El veredicto ya esta decidido. La escritura no puede rebajar INVALID a 4.
    if code not in (EXIT_OK, EXIT_WARNINGS, EXIT_CONSISTENT):
        _output_queue = [item for item in _output_queue if not item[2]]
    if _output_resource_error and code in (EXIT_OK, EXIT_WARNINGS, EXIT_CONSISTENT):
        code = EXIT_IO
        _output_queue = [item for item in _output_queue if not item[2]]
        _output_queue.append((sys.stderr, "ERROR USO [4]: salida esencial excede recursos; sin aprobacion\n", False, False))
        _output_queue.append((sys.stdout, "ERROR USO [4]: salida esencial excede recursos; sin aprobacion\n[FIN VEREDICTO]", False, True))
    failed = sys.stdout is None
    queue = _output_queue
    _output_queue = []
    _output_bytes, _output_limited = 0, False
    pending_closure = False
    for stream, text, approval, closure in queue:
        if failed and approval:
            continue
        try:
            message = text[:-len("[FIN VEREDICTO]")] if closure else text
            if closure and not approval:
                pending_closure = True
                closure = False
            emit(message[:-1], file=stream, essential=True, final=True,
                 approval=approval, closure=closure)
        except (OutputIOError, VerifierUsageError):
            # stderr es diagnostico auxiliar; stdout conserva el cierre/veredicto.
            if stream is not sys.stderr:
                failed = True
    if failed:
        invalid = VERDICT_PRECEDENCE.get(code, 0) == VERDICT_PRECEDENCE[EXIT_INTEGRITY]
        if not invalid:
            code = EXIT_IO
        message = (f"ERROR E/S: salida incompleta; se conserva INVALID[{code}]\n" if invalid
                   else "ERROR E/S [4]: salida incompleta; no se emite aprobacion\n")
        try:
            emit("\n" + message.rstrip("\n"), essential=True, final=True, closure=True)
        except (OutputIOError, VerifierUsageError):
            pass
        try:
            os.write(2, ("\n" + message).encode("ascii"))
        except OSError:
            pass
    elif pending_closure:
        try:
            emit("", essential=True, final=True, closure=True)
        except (OutputIOError, VerifierUsageError):
            pass
    raise SystemExit(code)


def _main() -> None:
    ap = VerifierArgumentParser(description="X-39 Notaria - verificador de referencia offline. "
                                            "Un veredicto solo vale si termina con su marca de cierre final.",
                                add_help=False, allow_abbrev=False)
    ap.add_argument("-h", "--help", action="store_true", help="mostrar uso (codigo 4; no verifica)")
    ap.add_argument("bundle", type=Path, nargs="?", help="x39-evidencia-<aid>.zip")
    ap.add_argument("--content", type=Path, default=None, help="documento original necesario para VALID")
    ap.add_argument("--skip-ots", action="store_true", help="diagnostico offline; resultado incompleto, sin VALID ni codigo 0")
    ap.add_argument("--bitcoin-node", default=None, metavar="URL",
                    help="RPC de tu nodo Bitcoin (http://user:pass@host:8332 o cookie); "
                         "verificacion soberana del ancla sin terceros")
    args = ap.parse_args()
    if args.help:
        emit(ap.format_help().rstrip())
        emit("Para rutas que empiezan por guion: --content documento -- -h")
        die(EXIT_IO, "ayuda: no se ha verificado ningun bundle")
    if args.bundle is None:
        die(EXIT_IO, "falta bundle; use --help (4), o -- para rutas que empiezan por guion")
    anomalies: list[str] = []
    member_names: set[str] = set()
    unsupported = []
    emit(f"  bundle: {essential_text(args.bundle)}", essential=True)
    ignored = []
    files = load_zip(args.bundle, anomalies=anomalies, member_names=member_names, unsupported=unsupported, ignored_out=ignored)
    if "proof.json" not in files:
        die(EXIT_IO, "ZIP incompleto: falta proof.json; no hay nucleo para comprobar")
    missing_core = CORE_MEMBERS - set(files)
    proof_bytes = files["proof.json"]
    proof = parse_json_bytes(proof_bytes, "proof.json")
    verify_proof_schema(proof)
    uncovered = validate_member_world(files, member_names, proof, anomalies)
    usage_errors = (["ZIP incompleto, faltan: " + terminal_text(sorted(missing_core))]
                    if missing_core else [])
    def stage(fn: Any, *values: Any, **kw: Any) -> Any:
        try:
            return fn(*values, **kw)
        except VerifierUsageError as e:
            usage_errors.append(str(e))
            return None
    manifest_ok = stage(verify_manifest, files, proof) or []
    stage(verify_chat_chain_v2, files, proof)
    stage(verify_msg_sigs, files, proof)
    result = (stage(verify_signatures, proof_bytes, files["signatures.json"], anomalies=anomalies)
              if "signatures.json" in files else None)
    notes, cold_fp = result if result is not None else ([], None)
    # COLD ausente: verify_signatures no muere y devuelve cold_fp None (presente e invalida muere con 2).
    cold_missing = result is not None and cold_fp is None
    stage(verify_content_hash, proof, args.content)
    anomalies.extend(auxiliary_parse_anomalies(files, proof, uncovered))
    for name in ("proof.json", "signatures.json"):
        if any(a.startswith((name + ":", name + ".", name + " /", "\'" + name + "\':")) for a in anomalies):
            uncovered.add(name)
    ots_summary = None
    if not args.skip_ots and "proof.json.ots" in files:
        ots_summary = stage(verify_ots, proof_bytes, files["proof.json.ots"], args.bitcoin_node)
    elif "proof.json.ots" in files:
        # Aun con --skip-ots, hash/perfil locales pueden revelar manipulacion.
        stage(parse_ots_bitcoin_paths, proof_bytes, files["proof.json.ots"])
    if unsupported:
        usage_errors.insert(0, "CONTENEDOR NO SOPORTADO: " + "; ".join(unsupported) +
                            "; NO implica que el bundle sea genuino")
    if not args.skip_ots:
        if args.bitcoin_node:
            emit("  fuente del ancla: RPC del nodo Bitcoin indicado mediante --bitcoin-node")
        else:
            emit("  fuente del ancla: RPC Bitcoin por defecto del CLI ots (configuracion local "
                 "bitcoin.conf; endpoint no identificado por este verificador)")
        emit("  el ancla acota proof.json; la co-firma COLD no tiene fecha atestiguada")
    if ots_summary:
        for path in ots_summary["bitcoin_paths"]:
            emit(f"  OTS Bitcoin: rama confirmada - bloque {terminal_text(path['height'])} - Merkle {terminal_text(path['merkle_root'])}")
        if ots_summary["legacy_calendar_metadata"]:
            emit("  OTS heredado: calendario/ramas pendientes reconocidos por referencia local; "
                 "NO son atestaciones Bitcoin ni contenido verificado")
    emit("  envoltorio: directorios vacios y AppleDouble ._ de __MACOSX se ignoran como metadatos; "
         "cualquier otro contenido de __MACOSX cuenta como miembro")
    emit(f"  version:     {terminal_text(proof.get('v'))}")
    emit(f"  agreement:   {essential_text(proof.get('agreement_id'))}", essential=True)
    emit(f"  title:       {essential_text(proof.get('title'))}", essential=True)
    emit(f"  proof_hash:  {essential_text(hashlib.sha256(proof_bytes).hexdigest())}", essential=True)
    emit(f"  content:     {terminal_text(proof.get('content_hash'))}")
    if proof.get("v") in ("X39-NOTARIA-2", "X39-NOTARIA-3"):
        emit(f"  chat_root:   {terminal_text(proof.get('chat_merkle_root'))}  ({terminal_text(len(json.loads(files['chat_chain.json'])['entries']))} mensajes encadenados)")
    if proof.get("msg_sigs"):
        emit(f"  msg_sigs:    Ed25519 {terminal_text(proof['msg_sigs']['signed'])}/{terminal_text(proof['msg_sigs']['total'])} verificadas; "
             "las claves las declara el propio proof.json y no prueban identidad")
    if cold_fp:
        emit(f"  co-firma:    COLD ML-DSA-87 valida - clave PINEADA {essential_text(cold_fp)}", essential=True)
    elif cold_missing:
        emit("  co-firma:    SIN COLD (ausente): sin atestacion COLD en este paquete", essential=True)
    emit(f"  sealed_at:   {terminal_text(proof.get('sealed_at'))} (declarado en proof.json)")
    if ots_summary:
        for path in ots_summary["bitcoin_paths"]:
            emit(f"  el ancla solo acota: proof.json existia antes del bloque {terminal_text(path['height'])}")
    # Honestidad de cobertura: que ficheros del ZIP respalda este veredicto y cuales no.
    if cold_missing:
        emit("  CONSISTENTE 6 acredita: documento + cadena del formato + ancla Bitcoin; "
             "SIN atestacion COLD; no autoria de cada byte del contenedor", essential=True, approval=True)
    else:
        emit("  VALID 0 acredita: nucleo COLD + documento + cadena del formato + ancla Bitcoin; "
             "no autoria de cada byte del contenedor", essential=True, approval=True)
    emit("  ZIP/JSON: solo ZIP32 STORED/DEFLATE, entradas contiguas y descriptores estandar; "
         "extras UT/ux/UNIX/NTFS y Unicode Path redundante; sin comentarios, enlaces ni ZIP64; "
         "una carpeta comun, directorios vacios y AppleDouble de __MACOSX tolerados; "
         "whitespace de JSON externos permitido; "
         "una COLD valida autentica proof.json byte a byte; verified_at externo no es fecha autenticada")
    if cold_missing:
        emit("  SIN COLD: proof.json comprobado por huella y ancla Bitcoin; sin atestacion COLD")
    else:
        emit("  COLD autentica: todos los bytes y campos de proof.json; no acredita su veracidad")
    emit("  COLD NO autentica: signatures.json (titulo y campos cruzados solo contrastados), "
          "metadatos COLD/WARM externos, nombre/fecha del fichero original, "
          "campos extra de chat_chain.json ni ficheros fuera de proof.files")
    emit("  documento: SHA-256 de --content contrastado con content_hash"
         + (" (sin atestacion COLD)" if cold_missing else " autenticado por COLD"))
    verificados = {"proof.json"}
    parciales = {"signatures.json"}
    if "README.md" in files and "README.md" not in (proof.get("files") or {}):
        parciales.add("README.md")
        emit("  INFO: README de formato heredado; miembro declarado por referencia SHA-256 local "
             "exacta, no por proof.files ni por COLD")
    omitidos = set()
    if args.skip_ots:
        omitidos.add("proof.json.ots")
        uncovered.add("proof.json.ots")
    else:
        parciales.add("proof.json.ots")
    if proof.get("v", "") in ("X39-NOTARIA-2", "X39-NOTARIA-3"):
        parciales.add("chat_chain.json")
    verificados |= set(manifest_ok)
    presentes = member_names
    no_cubiertos = sorted(uncovered | (presentes - verificados - parciales - omitidos))
    emit(f"  verificados: {essential_text(', '.join(sorted(verificados & presentes)))}", essential=True)
    emit(f"  cobertura parcial: {essential_text(', '.join(sorted(parciales - verificados - {'README.md'})))} "
          "(firmas, campos cruzados, cadena y solo rutas OTS Bitcoin confirmadas; "
          "no autentica textos externos)", essential=True)
    if "README.md" in parciales:
        emit("  cobertura README.md: bytes contrastados con referencia SHA-256 local heredada; no firma COLD", essential=True)
    if omitidos:
        emit(f"  omitidos:    {terminal_text(', '.join(sorted(omitidos)))}  (--skip-ots)")
    emit(f"  ignorados: {sum(e['appledouble'] for e in ignored)} AppleDouble, "
         f"{sum(e['directory'] for e in ignored)} directorios vacios, "
         f"{sum(e['usize'] for e in ignored)} bytes", essential=True)
    for entry in ignored:
        emit(f"  ignorado: {essential_text(entry['name'])} ({entry['usize']} bytes)", essential=True)
    if ignored:
        no_cubiertos.append("metadatos/directorios enumerados como ignorados")
    coverage_text = ", ".join(essential_text(name) for name in no_cubiertos)
    if usage_errors:
        coverage_text += ("; " if coverage_text else "") + "contenedor/nombres no soportados: " + "; ".join(usage_errors)
    if coverage_text:
        emit(f"  NO cubiertos: {coverage_text}  (sin hash ni firma que los proteja: informativos, NO son evidencia)", essential=True)
    else:
        emit("  NO cubiertos: ninguno", essential=True)
    candidates = [EXIT_OK]
    if anomalies:
        candidates.append(EXIT_WARNINGS)
    if usage_errors or _output_resource_error:
        candidates.append(EXIT_IO)
    if _output_resource_error:
        usage_errors.append("salida esencial excede recursos; no se emite aprobacion")
    # INVALID ya interrumpe la etapa; nunca se captura para degradarlo a 4.
    final_code = max(candidates, key=VERDICT_PRECEDENCE.__getitem__)
    if final_code == EXIT_IO:
        die(final_code, "; ".join(usage_errors))
    for n in notes:
        emit(f"  INFO:        {n}")
    for anomaly in anomalies:
        emit(f"  ANOMALIA:    {anomaly}")
    if args.skip_ots:
        die(EXIT_OTS, "VERIFICACION INCOMPLETA: OTS NO COMPROBADO (--skip-ots); no se emite VALID")
    if cold_missing:
        # Comprobaciones obligatorias y ancla correctas; sin COLD no hay VALID, incluso sin anomalias.
        emit("  sin co-firma soberana COLD: huella, manifiesto y ancla Bitcoin verificados; "
             "falta la atestacion COLD en este paquete. NO es VALID. Si la co-firma llega despues, "
             "vuelva a verificar", essential=True, final=True)
        emit("CONSISTENTE [6]", essential=True, final=True, approval=True, closure=True)
        sys.exit(EXIT_CONSISTENT)
    if final_code == EXIT_WARNINGS:
        emit("  aprobacion sostenida solo por COLD valida + documento + cadena "
              "(cuando el formato la incluye) + ancla Bitcoin; metadatos externos no autenticados "
              "no quedan aprobados por ese nucleo", essential=True, final=True)
        emit("VALID CON AVISOS [5]", essential=True, final=True, approval=True, closure=True)
        sys.exit(EXIT_WARNINGS)
    emit("VALID [0]", essential=True, final=True, approval=True, closure=True)
    sys.exit(EXIT_OK)


if __name__ == "__main__":
    main()

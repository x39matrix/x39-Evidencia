"""Pruebas criptograficas OpenTimestamps para la Notaria X-39.

Este modulo envuelve el CLI `ots`. NO firma nada: la firma post-cuantica
ML-DSA-87 vive en el backend y la co-firma COLD en la Pi 500 aislada.

HONESTIDAD SOBRE EL ANCLAJE (nunca se miente sobre el sello):
    not_stamped   = no se intento sellar, o el intento fallo.
    pending       = `ots stamp` funciono; el compromiso esta en los calendarios,
                    TODAVIA NO en un bloque de Bitcoin. Lleva `PendingAttestation`.
    anchored_btc  = `ots info` reporta al menos un
                    `BitcoinBlockHeaderAttestation(<bloque>)`. Es la UNICA
                    condicion bajo la que se sube el estado; si hay varias
                    atestaciones se cita la del bloque MAS TEMPRANO.
- Si cualquier operacion falla (red, calendarios, disco, binario ausente) se
  devuelve un honesto `not_stamped`. Jamas se fabrica una prueba.
- MATIZ: `ots info` lee lo que la propia prueba declara. La verificacion
  soberana contra la cadena es `ots verify` contra el nodo Bitcoin propio,
  y ocurre fuera de este modulo.
"""
import os
import asyncio
import base64
import re
import shutil
from pathlib import Path
from typing import Optional, Tuple, List, Dict, Any


# Resolve binary paths at import time so we don't rely on supervisor's PATH.
OTS_BIN = os.environ.get("HWG_OTS_BIN") or shutil.which("ots") or "/root/.venv/bin/ots"

# OTS output workspace (persistent so upgrade can find files later if needed)
OTS_WORK = Path(os.environ.get("HWG_OTS_WORK", "/app/backend/hwg/ots_work"))
OTS_WORK.mkdir(parents=True, exist_ok=True)

# Sovereign calendar (FASE 5). Unset => stock behaviour (public calendars only).
# Verified against otsclient 0.7.2 source: any -c REPLACES the default list,
# so when our calendar is set we must pass all 5 explicitly. `upgrade` ignores
# attestations from calendars outside the default whitelist => --whitelist needed.
OTS_OWN_CALENDAR = os.environ.get("OTS_CALENDAR_URL", "").strip().rstrip("/")
_PUBLIC_CALENDARS = [
    "https://a.pool.opentimestamps.org",
    "https://b.pool.opentimestamps.org",
    "https://a.pool.eternitywall.com",
    "https://ots.btc.catallaxy.com",
]


def _stamp_calendar_args() -> List[str]:
    if not OTS_OWN_CALENDAR:
        return []
    args: List[str] = []
    for url in [OTS_OWN_CALENDAR] + _PUBLIC_CALENDARS:
        args += ["-c", url]
    return args


def _whitelist_args() -> List[str]:
    return ["--whitelist", OTS_OWN_CALENDAR] if OTS_OWN_CALENDAR else []


_BTC_BLOCK_RE = re.compile(r"BitcoinBlockHeaderAttestation\s*\(\s*(\d+)\s*\)")
_PENDING_RE = re.compile(r"PendingAttestation\s*\(\s*['\"]?(https?://[^'\")\s]+)")


def _write_ots_pair(sha256_hex: str, payload: bytes,
                    ots_bytes: Optional[bytes] = None) -> Tuple[Path, Path]:
    """Persist payload + optional .ots into OTS_WORK for later upgrade."""
    payload_path = OTS_WORK / f"{sha256_hex}.txt"
    ots_path = OTS_WORK / f"{sha256_hex}.txt.ots"
    payload_path.write_bytes(payload)
    if ots_bytes is not None:
        ots_path.write_bytes(ots_bytes)
    return payload_path, ots_path


async def _run_ots(args: List[str], timeout: int) -> Tuple[int, bytes, bytes]:
    """Run the `ots` CLI without blocking the event loop. Raises on timeout."""
    proc = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise
    return proc.returncode, stdout, stderr


async def ots_stamp(sha256_hex: str, payload: bytes,
                    timeout: int = 60) -> Tuple[Optional[str], List[str]]:
    """Timestamp `payload`. Returns (ots_proof_b64, calendars_reported).
    (None, []) if the stamp fails (network, calendars). NEVER raises."""
    try:
        payload_path, ots_path = _write_ots_pair(sha256_hex, payload)
        rc, out, err = await _run_ots(
            [OTS_BIN, "stamp"] + _stamp_calendar_args() + [str(payload_path)], timeout)
    except Exception as e:
        # Contrato de esta funcion: NUNCA lanza. Binario ots ausente, disco lleno o
        # timeout degradan a "sin ancla" (not_stamped), que /ots/refresh reintenta;
        # jamas impiden que el acuerdo llegue a sellarse.
        print(f"[OTS] ERROR: stamp de {sha256_hex[:16]} fallo ({type(e).__name__}: {e}); "
              f"se sella como not_stamped.", flush=True)
        return None, []
    if rc != 0 or not ots_path.exists():
        return None, []
    ots_b64 = base64.b64encode(ots_path.read_bytes()).decode()
    calendars: List[str] = []
    for line in (out.decode(errors="replace")
                 + err.decode(errors="replace")).splitlines():
        m = re.search(r"(https?://\S+)", line)
        if m:
            calendars.append(m.group(1))
    return ots_b64, calendars


async def ots_info_probe(sha256_hex: str, ots_b64: str,
                         payload: bytes) -> Dict[str, Any]:
    """Run `ots info` on a proof. Returns dict:
      { ots_status, btc_block, pending_calendars, raw_info_snippet }
    - anchored_btc iff at least one BitcoinBlockHeaderAttestation appears.
    - Otherwise pending if PendingAttestation appears.
    - Otherwise not_stamped (proof malformed / missing).
    """
    _, ots_path = _write_ots_pair(sha256_hex, payload, base64.b64decode(ots_b64))
    try:
        _, out, err = await _run_ots([OTS_BIN, "info", str(ots_path)], 30)
        text = out.decode(errors="replace") + err.decode(errors="replace")
    except asyncio.TimeoutError:
        text = ""
    btc_matches = _BTC_BLOCK_RE.findall(text)
    pending_matches = _PENDING_RE.findall(text)
    if btc_matches:
        status = "anchored_btc"
        btc_block: Optional[int] = min(int(b) for b in btc_matches)
    elif pending_matches:
        status = "pending"
        btc_block = None
    else:
        status = "not_stamped"
        btc_block = None
    return {
        "ots_status": status,
        "btc_block": btc_block,
        "pending_calendars": pending_matches,
        "raw_info_snippet": text[:1500],
    }


async def ots_upgrade(sha256_hex: str, ots_b64: str,
                      payload: bytes, timeout: int = 60) -> Tuple[str, Dict[str, Any]]:
    """Attempt `ots upgrade` on a pending proof. Returns (new_ots_b64, info_probe).
    If nothing changed, returns the original b64 + current info probe."""
    _, ots_path = _write_ots_pair(sha256_hex, payload, base64.b64decode(ots_b64))
    try:
        await _run_ots([OTS_BIN] + _whitelist_args() + ["upgrade", str(ots_path)], timeout)
    except asyncio.TimeoutError:
        pass
    # Clean any .bak file ots writes on successful upgrade
    bak = Path(str(ots_path) + ".bak")
    if bak.exists():
        try:
            bak.unlink()
        except OSError:
            pass
    new_b64 = base64.b64encode(ots_path.read_bytes()).decode() if ots_path.exists() else ots_b64
    info = await ots_info_probe(sha256_hex, new_b64, payload)
    return new_b64, info

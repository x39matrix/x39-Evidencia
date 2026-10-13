"""Regresión: integridad de bundles con chat_hash HMAC-SHA256.

Ningún verificador recalcula chat_hash: el ZIP no lleva ni los mensajes ni la sal por
acuerdo (a propósito). chat_hash viaja dentro de proof.json y queda cubierto por
proof_hash, la co-firma ML-DSA y el ancla OTS, como cualquier otro campo.

Los ZIP de testdata/e2e_chat_hmac_v*.zip salen de un backend local de pruebas
(12/10/2026) sin COLD y con OTS sustituido por un marcador: no pueden aprobarse.

    python3 -m pytest tests/test_verificadores_chat_hash.py
"""
import io
import json
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

RAIZ = Path(__file__).resolve().parent.parent
GENERAL = RAIZ / "verify_bundle.py"
V1_1 = RAIZ / "verify_bundle_v1_1.py"
ZIPS = [RAIZ / "testdata" / "e2e_chat_hmac_v2.zip", RAIZ / "testdata" / "e2e_chat_hmac_v1.zip"]


def _run(script, bundle, *extra):
    return subprocess.run([sys.executable, "-I", str(script), str(bundle), *extra],
                          capture_output=True, text=True, timeout=60)


def _alterar_chat_hash(src: Path, dst: Path) -> None:
    """Copia el ZIP cambiando un carácter de chat_hash en proof.json (mismos bytes salvo ese)."""
    with zipfile.ZipFile(src) as zin, zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zout:
        for info in zin.infolist():
            data = zin.read(info.filename)
            if info.filename == "proof.json":
                h = json.loads(data)["chat_hash"]
                otro = ("0" if h[0] != "0" else "1") + h[1:]
                data = data.replace(h.encode(), otro.encode())
            zout.writestr(info, data)


@pytest.mark.parametrize("bundle", ZIPS, ids=lambda p: p.stem)
def test_bundle_lleva_hmac(bundle):
    with zipfile.ZipFile(bundle) as z:
        proof = json.loads(z.read("proof.json"))
        assert proof["chat_hash_alg"] == "hmac-sha256"
        assert len(proof["chat_hash"]) == 64
        # La sal nunca sale del servidor.
        assert all(b"chat_salt" not in z.read(n) for n in z.namelist())


@pytest.mark.parametrize("bundle", ZIPS, ids=lambda p: p.stem)
def test_general_rechaza_bundle_sin_cold(bundle):
    r = _run(GENERAL, bundle, "--skip-ots")
    assert r.returncode == 2, r.stderr
    assert r.stderr.startswith("INVALID[2]")
    assert "COLD" in r.stderr


@pytest.mark.parametrize("bundle", ZIPS, ids=lambda p: p.stem)
def test_v1_1_pasa_integridad_y_para_en_cold(bundle):
    # El estricto exige COLD: sin ella sale con 2 (firma), no con 1 (integridad).
    r = _run(V1_1, bundle)
    assert r.returncode == 2, r.stderr
    assert "COLD" in r.stderr


@pytest.mark.parametrize("script", [GENERAL, V1_1], ids=["general", "v1_1"])
def test_chat_hash_alterado_falla_integridad(script, tmp_path):
    malo = tmp_path / "alterado.zip"
    _alterar_chat_hash(ZIPS[0], malo)
    extra = ["--skip-ots"] if script == GENERAL else []
    r = _run(script, malo, *extra)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "proof_hash mismatch" in r.stderr

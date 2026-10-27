"""Poda de la prueba .ots al servirla (backend/hwg/crypto.py: ots_prune_pending).

Hallazgo del 27/10/2026: el .ots que guarda y sirve la API conserva las PendingAttestation
de los calendarios junto a las atestaciones Bitcoin (`ots upgrade` nunca las retira), y el
verificador publicado solo tolera eso en los dos .ots fichados en LEGACY_METADATA. Todo
acuerdo nuevo anclado daba INVALID[3] ".ots con ramas/appends sobrantes sin Bitcoin" aunque
el ancla fuera real. La poda deja solo las rutas Bitcoin, sin consultar nada ni inventar nada.

Offline: sin red, sin firmar, sin nodo. El verificador se carga con el fixture habitual
(red y subprocess bloqueados) y `ots verify` se simula como en las demas pruebas.
"""
import copy
import hashlib
import importlib.util
import io
import subprocess

import pytest

from test_verificador_estricto import ROOT, bundle, content, verifier, run_main


@pytest.fixture
def poda(tmp_path, monkeypatch):
    # crypto.py crea su carpeta de trabajo al importarse: que sea temporal, nunca /app.
    monkeypatch.setenv("HWG_OTS_WORK", str(tmp_path / "ots_work"))
    spec = importlib.util.spec_from_file_location("hwg_crypto_local", ROOT / "backend/hwg/crypto.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.ots_prune_pending


def censo(ots_bytes):
    from opentimestamps.core.timestamp import DetachedTimestampFile
    from opentimestamps.core.serialize import StreamDeserializationContext
    from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation
    d = DetachedTimestampFile.deserialize(StreamDeserializationContext(io.BytesIO(ots_bytes)))
    pend = sum(1 for _, a in d.timestamp.all_attestations() if isinstance(a, PendingAttestation))
    btc = {(msg, a.height) for msg, a in d.timestamp.all_attestations()
           if isinstance(a, BitcoinBlockHeaderAttestation)}
    return d, pend, btc


def ots_sintetico(pendientes=True, bitcoin=True):
    """Arbol como el que deja `ots upgrade`: por calendario, hoja pendiente + rama Bitcoin."""
    from opentimestamps.core.timestamp import Timestamp, DetachedTimestampFile
    from opentimestamps.core.op import OpSHA256, OpAppend, OpPrepend
    from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation
    from opentimestamps.core.serialize import BytesSerializationContext
    t = Timestamp(hashlib.sha256(b"proof.json de prueba").digest())
    for i, (uri, height) in enumerate([("https://alice.btc.calendar.opentimestamps.org", 966105),
                                        ("https://bob.btc.calendar.opentimestamps.org", 966113)]):
        cal = t.ops.add(OpAppend(bytes([i + 1]) * 8)).ops.add(OpSHA256())
        if pendientes:
            cal.attestations.add(PendingAttestation(uri))
        if bitcoin:
            cal.ops.add(OpPrepend(bytes([i + 9]) * 4)).ops.add(OpSHA256()).attestations.add(
                BitcoinBlockHeaderAttestation(height))
    ctx = BytesSerializationContext()
    DetachedTimestampFile(OpSHA256(), t).serialize(ctx)
    return ctx.getbytes()


def test_ots_real_del_demo_queda_sin_pendientes_y_con_todos_los_bloques(poda, bundle):
    original = bundle["proof.json.ots"]
    d0, pend0, btc0 = censo(original)
    assert pend0 == 4 and {h for _, h in btc0} == {957242, 957244, 957246}
    podado = poda(original)
    d1, pend1, btc1 = censo(podado)
    assert pend1 == 0 and btc1 == btc0, "mismas hojas Bitcoin (mensaje y bloque), ninguna pendiente"
    assert d1.file_digest == d0.file_digest and type(d1.file_hash_op) is type(d0.file_hash_op)
    assert len(podado) < len(original)


def test_poda_es_pura_determinista_e_idempotente(poda):
    raw = ots_sintetico()
    a, b = poda(raw), poda(raw)
    assert a == b and poda(a) == a
    assert censo(a)[1] == 0 and {h for _, h in censo(a)[2]} == {966105, 966113}


def test_prueba_aun_pendiente_se_sirve_intacta(poda):
    raw = ots_sintetico(pendientes=True, bitcoin=False)
    assert poda(raw) == raw


def test_bytes_ilegibles_se_sirven_intactos_sin_lanzar(poda, capsys):
    basura = b"OTS-FALSO-PRUEBA-LOCAL:0000"
    assert poda(basura) == basura
    assert "poda de la prueba no aplicada" in capsys.readouterr().out


def test_ots_podado_cumple_el_perfil_cerrado_del_verificador(poda, verifier, bundle):
    # El .ots original del demo solo pasa por LEGACY_METADATA (surplus=True); el podado,
    # por si mismo (surplus=False), que es lo que necesita cualquier acuerdo nuevo.
    proof = bundle["proof.json"]
    _, _, surplus_original = verifier.parse_ots_bitcoin_paths(proof, bundle["proof.json.ots"])
    assert surplus_original is True
    podado = poda(bundle["proof.json.ots"])
    detached, rutas, surplus = verifier.parse_ots_bitcoin_paths(proof, podado)
    assert surplus is False and sorted(a.height for _, a, _ in rutas) == [957242, 957244, 957246]


def test_bundle_con_ots_podado_verifica_sin_lista_blanca(poda, verifier, bundle, content, tmp_path, monkeypatch, capsys):
    files = copy.deepcopy(bundle)
    files["proof.json.ots"] = poda(files["proof.json.ots"])
    monkeypatch.setattr(subprocess, "run", lambda command, **kw: subprocess.CompletedProcess(command, 0, "", ""))
    code, out = run_main(verifier, files, tmp_path, monkeypatch, capsys, content, skip=False)
    assert code == 0 and out.out.endswith("VALID [0]\n[FIN VEREDICTO]")
    assert "OTS heredado" not in out.out, "sin hojas pendientes no hace falta la referencia local"
    assert out.out.count("OTS Bitcoin: rama confirmada") == 3

"""CONSISTENTE [6]: COLD AUSENTE con las comprobaciones obligatorias correctas.

Offline: COLD/documento reales del bundle de prueba, OTS simulado, sin red, sin firmar.
La co-firma COLD llega despues del sellado (sneakernet); entre medias, un paquete
legitimo no tiene COLD y NO debe leerse como falsificado. Tampoco es VALID: falta su
atestacion COLD. Una COLD presente pero vacia, falsa o no reconocida sigue siendo INVALID[2].
"""
import contextlib
import io
import json
import subprocess
import sys

import pytest

from test_verificador_estricto import ROOT, bundle, content, verifier, run_main


def sin_cold(files, value='ausente'):
    sigs = json.loads(files['signatures.json'])
    if value == 'ausente':
        sigs.pop('cold', None)
    else:
        sigs['cold'] = value
    files['signatures.json'] = json.dumps(sigs).encode()
    return files


def ots_ok(monkeypatch):
    monkeypatch.setattr(subprocess, 'run', lambda command, **kw: subprocess.CompletedProcess(command, 0, '', ''))


@pytest.mark.parametrize('forma', ['ausente', None], ids=['sin clave cold', 'cold: null'])
def test_cold_ausente_todo_correcto_es_consistente(verifier, bundle, content, tmp_path, monkeypatch, capsys, forma):
    ots_ok(monkeypatch)
    code, out = run_main(verifier, sin_cold(bundle, forma), tmp_path, monkeypatch, capsys, content, skip=False)
    assert code == 6
    assert out.out.endswith('CONSISTENTE [6]\n[FIN VEREDICTO]')
    assert not out.err
    assert 'SIN co-firma COLD' in out.out and 'SIN COLD: proof.json comprobado' in out.out
    assert 'CONSISTENTE 6 acredita' in out.out
    assert 'VALID [0]' not in out.out and 'VALID CON AVISOS' not in out.out
    assert 'COLD ML-DSA-87 valida' not in out.out and 'VALID 0 acredita' not in out.out


def test_cold_ausente_con_skip_ots_nunca_es_consistente(verifier, bundle, content, tmp_path, monkeypatch, capsys):
    code, out = run_main(verifier, sin_cold(bundle), tmp_path, monkeypatch, capsys, content, skip=True)
    assert code == 3 and 'OTS NO COMPROBADO' in out.err
    assert 'CONSISTENTE' not in out.out.splitlines()[-2:] and 'CONSISTENTE [6]' not in out.out


def test_cold_ausente_ots_fallido_es_3(verifier, bundle, content, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(subprocess, 'run', lambda command, **kw: subprocess.CompletedProcess(command, 1, '', 'ancla falsa'))
    code, out = run_main(verifier, sin_cold(bundle), tmp_path, monkeypatch, capsys, content, skip=False)
    assert code == 3 and out.err.startswith('INVALID[3]')
    assert 'CONSISTENTE [6]' not in out.out


def test_cold_ausente_documento_alterado_es_1(verifier, bundle, content, tmp_path, monkeypatch, capsys):
    ots_ok(monkeypatch)
    content.write_bytes(b'documento alterado')
    code, out = run_main(verifier, sin_cold(bundle), tmp_path, monkeypatch, capsys, content, skip=False)
    assert code == 1 and 'content_hash mismatch' in out.err
    assert 'CONSISTENTE [6]' not in out.out


def test_cold_ausente_sin_content_es_4(verifier, bundle, tmp_path, monkeypatch, capsys):
    ots_ok(monkeypatch)
    code, out = run_main(verifier, sin_cold(bundle), tmp_path, monkeypatch, capsys, None, skip=False)
    assert code == 4 and 'DOCUMENTO NO COMPROBADO' in out.err
    assert 'CONSISTENTE [6]' not in out.out


def test_cold_ausente_con_warm_rota_sigue_consistente_con_anomalia(verifier, bundle, content, tmp_path, monkeypatch, capsys):
    ots_ok(monkeypatch)
    files = sin_cold(bundle)
    sigs = json.loads(files['signatures.json']); sigs['warm'] = 'firma heredada malformada'
    files['signatures.json'] = json.dumps(sigs).encode()
    code, out = run_main(verifier, files, tmp_path, monkeypatch, capsys, content, skip=False)
    # 6 manda sobre 5: la anomalia se imprime, pero el veredicto es CONSISTENTE, no VALID CON AVISOS.
    assert code == 6 and out.out.endswith('CONSISTENTE [6]\n[FIN VEREDICTO]')
    assert 'ANOMALIA:' in out.out and 'WARM: NO VERIFICA' in out.out
    assert 'VALID CON AVISOS' not in out.out


@pytest.mark.parametrize('valor', [{}, False, 'texto', 0], ids=['vacio', 'false', 'texto', 'cero'])
def test_cold_presente_pero_invalida_sigue_siendo_2(verifier, bundle, content, tmp_path, monkeypatch, capsys, valor):
    ots_ok(monkeypatch)
    code, out = run_main(verifier, sin_cold(bundle, valor), tmp_path, monkeypatch, capsys, content, skip=False)
    assert code == 2 and out.err.startswith('INVALID[2]') and 'COLD' in out.err
    assert 'CONSISTENTE' not in out.out


def test_cold_ausente_salida_truncada_no_deja_consistente_a_medias(verifier, bundle, content, tmp_path, monkeypatch):
    import zipfile
    ots_ok(monkeypatch)
    files = sin_cold(bundle)
    path = tmp_path / 'prueba.zip'
    with zipfile.ZipFile(path, 'w') as z:
        for name, data in files.items(): z.writestr(name, data)
    monkeypatch.setattr(sys, 'argv', ['verificador', str(path), '--content', str(content)])

    class Partial(io.StringIO):
        def write(self, text):
            if text.startswith('CONSISTENTE'):
                super().write(text[:7])
                raise OSError('disco lleno en veredicto')
            return super().write(text)
    out = Partial()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        with pytest.raises(SystemExit) as exc: verifier.main()
    assert exc.value.code == 4
    assert out.getvalue().endswith('ERROR E/S [4]: salida incompleta; no se emite aprobacion\n[FIN VEREDICTO]')
    assert not out.getvalue().endswith('CONSISTENTE [6]\n')

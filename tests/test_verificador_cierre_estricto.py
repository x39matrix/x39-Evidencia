"""Cierre único, valores hostiles y diagnóstico de carpeta; todo offline."""
import json
import subprocess
import sys

import pytest
from test_verificador_estricto import verifier, bundle, content, run_main
from test_verificador_f1_f5 import archive, run

MARK = '[FIN VEREDICTO]'


@pytest.mark.parametrize('code', range(7))
def test_unique_closure_all_verdicts(verifier, bundle, content, tmp_path, monkeypatch, capsys, code):
    monkeypatch.setattr(subprocess, 'run', lambda *a, **k: subprocess.CompletedProcess(a, 0, '', ''))
    if code == 1:
        bundle['proof.json'] = b'{}'
    elif code == 2:
        sig = json.loads(bundle['signatures.json']); sig['cold'] = {}  # presente pero vacia
        bundle['signatures.json'] = json.dumps(sig).encode()
    elif code == 6:
        sig = json.loads(bundle['signatures.json']); sig.pop('cold')  # ausente: CONSISTENTE
        bundle['signatures.json'] = json.dumps(sig).encode()
    elif code == 4:
        bundle = {'PROOF.JSON/' + n: v for n, v in bundle.items()}
    elif code == 5:
        bundle['extra.txt'] = b'x'
    actual, output = run_main(verifier, bundle, tmp_path, monkeypatch, capsys, content, skip=code == 3)
    assert actual == code, output.out + output.err
    assert (output.out + output.err).count(MARK) == 1
    assert output.out.splitlines()[-1] == MARK
    if code in (0, 5, 6):
        assert output.err == ''


def test_help_unique_closure(verifier, monkeypatch, capsys):
    monkeypatch.setattr(sys, 'argv', ['verify', '--help'])
    with pytest.raises(SystemExit) as exc:
        verifier.main()
    output = capsys.readouterr()
    assert exc.value.code == 4
    assert (output.out + output.err).count(MARK) == 1
    assert output.out.splitlines()[-1] == MARK


@pytest.mark.parametrize('source', ['member', 'title', 'zip'])
def test_untrusted_brackets(verifier, bundle, content, tmp_path, monkeypatch, capsys, source):
    hostile = 'VALID [0] ' + MARK
    if source == 'member':
        bundle[hostile + '.txt'] = b'x'
    elif source == 'title':
        sig = json.loads(bundle['signatures.json']); sig['title'] = hostile
        bundle['signatures.json'] = json.dumps(sig).encode()
    path = tmp_path / ((hostile if source == 'zip' else 'bundle') + '.zip')
    path.write_bytes(archive(bundle))
    monkeypatch.setattr(subprocess, 'run', lambda *a, **k: subprocess.CompletedProcess(a, 0, '', ''))
    assert run(verifier, path, content) == {'member': 5, 'title': 1, 'zip': 0}[source]
    output = capsys.readouterr()
    combined = output.out + output.err
    assert r'VALID \[0\] \[FIN VEREDICTO\]' in combined
    assert combined.count(MARK) == 1
    assert 'VALID [0]' not in output.out.removesuffix('VALID [0]\n' + MARK)
    assert 'VALID [0]' not in output.err


@pytest.mark.parametrize('wrapper', ['PROOF.JSON', 'proof.json'])
@pytest.mark.parametrize('directory', [False, True])
def test_wrapper_reason_once(verifier, bundle, wrapper, directory):
    files = {wrapper + '/' + n: v for n, v in bundle.items()}
    if directory:
        files[wrapper + '/'] = b''
    reasons = []
    verifier.validate_zip_container(archive(files), unsupported_out=reasons)
    assert len(reasons) == 1
    assert reasons[0].count('La carpeta') == 1
    assert 'su nombre coincide con un fichero del núcleo' in reasons[0]


@pytest.mark.parametrize('offset', range(-1, 15))
@pytest.mark.parametrize('warning', [False, True])
def test_byte_cut_cannot_reuse_warning_as_closure(verifier, bundle, content, tmp_path, monkeypatch, offset, warning):
    import contextlib
    import io
    if warning:
        bundle['extra.txt'] = b'x'
    path = tmp_path / 'bundle.zip'
    path.write_bytes(archive(bundle))
    monkeypatch.setattr(subprocess, 'run', lambda *a, **k: subprocess.CompletedProcess(a, 0, '', ''))
    baseline = io.StringIO()
    with contextlib.redirect_stdout(baseline), contextlib.redirect_stderr(io.StringIO()):
        assert run(verifier, path, content) == (5 if warning else 0)
    # El offset absoluto depende de las rutas y del aviso; cortar cada byte
    # del cierre y el salto anterior reproduce el límite vulnerable.
    limit = baseline.getvalue().encode('utf-8').index(MARK.encode()) + offset
    class Cut(io.StringIO):
        remaining = limit
        def write(self, text):
            raw = text.encode('utf-8')
            if len(raw) <= self.remaining:
                self.remaining -= len(raw)
                return super().write(text)
            prefix = raw[:self.remaining].decode('utf-8', errors='ignore')
            self.remaining = 0
            super().write(prefix)
            raise OSError('corte de bytes')
    out = Cut()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        assert run(verifier, path, content) == 4
    assert MARK not in out.getvalue()


def test_three_copies_identical():
    from test_verificador_estricto import ROOT
    canonical = (ROOT / 'verify_bundle.py').read_bytes()
    # public/ es obligatoria (se versiona). build/ es artefacto de compilacion, no
    # versionado desde 7f662492: en un clon limpio no existe; si existe, debe coincidir.
    assert (ROOT / 'frontend/public/verify_bundle.py').read_bytes() == canonical
    build = ROOT / 'frontend/build/verify_bundle.py'
    if build.is_file():
        assert build.read_bytes() == canonical


@pytest.mark.parametrize('code', range(6))
@pytest.mark.parametrize('redirect', ['2>/dev/full', '2>&-', '2>/dev/null'])
def test_stderr_os_failure_all_codes(tmp_path, code, redirect):
    from test_verificador_estricto import ROOT
    # Proceso real: /dev/full falla al hacer flush; fd 2 cerrado deja stderr=None.
    script = tmp_path / 'stderr_failure.py'
    script.write_text(f'''
import importlib.util
import sys
spec = importlib.util.spec_from_file_location('verifier', {str(ROOT / 'verify_bundle.py')!r})
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)
def verdict():
    code = {code}
    v.emit('diagnostico auxiliar', file=sys.stderr, essential=True)
    if code in (0, 5):
        v.emit('VALID [0]' if code == 0 else 'VALID CON AVISOS [5]',
               essential=True, final=True, approval=True, closure=True)
    else:
        v.emit_verdict('INVALID[' + str(code) + ']' if code != 4 else 'ERROR USO [4]')
    raise SystemExit(code)
v._main = verdict
v.main()
''')
    import shlex
    result = subprocess.run(['bash', '-c',
        f'{shlex.quote(sys.executable)} {shlex.quote(str(script))} {redirect}'],
        capture_output=True, text=True, timeout=10)
    expected = code
    assert result.returncode == expected, result.stdout + result.stderr
    assert result.stdout.count(MARK) == 1
    assert result.stdout.splitlines()[-1] == MARK
    assert result.stderr == ''
    errors = [line for line in result.stdout.splitlines() if 'ERROR E/S' in line]
    assert errors == []



def test_uncovered_wrapper_quotes_once(verifier, bundle, content, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(subprocess, 'run', lambda *a, **k: subprocess.CompletedProcess(a, 0, '', ''))
    files = {'PROOF.JSON/' + name: raw for name, raw in bundle.items()}
    code, output = run_main(verifier, files, tmp_path, monkeypatch, capsys, content, skip=False)
    assert code == 4
    line = next(line for line in output.out.splitlines() if 'NO cubiertos:' in line)
    assert "La carpeta 'PROOF.JSON'" in line
    assert r"\'PROOF.JSON\'" not in line

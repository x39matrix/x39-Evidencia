"""Regresiones F1–F5 offline; fixtures copiados, arnés auditor intacto."""
import contextlib
import hashlib
import importlib.util
import io
import struct
import subprocess
import sys
import zipfile
import zlib
from pathlib import Path

import pytest
from test_verificador_estricto import ROOT, verifier, bundle, content

REAL_RUN = subprocess.run
FIXTURES = sorted((ROOT / 'testdata/verificador-f1').glob('*.zip'))


def archive(files, compression=zipfile.ZIP_STORED):
    out = io.BytesIO()
    with zipfile.ZipFile(out, 'w', compression=compression) as z:
        for name, data in files.items():
            z.writestr(name, data)
    return out.getvalue()


def decision(module, raw):
    try:
        module.validate_zip_container(raw)
        return 0
    except module.VerifierUsageError:
        return 4
    except SystemExit as exc:
        return exc.code


def test_public_copy_sha256():
    assert hashlib.sha256((ROOT/'verify_bundle.py').read_bytes()).digest() == hashlib.sha256((ROOT/'frontend/public/verify_bundle.py').read_bytes()).digest()


@pytest.mark.parametrize('path', FIXTURES, ids=lambda p: p.stem)
@pytest.mark.parametrize('omit_directories', [False, True])
def test_audit_containers(verifier, path, omit_directories):
    raw = path.read_bytes()
    if omit_directories:
        output = io.BytesIO()
        with zipfile.ZipFile(io.BytesIO(raw)) as source, zipfile.ZipFile(output, 'w') as target:
            for info in source.infolist():
                if not info.is_dir():
                    target.writestr(info, source.read(info))
        raw = output.getvalue()
    assert decision(verifier, raw) == 4


@pytest.mark.parametrize('name,expected', [('evidencia ',4),('evidencia.',4),('CON',4),('aux',4),('CON1',0)])
@pytest.mark.parametrize('directory', [False, True])
def test_wrapper_single_criterion(verifier, name, expected, directory):
    files = {name+'/proof.json': b'{}', name+'/signatures.json': b'{}'}
    if directory:
        files[name+'/'] = b''
    assert decision(verifier, archive(files)) == expected


def test_wrapper_collision(verifier):
    assert decision(verifier, archive({'aux/AUX':b'x', 'aux/proof.json':b'{}'})) == 1


@pytest.mark.parametrize('size', [4, 64, 1024])
def test_broken_deflate_after_magic(verifier, size, tmp_path):
    # Non-final STORED DEFLATE block followed by forbidden BTYPE=3.
    data = b'\x00\x05\x16\x07' + bytes(range(1, 251)) * 5
    data = data[:size]
    compressed = b'\x00' + struct.pack('<HH', len(data), len(data)^0xffff) + data + b'\x07'
    raw = bytearray(archive({'proof.json':b'{}', '__MACOSX/._proof.json':compressed}))
    cd = struct.unpack_from('<I', raw, len(raw)-6)[0]
    first_len = struct.unpack_from('<H',raw,cd+28)[0]
    central = cd + 46 + first_len
    local = struct.unpack_from('<I',raw,central+42)[0]
    struct.pack_into('<H',raw,central+6,20); struct.pack_into('<H',raw,central+10,8)
    struct.pack_into('<I',raw,central+24,len(data))
    struct.pack_into('<H',raw,local+4,20); struct.pack_into('<H',raw,local+8,8)
    struct.pack_into('<I',raw,local+22,len(data))
    assert decision(verifier, bytes(raw)) == 1
    p = tmp_path / "broken.zip"
    p.write_bytes(raw)
    result = REAL_RUN(["node", str(ROOT/"docs/zip-profile-reference.mjs"), str(p)], capture_output=True, text=True, timeout=5)
    assert result.returncode == 1, result.stdout + result.stderr


def run(module, path, document):
    sys.argv = ['verify',str(path),'--content',str(document)]
    with pytest.raises(SystemExit) as exc:
        module.main()
    return exc.value.code


@pytest.mark.parametrize('directory',[False,True])
def test_unsupported_has_no_approval(verifier,bundle,content,tmp_path,monkeypatch,capsys,directory):
    files={'aux/'+n:v for n,v in bundle.items()}
    if directory: files['aux/']=b''
    p=tmp_path/'wrapped.zip';p.write_bytes(archive(files))
    monkeypatch.setattr(subprocess,'run',lambda *a,**k:subprocess.CompletedProcess(a,0,'',''))
    assert run(verifier,p,content)==4
    out=capsys.readouterr()
    assert 'VALID 0 acredita' not in out.out
    assert 'NO cubiertos: ninguno' not in out.out
    assert 'Vuelva a comprimir los ficheros sin carpeta' in out.out
    assert '[FIN VEREDICTO]' in out.out


@pytest.mark.parametrize('warning',[False,True])
@pytest.mark.parametrize('raises',[False,True])
def test_cut_at_old_final_newline(verifier,bundle,content,tmp_path,monkeypatch,warning,raises):
    if warning: bundle['extra.txt']=b'x'
    p=tmp_path/'good.zip';p.write_bytes(archive(bundle))
    monkeypatch.setattr(subprocess,'run',lambda *a,**k:subprocess.CompletedProcess(a,0,'',''))
    class Cut(io.StringIO):
        def write(self,text):
            if text.startswith('VALID'):
                prefix=text.split('\n',1)[0]
                super().write(prefix)
                if raises: raise OSError('corte antes del salto')
                return len(prefix)
            return super().write(text)
    out=Cut()
    with contextlib.redirect_stdout(out),contextlib.redirect_stderr(io.StringIO()):
        assert run(verifier,p,content)==4
    assert not out.getvalue().endswith('VALID [0]\n[FIN VEREDICTO]')
    assert not out.getvalue().endswith('VALID CON AVISOS [5]\n[FIN VEREDICTO]')


def test_fixture_count():
    assert len(FIXTURES) == 58
    assert sum(p.name.startswith('G_') for p in FIXTURES) == 48


@pytest.mark.parametrize('directory',[False,True])
@pytest.mark.parametrize('warning',[False,True])
def test_con1_approval_and_closure(verifier,bundle,content,tmp_path,monkeypatch,capsys,directory,warning):
    if warning: bundle['extra.txt']=b'x'
    files={'CON1/'+n:v for n,v in bundle.items()}
    if directory: files['CON1/']=b''
    p=tmp_path/'con1.zip';p.write_bytes(archive(files))
    monkeypatch.setattr(subprocess,'run',lambda *a,**k:subprocess.CompletedProcess(a,0,'',''))
    assert run(verifier,p,content)==(5 if warning else 0)
    out=capsys.readouterr().out
    assert 'VALID 0 acredita' in out
    assert out.endswith(('VALID CON AVISOS [5]' if warning else 'VALID [0]')+'\n[FIN VEREDICTO]')


def test_valid_deflate_appledouble(verifier):
    raw=archive({'proof.json':b'{}','__MACOSX/._proof.json':b'\x00\x05\x16\x07'+bytes(range(256))*4},zipfile.ZIP_DEFLATED)
    entries=verifier.validate_zip_container(raw)
    assert next(e for e in entries if e['macosx'])['appledouble']

@pytest.mark.parametrize('name', ['proof.json', 'PROOF.JSON', 'prооf.json', 'extra.txt'])
@pytest.mark.parametrize('directory', [False, True])
def test_wrapper_core_and_member(verifier, name, directory):
    files = {name+'/proof.json': b'{}', name+'/extra.txt': b'x'}
    if directory: files[name+'/'] = b''
    assert decision(verifier, archive(files)) == 4

@pytest.mark.parametrize('code', [1, 2, 3, 4])
def test_error_verdict_stdout(verifier, monkeypatch, capsys, code):
    monkeypatch.setattr(verifier, '_main', lambda: verifier.die(code, 'prueba'))
    with pytest.raises(SystemExit) as exc: verifier.main()
    assert exc.value.code == code
    out = capsys.readouterr()
    assert f'[{code}]' in out.out
    assert out.out.endswith('[FIN VEREDICTO]')
    assert 'marca de cierre final' in out.out
    assert f'[{code}]' in out.err

@pytest.mark.parametrize('name', ['proof.json', 'PROOF.JSON', 'prооf.json', 'extra.txt'])
def test_wrapper_cli_four(verifier, bundle, content, tmp_path, monkeypatch, capsys, name):
    files = {name+'/'+n: v for n, v in bundle.items()}
    files[name+'/'] = b''
    files[name+'/extra.txt'] = b'x'
    path = tmp_path/'wrapped.zip'
    path.write_bytes(archive(files))
    monkeypatch.setattr(subprocess, 'run', lambda *a, **k: subprocess.CompletedProcess(a, 0, '', ''))
    assert run(verifier, path, content) == 4
    out = capsys.readouterr()
    assert '[4]' in out.out and '[4]' in out.err
    assert out.out.endswith('[FIN VEREDICTO]')


def test_stderr_failure_still_stdout_four(verifier, monkeypatch):
    class Broken(io.StringIO):
        def write(self, text): raise OSError('fallo stderr')
    monkeypatch.setattr(verifier, '_main', lambda: verifier.die(4, 'prueba'))
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(Broken()):
        with pytest.raises(SystemExit) as exc: verifier.main()
    assert exc.value.code == 4
    assert '[4]' in out.getvalue()
    assert out.getvalue().endswith('[FIN VEREDICTO]')

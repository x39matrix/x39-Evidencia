"""Regresiones locales del extra UNIX y de la salida; sin red ni firmas nuevas."""
import struct
import subprocess
import zipfile
import zlib

import pytest
from test_verificador_estricto import ROOT, verifier, bundle, content
from test_verificador_f1_f5 import run

ORIGINAL_RUN = subprocess.run

FIXTURE = ROOT / 'testdata/bundle_unix_5855_sintetico.zip'


def unix_archive(files, local=None, central=None, flags=0x800):
    # Sintetico: replica exactamente el molde observado de ditto (12/8 bytes),
    # sin afirmar procedencia macOS. Solo reempaqueta evidencia ya firmada.
    local = struct.pack('<IIHH', 1700000000, 1700000001, 501, 20) if local is None else local
    central = struct.pack('<II', 1700000000, 1700000001) if central is None else central
    output, directory = bytearray(), bytearray()
    for name, data in files.items():
        name = name.encode('utf-8')
        lextra = struct.pack('<HH', 0x5855, len(local)) + local
        cextra = struct.pack('<HH', 0x5855, len(central)) + central
        crc, size, offset = zlib.crc32(data), len(data), len(output)
        output += struct.pack('<4s5H3I2H', b'PK\x03\x04', 20, flags, 0, 0, 33,
                              crc, size, size, len(name), len(lextra)) + name + lextra + data
        directory += struct.pack('<4s6H3I5H2I', b'PK\x01\x02', 20, 20, flags, 0, 0, 33,
                                 crc, size, size, len(name), len(cextra), 0, 0, 0, 0, offset) + name + cextra
    start = len(output)
    return bytes(output + directory + struct.pack('<4s4H2IH', b'PK\x05\x06', 0, 0,
                 len(files), len(files), len(directory), start, 0))


@pytest.mark.parametrize('local,central,expected', [
    (None, None, 0), (b'', None, 4), (b'x'*8, None, 4),
    (b'x'*13, None, 4), (None, b'' ,4), (None, b'x'*12, 4),
    (None, struct.pack('<II', 1, 2), 4),
])
def test_unix_lengths(verifier, bundle, content, tmp_path, monkeypatch, capsys, local, central, expected):
    monkeypatch.setattr(subprocess, 'run', lambda *a, **k: subprocess.CompletedProcess(a, 0, '', ''))
    path = tmp_path / 'unix.zip'
    path.write_bytes(unix_archive(bundle, local, central))
    assert run(verifier, path, content) == expected
    output = capsys.readouterr()
    assert 'INVALID' not in output.out + output.err


def test_saved_synthetic(verifier, bundle, content, monkeypatch):
    assert FIXTURE.read_bytes() == unix_archive(bundle)
    with zipfile.ZipFile(FIXTURE) as z:
        assert {n: z.read(n) for n in z.namelist()} == bundle
    monkeypatch.setattr(subprocess, 'run', lambda *a, **k: subprocess.CompletedProcess(a, 0, '', ''))
    assert run(verifier, FIXTURE, content) == 0


def test_unix_does_not_override_members(verifier, bundle, content, tmp_path, monkeypatch):
    monkeypatch.setattr(subprocess, 'run', lambda *a, **k: subprocess.CompletedProcess(a, 0, '', ''))
    baseline = verifier.validate_zip_container(unix_archive(bundle))
    changed = verifier.validate_zip_container(unix_archive(bundle, struct.pack('<IIHH', 1, 2, 0, 65535), struct.pack('<II', 1, 2)))
    keys = ('name', 'name_bytes', 'csize', 'usize', 'offset')
    assert [tuple(e[k] for k in keys) for e in baseline] == [tuple(e[k] for k in keys) for e in changed]
    bundle['proof.json'] = b'{}'
    path = tmp_path / 'alterado.zip'; path.write_bytes(unix_archive(bundle))
    assert run(verifier, path, content) == 1


def test_fallback_blank_line(verifier, monkeypatch):
    writes = []
    monkeypatch.setattr(verifier.os, 'write', lambda fd, data: writes.append((fd, data)))
    with pytest.raises(SystemExit) as exc:
        verifier.io_failure()
    assert exc.value.code == 4
    assert writes == [(2, b'\nERROR E/S [4]: no se pudo completar la entrada/salida; no se emite veredicto\n')]


def test_uncovered_quotes(verifier, bundle, content, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(subprocess, 'run', lambda *a, **k: subprocess.CompletedProcess(a, 0, '', ''))
    bundle['uno.txt'] = b'x'; bundle['dos.txt'] = b'y'
    path = tmp_path / 'avisos.zip'; path.write_bytes(unix_archive(bundle))
    assert run(verifier, path, content) == 5
    line = next(x for x in capsys.readouterr().out.splitlines() if 'NO cubiertos:' in x)
    assert line == "  NO cubiertos: 'dos.txt', 'uno.txt'  (sin hash ni firma que los proteja: informativos, NO son evidencia)"


@pytest.mark.parametrize('local,central', [(b'proof.json', None), (None, b'proof.json')])
def test_unix_name_payload_is_unsupported(verifier, bundle, content, tmp_path, monkeypatch, local, central):
    monkeypatch.setattr(subprocess, 'run', lambda *a, **k: subprocess.CompletedProcess(a, 0, '', ''))
    path = tmp_path / 'nombre.zip'; path.write_bytes(unix_archive(bundle, local, central))
    assert run(verifier, path, content) == 4


@pytest.mark.parametrize('extra', [b'\x55\x58', struct.pack('<HH', 0x5855, 100) + b'x',
                                (struct.pack('<HHII', 0x5855, 8, 1, 2)) * 2])
def test_unix_truncated_or_repeated(verifier, extra, tmp_path, monkeypatch):
    # Rehacer solo el directorio central del primer miembro conserva los offsets locales.
    raw = FIXTURE.read_bytes()
    cd = struct.unpack_from('<I', raw, len(raw) - 6)[0]
    nlen, xlen = struct.unpack_from('<HH', raw, cd + 28)
    start = cd + 46 + nlen
    changed = bytearray(raw[:start] + extra + raw[start + xlen:])
    struct.pack_into('<H', changed, cd + 30, len(extra))
    struct.pack_into('<I', changed, len(changed) - 10,
                     struct.unpack_from('<I', raw, len(raw) - 10)[0] + len(extra) - xlen)
    reasons = []
    verifier.validate_zip_container(bytes(changed), unsupported_out=reasons)
    assert reasons and all('0x5855' in reason for reason in reasons)
    path = tmp_path / 'truncado.zip'
    path.write_bytes(changed)
    monkeypatch.setattr(subprocess, 'run', ORIGINAL_RUN)
    assert js_decision(path) == 4


def js_decision(path):
    result = subprocess.run(['node', str(ROOT / 'docs/zip-profile-reference.mjs'), str(path)],
                            capture_output=True, text=True)
    assert result.returncode in (0, 1, 4), result.stderr
    return result.returncode


@pytest.mark.parametrize('flags', [0, 0x800])
@pytest.mark.parametrize('name', ['ſignatures.json', 'carpeta/ſignatures.json',
                                  '__MACOSX/ſignatures.json', 'ſignatures.json/'])
def test_long_s_collision(verifier, bundle, content, tmp_path, monkeypatch, flags, name):
    files = dict(bundle, **{name: b'' if name.endswith('/') else b'{}'})
    path = tmp_path / 'colision.zip'
    path.write_bytes(unix_archive(files, flags=flags))
    with pytest.raises(SystemExit) as exc:
        verifier.validate_zip_container(path.read_bytes())
    assert exc.value.code == 1
    monkeypatch.setattr(subprocess, 'run', ORIGINAL_RUN)
    assert js_decision(path) == 1
    monkeypatch.setattr(subprocess, 'run', lambda *a, **k: subprocess.CompletedProcess(a, 0, '', ''))
    assert run(verifier, path, content) == 1


@pytest.mark.parametrize('flags', [0, 0x800])
@pytest.mark.parametrize('name', ['café.txt', 'cafe\u0301.txt'])
def test_accent_names_preserved(verifier, bundle, tmp_path, monkeypatch, flags, name):
    path = tmp_path / 'acentos.zip'
    path.write_bytes(unix_archive(dict(bundle, **{name: b'auxiliar'}), flags=flags))
    entries = verifier.validate_zip_container(path.read_bytes())
    assert name in [entry['name'] for entry in entries]
    monkeypatch.setattr(subprocess, 'run', ORIGINAL_RUN)
    assert js_decision(path) == 0


@pytest.mark.parametrize('local,central,expected', [
    (None, None, 0), (b'', None, 4), (b'x'*8, None, 4),
    (b'x'*13, None, 4), (None, b'', 4), (None, b'x'*12, 4),
    (None, struct.pack('<II', 1, 2), 4),
])
def test_unix_js_parity(verifier, bundle, tmp_path, monkeypatch, local, central, expected):
    from test_verificador_f1_f5 import decision
    path = tmp_path / 'paridad.zip'
    path.write_bytes(unix_archive(bundle, local, central, flags=0))
    assert decision(verifier, path.read_bytes()) == expected
    monkeypatch.setattr(subprocess, 'run', ORIGINAL_RUN)
    assert js_decision(path) == expected


@pytest.mark.parametrize('path', sorted((ROOT.parent / 'x39-fixtures-macos/zips').glob('*.zip')),
                         ids=lambda path: path.stem)
def test_macos_container_js_parity(verifier, path, monkeypatch):
    from test_verificador_f1_f5 import decision
    # Los archivos with-parent contienen payload/x39-bundle-v1: doble envoltorio.
    expected = 4 if 'with-parent' in path.stem and 'without-parent' not in path.stem else 0
    assert decision(verifier, path.read_bytes()) == expected
    monkeypatch.setattr(subprocess, 'run', ORIGINAL_RUN)
    assert js_decision(path) == expected


@pytest.mark.parametrize('flags', [0, 0x800])
def test_accent_equivalent_names_collide(verifier, bundle, tmp_path, monkeypatch, flags):
    files = dict(bundle, **{'café.txt': b'a', 'cafe\u0301.txt': b'b'})
    path = tmp_path / 'acentos_duplicados.zip'
    path.write_bytes(unix_archive(files, flags=flags))
    with pytest.raises(SystemExit) as exc:
        verifier.validate_zip_container(path.read_bytes())
    assert exc.value.code == 1
    monkeypatch.setattr(subprocess, 'run', ORIGINAL_RUN)
    assert js_decision(path) == 1


@pytest.mark.parametrize('flags', [0, 0x800])
def test_invalid_utf8_name_encoding_policy(verifier, bundle, tmp_path, monkeypatch, flags):
    raw = unix_archive(dict(bundle, **{'aux.txt': b'a'}), flags=flags)
    raw = raw.replace(b'aux.txt', b'\xffux.txt')
    path = tmp_path / 'utf8_invalido.zip'
    path.write_bytes(raw)
    from test_verificador_f1_f5 import decision
    expected = 1 if flags & 0x800 else 0
    assert decision(verifier, raw) == expected
    monkeypatch.setattr(subprocess, 'run', ORIGINAL_RUN)
    assert js_decision(path) == expected


def test_mixed_utf8_flags_shared_prefix(verifier, bundle, tmp_path, monkeypatch):
    files = {'café/' + name: data for name, data in bundle.items()}
    raw = bytearray(unix_archive(files, flags=0))
    central = struct.unpack_from('<I', raw, len(raw) - 6)[0]
    struct.pack_into('<H', raw, 6, 0x800)
    struct.pack_into('<H', raw, central + 8, 0x800)
    path = tmp_path / 'banderas_mezcladas.zip'
    path.write_bytes(raw)
    with pytest.raises(SystemExit) as exc:
        verifier.validate_zip_container(bytes(raw))
    assert exc.value.code == 1
    monkeypatch.setattr(subprocess, 'run', ORIGINAL_RUN)
    assert js_decision(path) == 1

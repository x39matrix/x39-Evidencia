"""Pruebas offline: firmas existentes, sin generar claves ni firmar datos."""
import ast
import base64
import copy
import hashlib
import importlib.util
import json
import socket
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(params=[ROOT / 'verify_bundle.py'])
def verifier(request, monkeypatch):
    spec = importlib.util.spec_from_file_location('verificador_local', request.param)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    def blocked(*args, **kwargs):
        raise AssertionError('Red/proceso externo no autorizado en prueba offline')
    monkeypatch.setattr(socket, 'socket', blocked)
    monkeypatch.setattr(subprocess, 'run', blocked)
    return module


@pytest.fixture
def bundle():
    with zipfile.ZipFile(ROOT / 'testdata/bundle_v1_prod.zip') as z:
        # El README heredado carece de manifiesto: excluirlo del control limpio.
        return {n: z.read(n) for n in z.namelist() if n != 'README.md'}


@pytest.fixture
def content(tmp_path, bundle):
    tree = ast.parse((ROOT / 'backend/notaria.py').read_text())
    text = next(n.value for n in ast.walk(tree)
                if isinstance(n, ast.Constant) and isinstance(n.value, str)
                and n.value.startswith('CONTRATO DE SERVICIOS FREELANCE\n\n'))
    p = tmp_path / 'documento.txt'
    p.write_text(text)
    assert hashlib.sha256(p.read_bytes()).hexdigest() == json.loads(bundle['proof.json'])['content_hash']
    return p


def run_main(module, files, tmp_path, monkeypatch, capsys, content=None, skip=True, corrupt_member=None):
    path = tmp_path / 'prueba.zip'
    with zipfile.ZipFile(path, 'w') as z:
        for name, data in files.items():
            z.writestr(name, data)
    if corrupt_member is not None:
        # ZIP_STORED: cambiar solo datos, dejando el CRC anterior, prueba lectura real.
        original = files[corrupt_member]
        changed = bytes([original[0] ^ 1]) + original[1:]
        raw = path.read_bytes()
        assert raw.count(original) == 1
        path.write_bytes(raw.replace(original, changed))
    args = ['verificador', str(path)]
    if skip:
        args.append('--skip-ots')
    if content is not None:
        args.extend(['--content', str(content)])
    monkeypatch.setattr(sys, 'argv', args)
    with pytest.raises(SystemExit) as exc:
        module.main()
    output = capsys.readouterr()
    return exc.value.code, output


@pytest.mark.parametrize('case,code,reason', [
    ('empty', 1, 'vacio'), ('unknown_version', 1, 'version'),
    ('missing_hash', 1, 'content_hash'), ('missing_cold', 2, 'COLD'),
    ('empty_cold', 2, 'COLD'), ('cold_false', 2, 'COLD'),
    ('cold_corrupt', 2, 'ML-DSA-87.verify FALLO'),
    ('proof_title', 1, 'proof_hash mismatch'),
    ('proof_rehashed', 2, 'ML-DSA-87.verify FALLO'),
    ('signatures_title', 1, "'title' difiere"),
    ('document_corrupt', 1, 'content_hash mismatch'),
    ('duplicate_json', 1, 'duplicado'),
])
def test_negatives(verifier, bundle, content, tmp_path, monkeypatch, capsys, case, code, reason):
    files = copy.deepcopy(bundle)
    proof = json.loads(files['proof.json'])
    sigs = json.loads(files['signatures.json'])
    if case == 'empty':
        proof = {}
    elif case == 'unknown_version':
        proof['v'] = 'X39-NOTARIA-999'
    elif case == 'missing_hash':
        proof.pop('content_hash')
    elif case in ('missing_cold', 'empty_cold', 'cold_false'):
        sigs['cold'] = {'missing_cold': None, 'empty_cold': {}, 'cold_false': False}[case]
    elif case == 'cold_corrupt':
        sig = bytearray(base64.b64decode(sigs['cold']['signature_b64']))
        sig[0] ^= 1
        sigs['cold']['signature_b64'] = base64.b64encode(sig).decode()
    elif case in ('proof_title', 'proof_rehashed'):
        proof['title'] = 'titulo alterado'
        if case == 'proof_rehashed':
            sigs['title'] = proof['title']
    elif case == 'signatures_title':
        sigs['title'] = 'titulo alterado'
    elif case == 'document_corrupt':
        data = bytearray(content.read_bytes()); data[0] ^= 1; content.write_bytes(data)
    if proof != json.loads(files['proof.json']):
        files['proof.json'] = json.dumps(proof, ensure_ascii=False).encode()
    if case in ('empty', 'proof_rehashed'):
        sigs['proof_hash'] = hashlib.sha256(files['proof.json']).hexdigest()
    if case == 'duplicate_json':
        files['proof.json'] = b'{"v":"X39-NOTARIA-1","v":"X39-NOTARIA-3"}'
    files['signatures.json'] = json.dumps(sigs).encode()
    exit_code, output = run_main(verifier, files, tmp_path, monkeypatch, capsys, content)
    assert exit_code == code
    assert output.err.startswith('INVALID[')
    assert reason in output.err
    assert 'VALID' not in output.out.splitlines()


def test_no_document(verifier, bundle, tmp_path, monkeypatch, capsys):
    code, output = run_main(verifier, bundle, tmp_path, monkeypatch, capsys)
    assert code == 4
    assert 'ERROR USO/CONTENEDOR [4]: DOCUMENTO NO COMPROBADO' in output.err


def test_skip_ots_never_approves(verifier, bundle, content, tmp_path, monkeypatch, capsys):
    code, output = run_main(verifier, bundle, tmp_path, monkeypatch, capsys, content)
    assert code == 3
    assert 'INVALID[3]' in output.err and 'OTS NO COMPROBADO' in output.err
    assert 'VALID' not in output.out.splitlines()
    assert 'COLD autentica: todos los bytes y campos de proof.json' in output.out
    assert 'COLD NO autentica: signatures.json' in output.out


def test_complete_path_with_simulated_ots(verifier, bundle, content, tmp_path, monkeypatch, capsys):
    # COLD/WARM y documento reales; solo el comando OTS es simulado, sin red.
    calls = []
    def ots_ok(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, '', '')
    monkeypatch.setattr(subprocess, 'run', ots_ok)
    code, output = run_main(verifier, bundle, tmp_path, monkeypatch, capsys, content, skip=False)
    assert code == 0 and output.out.endswith('VALID [0]\n[FIN VEREDICTO]')
    assert len([c for c in calls if c[0] == 'ots']) == 3


def test_ots_failure_is_fatal(verifier, bundle, content, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(subprocess, 'run', lambda command, **kwargs:
                        subprocess.CompletedProcess(command, 1, '', 'prueba de ancla fallida'))
    code, output = run_main(verifier, bundle, tmp_path, monkeypatch, capsys, content, skip=False)
    assert code == 3 and 'INVALID[3]' in output.err
    assert 'VALID' not in output.out.splitlines()


@pytest.mark.parametrize('warm_case', ['absent', 'valid', 'corrupt', 'malformed', 'empty'])
def test_warm_is_only_legacy_information(verifier, bundle, content, tmp_path, monkeypatch, capsys, warm_case):
    # COLD y documento reales; OTS simulado para no utilizar la red.
    sigs = json.loads(bundle['signatures.json'])
    if warm_case == 'absent':
        sigs.pop('warm')
    elif warm_case == 'corrupt':
        sig = bytearray(base64.b64decode(sigs['warm']['signature_b64'])); sig[0] ^= 1
        sigs['warm']['signature_b64'] = base64.b64encode(sig).decode()
    elif warm_case == 'malformed':
        sigs['warm'] = 'firma heredada malformada'
    elif warm_case == 'empty':
        sigs['warm'] = {}
    bundle['signatures.json'] = json.dumps(sigs).encode()
    monkeypatch.setattr(subprocess, 'run', lambda command, **kwargs:
                        subprocess.CompletedProcess(command, 0, '', ''))
    code, output = run_main(verifier, bundle, tmp_path, monkeypatch, capsys, content, skip=False)
    anomalous = warm_case in ('corrupt', 'malformed', 'empty')
    assert code == (5 if anomalous else 0)
    assert output.out.endswith(('VALID CON AVISOS [5]' if anomalous else 'VALID [0]') + '\n[FIN VEREDICTO]')
    assert not output.err
    if warm_case == 'valid':
        assert 'WARM: firma heredada, clave en linea retirada el 2026-07-16' in output.out
    if warm_case in ('corrupt', 'malformed', 'empty'):
        assert 'WARM: NO VERIFICA:' in output.out
        assert 'ANOMALIA:' in output.out
        assert 'aprobacion sostenida solo por COLD valida + documento + cadena' in output.out
    elif warm_case == 'valid':
        assert 'WARM: comprobacion heredada correcta' in output.out


def test_warm_environment_failure_is_informative(verifier, bundle, content, tmp_path, monkeypatch, capsys):
    original = verifier.check_ml_dsa_signature
    def check(label, *args, **kwargs):
        if label == 'warm':
            raise verifier.SignatureEnvironmentError('control negativo WARM no fiable')
        return original(label, *args, **kwargs)
    monkeypatch.setattr(verifier, 'check_ml_dsa_signature', check)
    monkeypatch.setattr(subprocess, 'run', lambda command, **kwargs:
                        subprocess.CompletedProcess(command, 0, '', ''))
    code, output = run_main(verifier, bundle, tmp_path, monkeypatch, capsys, content, skip=False)
    assert code == 5 and output.out.endswith('VALID CON AVISOS [5]\n[FIN VEREDICTO]')
    assert 'WARM: NO VERIFICA:' in output.out
    assert not output.err


@pytest.mark.parametrize('name,data,expected', [
    ('extra.json', b'{ilegible', 5),
    ('extra.json', b'{"campo":1,"campo":2}', 5),
    ('extra.json', b'{"campo":1}', 5),
    ('extra.json', b'[]', 5),
    ('extra.txt', b'\xff\xfe', 5),
    ('README.md', b'\xff\xfe', 1),
    ('chat_chain.json', b'ilegible', 1),  # v1: cadena fuera del formato, invalida.
])
def test_auxiliary_parse_anomalies(verifier, bundle, content, tmp_path, monkeypatch, capsys, name, data, expected):
    bundle[name] = data
    monkeypatch.setattr(subprocess, 'run', lambda command, **kwargs:
                        subprocess.CompletedProcess(command, 0, '', ''))
    code, output = run_main(verifier, bundle, tmp_path, monkeypatch, capsys, content, skip=False)
    assert code == expected
    if expected == 1:
        assert output.err.startswith('INVALID[1]')
        return
    assert output.out.endswith(('VALID CON AVISOS [5]' if expected == 5 else 'VALID [0]') + '\n[FIN VEREDICTO]')
    if expected == 5:
        assert name in output.out and 'ANOMALIA:' in output.out
        assert 'aprobacion sostenida solo por COLD valida + documento + cadena' in output.out
    assert not output.err


def test_auxiliary_zip_crc_anomaly(verifier, bundle, content, tmp_path, monkeypatch, capsys):
    bundle['extra.txt'] = b'contenido auxiliar unico para comprobar CRC'
    monkeypatch.setattr(subprocess, 'run', lambda command, **kwargs:
                        subprocess.CompletedProcess(command, 0, '', ''))
    code, output = run_main(verifier, bundle, tmp_path, monkeypatch, capsys, content,
                            skip=False, corrupt_member='extra.txt')
    assert code == 5 and output.out.endswith('VALID CON AVISOS [5]\n[FIN VEREDICTO]')
    assert "'extra.txt': fichero auxiliar ilegible" in output.out


@pytest.mark.parametrize('name', ['proof.json', 'signatures.json'])
def test_unparseable_essential_file_still_invalid(verifier, bundle, content, tmp_path, monkeypatch, capsys, name):
    bundle[name] = b'JSON ilegible'
    code, output = run_main(verifier, bundle, tmp_path, monkeypatch, capsys, content, skip=False)
    assert code == 1 and output.err.startswith('INVALID[1]')
    assert 'VALID CON AVISOS' not in output.out.splitlines()


def test_required_manifest_member_cannot_be_skipped(verifier, tmp_path, monkeypatch, capsys):
    with zipfile.ZipFile(ROOT / 'testdata/e2e_chat_hmac_v2.zip') as z:
        files = {n: z.read(n) for n in z.namelist()}
    code, output = run_main(verifier, files, tmp_path, monkeypatch, capsys,
                            corrupt_member='README.md')
    assert code == 1 and "manifiesto: falta 'README.md'" in output.err


def test_document_failure_overrides_warm_anomaly(verifier, bundle, content, tmp_path, monkeypatch, capsys):
    sigs = json.loads(bundle['signatures.json']); sigs['warm'] = 'malformada'
    bundle['signatures.json'] = json.dumps(sigs).encode()
    content.write_bytes(b'documento alterado')
    code, output = run_main(verifier, bundle, tmp_path, monkeypatch, capsys, content, skip=False)
    assert code == 1 and 'content_hash mismatch' in output.err
    assert 'VALID CON AVISOS' not in output.out.splitlines()


def test_unsigned_metadata_is_explicitly_outside_coverage(verifier, bundle, content, tmp_path, monkeypatch, capsys):
    sigs = json.loads(bundle['signatures.json'])
    sigs['cold']['verified_at'] = '2099-01-01'
    sigs['cold']['notes'] = 'notas alteradas'
    bundle['signatures.json'] = json.dumps(sigs).encode()
    bundle['README.md'] = b'informacion externa alterada'
    monkeypatch.setattr(subprocess, 'run', lambda command, **kwargs:
                        subprocess.CompletedProcess(command, 0, '', ''))
    code, output = run_main(verifier, bundle, tmp_path, monkeypatch, capsys, content, skip=False)
    assert code == 1 and output.err.startswith('INVALID[1]')
    assert 'VALID' not in output.out.splitlines()


@pytest.mark.parametrize('result', [False, 0, 1, '', 'OK', object()])
def test_unexpected_crypto_result_fails(verifier, monkeypatch, result):
    from pqcrypto.sign import ml_dsa_87
    monkeypatch.setattr(ml_dsa_87, 'verify', lambda *args: result)
    assert verifier.mldsa_verify_ok(b'', b'', b'') is False


def test_always_none_crypto_library_is_rejected(verifier, bundle, monkeypatch, capsys):
    from pqcrypto.sign import ml_dsa_87
    monkeypatch.setattr(ml_dsa_87, 'verify', lambda *args: None)
    # El autotest caza la libreria envenenada: die(4) se propaga como VerifierUsageError
    # y main() lo imprime como ERROR USO/CONTENEDOR [4]. Se exige el motivo exacto.
    with pytest.raises(verifier.VerifierUsageError) as exc:
        verifier.verify_signatures(bundle['proof.json'], bundle['signatures.json'])
    assert 'acepta una firma ALTERADA' in str(exc.value)


def test_v3_cannot_skip_message_signatures(verifier, capsys):
    with pytest.raises(SystemExit) as exc:
        verifier.verify_msg_sigs({}, {'v': 'X39-NOTARIA-3', 'msg_sigs': None})
    assert exc.value.code == 2
    assert capsys.readouterr().err.startswith('INVALID[2]')

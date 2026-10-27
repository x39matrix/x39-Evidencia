"""Matriz adversaria local: firmas publicas existentes; ZIP mutados desechables."""
import base64
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
import random
import struct
import subprocess
import sys
import tempfile
import warnings
import zipfile
import zlib
from pathlib import Path

import pytest

from test_verificador_estricto import ROOT, bundle, content, verifier

REAL_RUN = subprocess.run
REPORT_DIR = Path(tempfile.mkdtemp(prefix='matriz-mundo-cerrado-'))
ROWS = []

CASES = [
    ('control_limpio', 0), ('control_deflate', 0), ('control_descriptor', 0), ('control_descriptor_sin_firma', 0),
    ('zip_concatenado_falso_legitimo', 1), ('zip_prefijo', 1), ('zip_sufijo', 1),
    ('zip_hueco_entre_entradas', 1), ('zip_hueco_antes_central', 1), ('zip_comentario', 1),
    ('zip_nombre_local_distinto', 1), ('zip_crc_local_distinto', 1), ('zip_symlink', 1),
    ('zip_directorio_UNIX', 1), ('zip_version_no_soportada', 1), ('zip_descriptor_distinto', 1),
    ('zip_deflate_con_cola', 1), ('zip_zip64', 1),
    ('nombre_PROOF_JSON', 1), ('nombre_Proof_json', 1), ('nombre_readme_md', 1),
    ('nombre_homoglifo', 1), ('nombre_punto_proof', 1), ('nombre_parent_interno', 1),
    ('nombre_parent_externo', 1), ('nombre_absoluto', 1), ('nombre_backslash', 1),
    ('nombre_NUL', 1), ('nombre_duplicado_proof', 1), ('nombre_colision_aux', 1),
    ('miembro_binario_no_declarado', 5), ('miembro_json_correcto_no_declarado', 5),
    ('README_sin_manifiesto', 0), ('auxiliar_json_corrupto', 5), ('auxiliar_md_corrupto', 5),
    ('auxiliar_100000_niveles', 5), ('auxiliar_NaN', 5),
    ('limite_200MB', 1), ('limite_ratio', 1), ('limite_total', 1), ('limite_zip', 1),
    ('limite_miembros', 1),
    ('warm_ausente', 0), ('warm_valida_historica', 0), ('warm_basura', 5),
    ('warm_malformada', 5), ('warm_clave_ajena', 5), ('warm_clave_ajena_verifica_simulada', 5),
    ('warm_cold_copiada', 2),
    ('signatures_extra', 1), ('cold_extra', 1), ('warm_extra', 1),
    ('estado_REVOCADO', 1), ('message_signatures_9_9', 1),
    ('message_signatures_recuento_v3', 1), ('message_signatures_claves_v3', 1),
    ('cold_algorithm_falso', 2), ('cold_tier_WARM', 2), ('cold_base64_relleno', 2),
    ('JSON_NaN', 1), ('JSON_Infinity', 1), ('JSON_menos_Infinity', 1), ('JSON_overflow_float', 1),
    ('falta_signatures', 4), ('falta_ots', 4), ('falta_README_manifiesto', 1),
    ('README_manifiesto_alterado', 1), ('falta_cadena_v3', 1),
    ('falta_cadena_v3_manifiesto', 1),
    ('proof_vacio', 1), ('proof_byte_alterado', 1), ('proof_crc_alterado', 1), ('proof_hash_mayusculas', 1),
    ('cold_fingerprint_mayusculas', 2), ('ots_vacio', 3), ('ots_ajeno', 3),
    ('sin_content', 4), ('documento_equivocado', 1), ('content_directorio', 4),
    ('skip_ots', 3), ('signatures_ilegible', 1), ('cold_ausente', 6), ('cold_corrupta', 2),
    ('v1_cadena_inventada', 1),
    ('chain_content_hash_delimitador', 1), ('chain_content_hash_corto', 1),
    ('chain_index', 1), ('chain_v', 1), ('chain_top_extra', 1), ('chain_entry_extra', 1),
    ('chain_text_inyectado', 1), ('chain_v2_sig_basura', 2),
    ('chain_reordenada_v3', 1), ('chain_firma_eliminada_v3', 2), ('chain_firma_corrupta_v3', 2),
]


@pytest.fixture(scope='session', autouse=True)
def write_matrix():
    yield
    (REPORT_DIR / 'resultados.json').write_text(json.dumps(ROWS, indent=2, ensure_ascii=False))
    text = ['# Matriz del verificador: mundo cerrado', '',
            'Sin red ni firmas nuevas. Los archivos adversarios son copias locales desechables.',
            'OTS externo simulado exitoso salvo tests de fallo; formato/hash del .ots reales.',
            'Antes: snapshot local previo al parche, si existe. Los casos chain_* ejercitan las etapas',
            'de cadena y Ed25519 directamente, no afirman VALID completo del documento v3.',
            'La clave ajena que verifica se simula solo para WARM; COLD sigue usando criptografía real.',
            'El test de 200 MB no se ejecuta contra la versión anterior sin límites.', '',
            '| Caso | Etapa | Antes | Esperado | Obtenido |', '|---|---|---|---|---|']
    for r in ROWS:
        text.append(f"| {r['case']} | {r['phase']} | {r['before']} | {r['expected']} | {r['actual']} |")
    (REPORT_DIR / 'matriz.md').write_text('\n'.join(text) + '\n')
    print(f'\nMATRIZ_COMPLETA={REPORT_DIR / "matriz.md"}')


def read_bundle(name):
    with zipfile.ZipFile(ROOT / 'testdata' / name) as z:
        return {n: z.read(n) for n in z.namelist()}


def modify(files, name, action):
    obj = json.loads(files[name]); action(obj)
    files[name] = json.dumps(obj, ensure_ascii=False).encode()


def archive(files, compression=zipfile.ZIP_STORED, descriptor=False, zip64=False, symlink=False):
    class Pipe(io.BytesIO):
        def seek(self, *args): raise io.UnsupportedOperation()
    buf = Pipe() if descriptor else io.BytesIO()
    with zipfile.ZipFile(buf, 'w', compression=compression) as z:
        for name, data in files.items():
            if zip64 and name == 'proof.json':
                with z.open(name, 'w', force_zip64=True) as out: out.write(data)
            elif symlink and name == 'proof.json':
                info = zipfile.ZipInfo(name); info.external_attr = 0o120777 << 16
                z.writestr(info, data)
            else:
                z.writestr(name, data)
    return buf.getvalue()


def descriptor_without_signature(files):
    local, central = bytearray(), bytearray()
    for name, data in files.items():
        name = name.encode('ascii'); crc = zlib.crc32(data); size = len(data); offset = len(local)
        local += struct.pack('<4s5H3I2H', b'PK\x03\x04', 20, 8, 0, 0, 33, 0, 0, 0, len(name), 0)
        local += name + data + struct.pack('<3I', crc, size, size)
        central += struct.pack('<4s6H3I5H2I', b'PK\x01\x02', 20, 20, 8, 0, 0, 33,
                               crc, size, size, len(name), 0, 0, 0, 0, 0, offset) + name
    end = struct.pack('<4s4H2IH', b'PK\x05\x06', 0, 0, len(files), len(files), len(central), len(local), 0)
    return bytes(local + central + end)


def central_records(raw):
    end = len(raw) - 22; p = struct.unpack_from('<I', raw, end + 16)[0]
    records = []
    for _ in range(struct.unpack_from('<H', raw, end + 10)[0]):
        records.append(p)
        n, x, c = struct.unpack_from('<3H', raw, p + 28)
        p += 46 + n + x + c
    return records


def insert_gap(raw, at, payload=b'HUECO'):
    eocd = len(raw) - 22
    old_cd = struct.unpack_from('<I', raw, eocd + 16)[0]
    records = central_records(raw)
    out = bytearray(raw[:at] + payload + raw[at:]); delta = len(payload)
    struct.pack_into('<I', out, eocd + delta + 16, old_cd + delta)
    for p in records:
        old_offset = struct.unpack_from('<I', raw, p + 42)[0]
        struct.pack_into('<I', out, p + delta + 42, old_offset + (delta if old_offset >= at else 0))
    return bytes(out)


def alter_padding(s):
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    index = len(s.rstrip('=')) - 1
    return s[:index] + alphabet[alphabet.index(s[index]) ^ 1] + s[index + 1:]


def corrupt_signature(sigs, tier):
    sig = bytearray(base64.b64decode(sigs[tier]['signature_b64'])); sig[0] ^= 1
    sigs[tier]['signature_b64'] = base64.b64encode(sig).decode()


def evaluate(module, path, document, skip, phase, files):
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        try:
            if phase == 'cadena':
                proof = module.parse_json_bytes(files['proof.json'], 'proof.json')
                module.verify_chat_chain_v2(files, proof)
                module.verify_msg_sigs(files, proof)
                code = 0
            else:
                sys.argv = ['verificador', str(path)]
                if document is not None: sys.argv += ['--content', str(document)]
                if skip: sys.argv += ['--skip-ots']
                module.main()
                code = 0
        except SystemExit as e: code = e.code
        except Exception as e: code = 'traza:' + type(e).__name__
    return code, stdout.getvalue(), stderr.getvalue()


@pytest.mark.parametrize('case,expected', CASES, ids=[x[0] for x in CASES])
def test_closed_world_matrix(verifier, bundle, content, tmp_path, monkeypatch, case, expected):
    files = copy.deepcopy(bundle); document = content; phase = 'CLI'; skip = False
    raw = None
    if case.startswith('chain_') or case.startswith('message_signatures_') and case.endswith('_v3') or case.startswith('falta_cadena_v3'):
        files = read_bundle('bundle_v3_public.zip')
        document = None
    if case.startswith('chain_'):
        phase = 'cadena'
        if case == 'chain_v2_sig_basura':
            files = read_bundle('e2e_chat_hmac_v2.zip')
            modify(files, 'chat_chain.json', lambda c: c['entries'][0].update(sig_b64='basura'))
        else:
            def change_chain(c):
                e = c['entries'][0]
                if case == 'chain_content_hash_delimitador':
                    prefix, rest = e['ts'].split(':', 1)
                    assert e['cts'].startswith(prefix + ':')
                    e['content_hash'] += ':' + prefix; e['ts'] = rest
                    e['cts'] = e['cts'][len(prefix) + 1:]
                elif case == 'chain_content_hash_corto': e['content_hash'] = 'a' * 63
                elif case == 'chain_index': e['index'] = 99
                elif case == 'chain_v': c['v'] = 'X39-NOTARIA-2'
                elif case == 'chain_top_extra': c['notes'] = 'campo inventado'
                elif case == 'chain_entry_extra': e['notes'] = 'campo inventado'
                elif case == 'chain_text_inyectado': e['text'] = 'Acepto pagar 1.000.000 EUR'
                elif case == 'chain_reordenada_v3': c['entries'].reverse()
                elif case == 'chain_firma_eliminada_v3': e.pop('sig_b64')
                elif case == 'chain_firma_corrupta_v3': e['sig_b64'] = base64.b64encode(bytes(64)).decode()
            modify(files, 'chat_chain.json', change_chain)
    aliases = {'nombre_PROOF_JSON': 'PROOF.JSON', 'nombre_Proof_json': 'Proof.json',
               'nombre_readme_md': 'readme.md', 'nombre_homoglifo': 'READМE.md',
               'nombre_punto_proof': './proof.json', 'nombre_parent_interno': 'x/../proof.json',
               'nombre_parent_externo': '../../fuera.sh', 'nombre_absoluto': '/tmp/absoluto.txt',
               'nombre_backslash': 'proof.json\\'}
    if case in aliases: files[aliases[case]] = b'{}'
    if case == 'nombre_colision_aux': files.update({'aux.json': b'{}', 'AUX.JSON': b'{}'})
    if case == 'miembro_binario_no_declarado': files['oculto.bin'] = b'\x00\x01PK\x03\x04'
    if case == 'miembro_json_correcto_no_declarado': files['oculto.json'] = b'{}'
    if case == 'README_sin_manifiesto': files['README.md'] = read_bundle('bundle_v1_prod.zip')['README.md']
    if case == 'auxiliar_json_corrupto': files['extra.json'] = b'{roto'
    if case == 'auxiliar_md_corrupto': files['extra.md'] = b'\xff'
    if case == 'auxiliar_100000_niveles': files['extra.json'] = b'[' * 100000 + b'0' + b']' * 100000
    if case == 'auxiliar_NaN': files['extra.json'] = b'{"numero":NaN}'
    if case == 'v1_cadena_inventada': files['chat_chain.json'] = b'{"text":"Acepto pagar"}'
    if case == 'falta_signatures': files.pop('signatures.json')
    if case == 'falta_ots': files.pop('proof.json.ots')
    if case in ('falta_README_manifiesto', 'README_manifiesto_alterado'):
        files = read_bundle('e2e_chat_hmac_v2.zip')
        if case == 'falta_README_manifiesto': files.pop('README.md')
        else: files['README.md'] = b'alterado'
    if case.startswith('falta_cadena_v3'):
        if case.endswith('_manifiesto'):
            h = hashlib.sha256(files['chat_chain.json']).hexdigest()
            modify(files, 'proof.json', lambda p: p.update(files={'chat_chain.json': h}))
        files.pop('chat_chain.json')
    if case == 'proof_vacio': files['proof.json'] = b'{}'
    if case == 'proof_byte_alterado':
        modify(files, 'proof.json', lambda p: p.update(title='titulo alterado'))
    if case in ('JSON_NaN', 'JSON_Infinity', 'JSON_menos_Infinity', 'JSON_overflow_float'):
        token = {'JSON_NaN': 'NaN', 'JSON_Infinity': 'Infinity', 'JSON_menos_Infinity': '-Infinity',
                 'JSON_overflow_float': '1e9999'}[case]
        files['signatures.json'] = files['signatures.json'].rstrip()[:-1] + (',"extra":' + token + '}').encode()
    elif case.startswith(('warm_', 'cold_', 'signatures_', 'message_signatures_')) or case in ('estado_REVOCADO', 'proof_hash_mayusculas'):
        def change_sigs(s):
            if case == 'warm_ausente': s.pop('warm')
            elif case in ('warm_clave_ajena', 'warm_clave_ajena_verifica_simulada'):
                s['warm']['public_key_b64'] = base64.b64encode(bytes([1]) * 2592).decode()
                s['warm']['signature_b64'] = base64.b64encode(bytes([2]) * 4627).decode()
            elif case == 'warm_cold_copiada': s['warm'] = copy.deepcopy(s['cold'])
            elif case == 'warm_basura': corrupt_signature(s, 'warm')
            elif case == 'warm_malformada': s['warm'] = 'ilegible'
            elif case == 'signatures_extra': s['nuevo'] = 'inventado'
            elif case == 'cold_extra': s['cold']['nuevo'] = 'inventado'
            elif case == 'warm_extra': s['warm']['nuevo'] = 'inventado'
            elif case == 'estado_REVOCADO': s['estado'] = 'REVOCADO'
            elif case == 'message_signatures_9_9': s['message_signatures'] = {'algorithm': 'Ed25519', 'signed': 9, 'total': 9, 'keys': {}}
            elif case == 'message_signatures_recuento_v3': s['message_signatures'].update(signed=9, total=9)
            elif case == 'message_signatures_claves_v3': s['message_signatures']['keys']['A'] = 'otra clave'
            elif case == 'cold_algorithm_falso': s['cold']['algorithm'] = 'ML-DSA-87 NO VERIFICADO / falso'
            elif case == 'cold_tier_WARM': s['cold']['tier'] = 'WARM'
            elif case == 'cold_base64_relleno': s['cold']['signature_b64'] = alter_padding(s['cold']['signature_b64'])
            elif case == 'cold_fingerprint_mayusculas': s['cold']['fingerprint'] = s['cold']['fingerprint'].upper()
            elif case == 'proof_hash_mayusculas': s['proof_hash'] = s['proof_hash'].upper()
            elif case == 'cold_ausente': s.pop('cold')
            elif case == 'cold_corrupta': corrupt_signature(s, 'cold')
        modify(files, 'signatures.json', change_sigs)
    if case == 'signatures_ilegible': files['signatures.json'] = b'ilegible'
    if case == 'ots_vacio': files['proof.json.ots'] = b''
    if case == 'ots_ajeno': files['proof.json.ots'] = read_bundle('bundle_v3_public.zip')['proof.json.ots']
    if case == 'sin_content': document = None
    if case == 'documento_equivocado': content.write_bytes(b'equivocado')
    if case == 'content_directorio': document = tmp_path
    if case == 'skip_ots': skip = True
    raw = archive(files, zipfile.ZIP_DEFLATED if case in ('control_deflate', 'zip_deflate_con_cola') else zipfile.ZIP_STORED,
                  descriptor=case in ('control_descriptor', 'zip_descriptor_distinto'),
                  zip64=case == 'zip_zip64', symlink=case == 'zip_symlink')
    if case == 'control_descriptor_sin_firma': raw = descriptor_without_signature(files)
    if case in ('zip_directorio_UNIX', 'zip_version_no_soportada', 'zip_descriptor_distinto'):
        r = bytearray(raw); first = central_records(raw)[0]
        if case == 'zip_directorio_UNIX': struct.pack_into('<I', r, first + 38, 0o040777 << 16)
        elif case == 'zip_version_no_soportada':
            struct.pack_into('<H', r, 4, 15); struct.pack_into('<H', r, first + 6, 15)
        else:
            size = struct.unpack_from('<I', r, first + 20)[0]
            nlen = struct.unpack_from('<H', r, 26)[0]
            r[30 + nlen + size + 4] ^= 1
        raw = bytes(r)
    if case == 'zip_concatenado_falso_legitimo': raw = archive({'proof.json': b'{"falso":true}'}) + raw
    if case == 'zip_prefijo': raw = b'PREFIJO' + raw
    if case == 'zip_sufijo': raw += b'SUFIJO'
    if case == 'zip_hueco_entre_entradas':
        at = struct.unpack_from('<I', raw, central_records(raw)[1] + 42)[0]
        raw = insert_gap(raw, at)
    if case == 'zip_hueco_antes_central': raw = insert_gap(raw, struct.unpack_from('<I', raw, len(raw) - 6)[0])
    if case == 'zip_comentario':
        r = bytearray(raw); struct.pack_into('<H', r, len(r) - 2, 4); raw = bytes(r) + b'nota'
    if case in ('zip_nombre_local_distinto', 'zip_crc_local_distinto', 'nombre_NUL'):
        r = bytearray(raw)
        if case == 'zip_nombre_local_distinto': r[30] = ord('P')
        elif case == 'zip_crc_local_distinto': r[14] ^= 1
        else:
            r[30] = 0; r[central_records(raw)[0] + 46] = 0
        raw = bytes(r)
    if case == 'proof_crc_alterado':
        r = bytearray(raw); r[30 + len('proof.json')] ^= 1; raw = bytes(r)
    if case == 'nombre_duplicado_proof':
        buf = io.BytesIO()
        with warnings.catch_warnings(), zipfile.ZipFile(buf, 'w') as z:
            warnings.simplefilter('ignore', UserWarning)
            for name, data in files.items(): z.writestr(name, data)
            z.writestr('proof.json', files['proof.json'])
        raw = buf.getvalue()
    if case == 'zip_deflate_con_cola':
        # Anexar bytes al payload comprimido y contabilizarlos en ambos headers.
        first = central_records(raw)[0]
        csize = struct.unpack_from('<I', raw, first + 20)[0]
        nlen = struct.unpack_from('<H', raw, 26)[0]
        at = 30 + nlen + csize
        raw = bytearray(insert_gap(raw, at, b'COLA'))
        struct.pack_into('<I', raw, 18, csize + 4)
        struct.pack_into('<I', raw, central_records(raw)[0] + 20, csize + 4)
        raw = bytes(raw)
    path = tmp_path / 'prueba.zip'; path.write_bytes(raw)
    if case in ('limite_200MB', 'limite_ratio', 'limite_total', 'limite_miembros'):
        with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as z:
            for name, data in files.items(): z.writestr(name, data)
            if case == 'limite_200MB':
                with z.open('grande.bin', 'w') as dest:
                    for _ in range(200): dest.write(b'0' * 1024 * 1024)
            elif case == 'limite_ratio': z.writestr('ratio.bin', b'0' * 1024 * 1024)
            elif case == 'limite_total':
                block = random.Random(39).randbytes(256 * 1024)
                for i in range(65): z.writestr(f'miembro{i}.bin', block + block)
            else:
                for i in range(256): z.writestr(f'miembro{i}.bin', b'x')
    if case == 'limite_zip':
        with path.open('ab') as dest: dest.truncate(verifier.MAX_ZIP_BYTES + 1)
    monkeypatch.setattr(subprocess, 'run', lambda command, **kwargs: subprocess.CompletedProcess(command, 0, '', ''))
    if case == 'warm_clave_ajena_verifica_simulada':
        from pqcrypto.sign import ml_dsa_87
        original = ml_dsa_87.verify
        def simulated(pk, msg, sig):
            if pk == bytes([1]) * 2592: return sig == bytes([2]) * 4627
            return original(pk, msg, sig)
        monkeypatch.setattr(ml_dsa_87, 'verify', simulated)
    before = 'sin referencia'
    snapshot = Path('/tmp/verificador_antes_mundo_cerrado.py')
    if snapshot.is_file() and case not in ('limite_200MB', 'limite_total', 'limite_zip'):
        spec = importlib.util.spec_from_file_location('verificador_anterior', snapshot)
        old = importlib.util.module_from_spec(spec); spec.loader.exec_module(old)
        before, _, _ = evaluate(old, path, document, skip, phase, files)
    elif case in ('limite_200MB', 'limite_total', 'limite_zip'):
        before = 'no ejecutado sin limites'
    actual, stdout, stderr = evaluate(verifier, path, document, skip, phase, files)
    ROWS.append(dict(case=case, phase=phase, expected=expected, actual=actual, before=before,
                     stdout=stdout, stderr=stderr))
    assert actual == expected, stdout + stderr
    if expected in (0, 5) and phase == 'CLI':
        assert stdout.endswith(('VALID [0]' if expected == 0 else 'VALID CON AVISOS [5]') + '\n[FIN VEREDICTO]')
        if expected == 5:
            assert 'ANOMALIA:' in stdout and 'NO cubiertos: ninguno' not in stdout
    elif expected == 6 and phase == 'CLI':
        # COLD ausente (no mala) con todo lo demas correcto: CONSISTENTE, nunca VALID.
        assert stdout.endswith('CONSISTENTE [6]\n[FIN VEREDICTO]') and not stderr
        assert 'SIN co-firma COLD' in stdout and 'VALID [0]' not in stdout
    elif expected == 4:
        # Un 4 es error de uso/contenedor y no implica genuinidad: no se titula INVALID.
        assert stderr.startswith('ERROR USO/CONTENEDOR [4]')
    elif expected != 0:
        assert stderr.startswith('INVALID[')
    if case == 'warm_clave_ajena_verifica_simulada':
        assert before in (0, 'sin referencia')
        assert 'WARM: comprobacion heredada correcta' not in stdout
    if case in ('zip_concatenado_falso_legitimo', 'zip_prefijo', 'zip_sufijo',
                'zip_hueco_entre_entradas', 'zip_hueco_antes_central', 'zip_comentario',
                'zip_nombre_local_distinto', 'zip_crc_local_distinto', 'zip_symlink',
                'zip_directorio_UNIX', 'zip_version_no_soportada', 'zip_descriptor_distinto',
                'zip_zip64', 'nombre_NUL', 'nombre_duplicado_proof', 'control_limpio',
                'control_deflate', 'control_descriptor', 'control_descriptor_sin_firma') or case in aliases:
        # Ejecutar solo la referencia local JS, nunca frontend ni red.
        result = REAL_RUN(['node', str(ROOT / 'docs/zip-profile-reference.mjs'), str(path)],
                          capture_output=True, text=True, timeout=10)
        assert result.returncode == (0 if case.startswith('control_') else 1), result.stderr

# Ronda 9b: nombres de directorio y Unicode Path redundante, local y central.
@pytest.mark.parametrize('name', ['CON/', 'SENTINELA./', 'dir/aux.txt/', 'PROOF~1.JSO/'])
def test_r9b_directory_names(verifier, name):
    import io
    out = io.BytesIO()
    with zipfile.ZipFile(out, 'w') as z:
        z.writestr('proof.json', b'{}')
        z.writestr(name, b'')
    with pytest.raises(SystemExit) as exc:
        verifier.validate_zip_container(out.getvalue(), [])
    assert exc.value.code == 1

@pytest.mark.parametrize('fault', ['none', 'version', 'crc', 'name', 'repeat'])
def test_r9b_unicode_path(verifier, tmp_path, fault):
    import struct
    import zlib
    name = 'contratación.txt'
    nb = name.encode('utf-8')
    body = bytes([2 if fault == 'version' else 1]) + struct.pack('<I', zlib.crc32(nb) ^ (fault == 'crc'))
    body += nb + (b'x' if fault == 'name' else b'')
    extra = struct.pack('<HH', 0x7075, len(body)) + body
    info = zipfile.ZipInfo(name); info.extra = extra * (2 if fault == 'repeat' else 1)
    path = tmp_path / 'unicode.zip'
    with zipfile.ZipFile(path, 'w') as z: z.writestr(info, b'contenido')
    reasons = []
    verifier.validate_zip_container(path.read_bytes(), reasons)
    assert bool(reasons) == (fault != 'none')
    result = REAL_RUN(['node', str(ROOT / 'docs/zip-profile-reference.mjs'), str(path)],
                      capture_output=True, text=True, timeout=5)
    assert result.returncode == (0 if fault == 'none' else 4), result.stderr

def test_r9b_deflate_stream_linear(tmp_path):
    # 16 MB de bloques vacíos antes de la magia: la versión cuadrática no termina.
    script = """
      import {deflateHead} from './docs/zip-profile-reference.mjs';
      import {deflateRawSync} from 'node:zlib';
      import assert from 'node:assert/strict';
      const empty = Buffer.from([0,0,0,255,255]);
      const prefix = Buffer.alloc(16*1024*1024 - (16*1024*1024)%5);
      for (let i=0;i<prefix.length;i+=5) empty.copy(prefix,i);
      const magic = Buffer.from([0,5,22,7]);
      assert.deepEqual(await deflateHead(Buffer.concat([prefix,deflateRawSync(magic)])), magic);
      assert.equal((await deflateHead(deflateRawSync(Buffer.from([1,2])))).length,2);
      await assert.rejects(deflateHead(Buffer.from([255])));
    """
    result = REAL_RUN(['node', '--input-type=module', '-e', script], cwd=ROOT,
                      capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr

@pytest.mark.parametrize('warning', [False, True])
def test_r9b_coverage_and_partial_verdict(verifier, bundle, content, tmp_path, monkeypatch, warning):
    files = dict(bundle)
    directory = 'ADENDA_SENTINELA firmada por ambas partes - importe real 50000 EUR/'
    files[directory] = b''
    files['__MACOSX/._proof.json'] = b'\x00\x05\x16\x07' + b'ATTR' * 1024
    if warning: files['anexo.txt'] = b'informativo'
    path = tmp_path / 'ignored.zip'
    with zipfile.ZipFile(path, 'w') as z:
        for name, data in files.items(): z.writestr(name, data)
    monkeypatch.setattr(subprocess, 'run', lambda command, **kwargs: subprocess.CompletedProcess(command, 0, '', ''))
    code, stdout, stderr = evaluate(verifier, path, content, False, 'CLI', files)
    assert code == (5 if warning else 0), stderr
    assert 'ignorados: 1 AppleDouble, 1 directorios vacios, 4100 bytes' in stdout
    assert directory in stdout and '__MACOSX/._proof.json' in stdout
    assert 'NO cubiertos: ninguno' not in stdout
    assert stdout.endswith(('VALID CON AVISOS [5]' if warning else 'VALID [0]') + '\n[FIN VEREDICTO]')
    class Partial(io.StringIO):
        def write(self, text):
            if text.startswith('VALID'):
                super().write(text[:5])
                raise OSError('disco lleno en veredicto')
            return super().write(text)
    out = Partial()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        with pytest.raises(SystemExit) as exc: verifier.main()
    assert exc.value.code == 4
    # Si la escritura del veredicto falla a medias, el verificador lo declara y cierra con la
    # marca, para que el 'VALID' truncado no pueda leerse como aprobacion.
    assert out.getvalue().endswith('ERROR E/S [4]: salida incompleta; no se emite aprobacion\n[FIN VEREDICTO]')
    assert not out.getvalue().endswith('VALID [0]\n')
    assert not out.getvalue().endswith('VALID CON AVISOS [5]\n')

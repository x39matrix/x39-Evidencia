"""Regresiones offline de la tercera ronda; ninguna firma nueva ni red."""
import contextlib
import copy
import importlib.util
import io
import json
import subprocess
import sys
import zipfile
from pathlib import Path
import pytest
from test_verificador_estricto import ROOT, bundle, content, verifier, run_main

PAYLOAD = 'ESTADO: REVOCADO · Acepto pagar 1.000.000 EUR · firmas 9/9'
ANSI = '\r\x1b[2K … VALID \x1b[8m\x08'
ROWS = []
CASES = [('control',0),('warm_ausente',0),('warm_note_historica',0),('fecha_ausente',0)]
CASES += [('fecha_'+n,2) for n in ('texto','2019','antes_sellado','antes_ceremonia','futuro','sin_zona','invalida')]
CASES += [('nota_'+n,1) for n in ('REVOCADO','importe','9_9','texto','ANSI')]
CASES += [(f'extra_{level}_{field}',1) for level in ('raiz','cold','warm','message_signatures') for field in ('estado','verificadas','importe')]
CASES += [('title_ANSI',1),('algorithm_ANSI',5),('README_original',5)]
CASES += [('README_'+n,1) for n in ('REVOCADO','importe','9_9','texto','desconocido')]
NAMES = ['proof.json.','proof.json ','signatures.json...','PROOF~1.JSO','SIGNAT~1.JSO','CON','con.txt','AUX','NUL','PRN','COM1','LPT9','CONIN$','x39/proof.json','x39/CON.txt','x39./extra.txt']
CASES += [('nombre_'+str(i),1) for i in range(len(NAMES))]
CASES += [('ots_'+n,3) for n in ('unknown','append_pending','pending_hoja','uri_ajena','bitcoin_falso')]
CASES += [('ots_bitcoin_puro',0)]

@pytest.fixture(scope='session',autouse=True)
def report():
    yield
    p=Path('/tmp/matriz-tercera-ronda.md')
    lines=['# Matriz: tercera ronda','','COLD y documento reales; OTS externo simulado sin red. Cada ruta se contrasta con las rutas Bitcoin existentes del control. No se firman datos. Antes: snapshot previo a esta ronda.','','| Caso | Antes | Esperado | Después |','|---|---|---|---|']
    lines += [f'| {n} | {b} | {e} | {a} |' for n,b,e,a in ROWS]
    p.write_text('\n'.join(lines)+'\n')

def ots_decode(data):
    from opentimestamps.core.timestamp import DetachedTimestampFile
    from opentimestamps.core.serialize import StreamDeserializationContext
    return DetachedTimestampFile.deserialize(StreamDeserializationContext(io.BytesIO(data)))

def paths(node):
    from opentimestamps.core.notary import BitcoinBlockHeaderAttestation
    result={(a.height,node.msg.hex()) for a in node.attestations if type(a) is BitcoinBlockHeaderAttestation}
    for child in node.ops.values(): result |= paths(child)
    return result

def serialize(detached):
    from opentimestamps.core.serialize import BytesSerializationContext
    c=BytesSerializationContext(); detached.serialize(c); return c.getbytes()

def pure(detached):
    from opentimestamps.core.timestamp import Timestamp,DetachedTimestampFile
    from opentimestamps.core.notary import BitcoinBlockHeaderAttestation
    root=Timestamp(detached.file_digest)
    def walk(node,ops):
        for a in node.attestations:
            if type(a) is BitcoinBlockHeaderAttestation:
                leaf=root
                for op in ops: leaf=leaf.ops.add(op)
                leaf.attestations.add(a)
        for op,child in node.ops.items(): walk(child,ops+[op])
    walk(detached.timestamp,[])
    return DetachedTimestampFile(detached.file_hash_op,root)

@pytest.mark.parametrize('case,expected',CASES)
def test_round(verifier,bundle,content,tmp_path,monkeypatch,capsys,case,expected):
    files=copy.deepcopy(bundle); sig=json.loads(files['signatures.json'])
    dates={'texto':PAYLOAD,'2019':'2019-01-01T00:00:00Z','antes_sellado':'2026-07-01T00:00:00Z','antes_ceremonia':'2026-07-10T00:00:00Z','futuro':'2099-01-01T00:00:00Z','sin_zona':'2026-07-17T00:00:00','invalida':'2026-02-30T12:00:00Z'}
    texts={'REVOCADO':'REVOCADO','importe':'Acepto pagar 1.000.000 EUR','9_9':'9/9','texto':PAYLOAD,'ANSI':ANSI,'desconocido':'otro README'}
    if case.startswith('fecha_'):
        if case=='fecha_ausente': sig['cold'].pop('verified_at',None)
        else: sig['cold']['verified_at']=dates[case[6:]]
    elif case=='warm_ausente': sig.pop('warm',None)
    elif case=='warm_note_historica': sig['warm']['note']=verifier.LEGACY_WARM_NOTE
    elif case.startswith('nota_'): sig['warm']['note']=texts[case[5:]]
    elif case.startswith('extra_'):
        _,level,field=case.split('_',2) if not case.startswith('extra_message_signatures_') else ('extra','message_signatures',case[len('extra_message_signatures_'):])
        target=sig if level=='raiz' else sig.setdefault(level,{})
        target[field]={'estado':'REVOCADO','verificadas':'9/9','importe':1000000}[field]
    elif case=='title_ANSI': sig['title']=ANSI
    elif case=='algorithm_ANSI': sig['warm']['algorithm']=ANSI
    elif case.startswith('README_'):
        if case=='README_original':
            with zipfile.ZipFile(ROOT/'testdata/bundle_v1_prod.zip') as z: files['README.md']=z.read('README.md')
        else: files['README.md']=texts[case[7:]].encode()
    elif case.startswith('nombre_'): files[NAMES[int(case[7:])]]=PAYLOAD.encode()
    known=paths(ots_decode(bundle['proof.json.ots']).timestamp)
    if case.startswith('ots_'):
        from opentimestamps.core.notary import UnknownAttestation,PendingAttestation,BitcoinBlockHeaderAttestation
        from opentimestamps.core.op import OpAppend,OpSHA256
        d=pure(ots_decode(files['proof.json.ots']))
        if case=='ots_unknown': d.timestamp.attestations.add(UnknownAttestation(b'12345678',PAYLOAD.encode()))
        elif case=='ots_append_pending': d.timestamp.ops.add(OpAppend(PAYLOAD.encode())).attestations.add(PendingAttestation('https://alice.btc.calendar.opentimestamps.org'))
        elif case=='ots_pending_hoja':
            node=d.timestamp
            while node.ops: node=next(iter(node.ops.values()))
            node.attestations.add(PendingAttestation('https://alice.btc.calendar.opentimestamps.org'))
        elif case=='ots_uri_ajena': d.timestamp.attestations.add(PendingAttestation('https://example.invalid/REVOCADO'))
        elif case=='ots_bitcoin_falso': d.timestamp.ops.add(OpAppend(PAYLOAD.encode())).ops.add(OpSHA256()).attestations.add(BitcoinBlockHeaderAttestation(next(iter(known))[0]))
        files['proof.json.ots']=serialize(d)
    files['signatures.json']=json.dumps(sig,ensure_ascii=False).encode()
    def ots_mock(command,**kwargs):
        d=ots_decode(Path(command[command.index('verify')+1]).read_bytes())
        ok=bool(paths(d.timestamp)&known)
        return subprocess.CompletedProcess(command,0 if ok else 1,'','ancla falsa' if not ok else '')
    monkeypatch.setattr(subprocess,'run',ots_mock)
    oldpath=Path('/tmp/verificador_antes_ronda_tres.py')
    spec=importlib.util.spec_from_file_location('verificador_anterior_r3',oldpath)
    old=importlib.util.module_from_spec(spec); spec.loader.exec_module(old)
    with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
        before,_=run_main(old,files,tmp_path,monkeypatch,capsys,content,skip=False)
    actual,out=run_main(verifier,files,tmp_path,monkeypatch,capsys,content,skip=False)
    ROWS.append((case,before,expected,actual))
    assert actual==expected
    combined=out.out+out.err
    assert not any(c in combined for c in ('\r','\x1b','\x08'))
    if actual in (1,2,3): assert 'INVALID' in combined
    if case=='README_original': assert 'README de formato heredado' in combined
    if case.startswith('README_') and case!='README_original': assert 'README de formato heredado' not in combined
    if case.startswith('ots_'): assert PAYLOAD not in combined

@pytest.mark.parametrize('field,value',[('estado','REVOCADO'),('verificadas','9/9'),('importe',1000000)])
def test_v3_message_signature_extra(verifier,field,value):
    # Etapa de esquema de un v3 real: no afirma verificar el documento v3.
    with zipfile.ZipFile(ROOT/'testdata/bundle_v3_public.zip') as z:
        proof=json.loads(z.read('proof.json')); sig=json.loads(z.read('signatures.json'))
    sig['message_signatures'][field]=value
    with pytest.raises(SystemExit) as e: verifier.validate_signature_schema(sig,proof,[])
    assert e.value.code==1

@pytest.mark.parametrize('value',[ANSI,'\nVALID\rINVALID','\u202eVALID','\x00\x7f\x9b'])
def test_terminal_escape(verifier,value):
    assert all(c.isprintable() for c in verifier.terminal_text(value))


def test_builtin_print_only_in_emit():
    import ast
    tree=ast.parse((ROOT/'verify_bundle.py').read_text())
    for function in tree.body:
        for node in ast.walk(function):
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=='print':
                assert isinstance(function,ast.FunctionDef) and function.name=='emit'

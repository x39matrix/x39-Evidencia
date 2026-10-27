"""Salida HTML publica: texto y atributos seguros, sin servidor, Mongo, claves ni red.

Se ejecutan las funciones reales extraidas por AST; no se importa notaria.py,
que inicializa Mongo y el autotest criptografico. Esto prueba la representacion
HTML, no la configuracion de CORS/CSP ni un recorrido HTTP en produccion.
"""
import ast
import asyncio
import copy
import re
from html.parser import HTMLParser
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
AID = "488a053fbd4874193a1e"
BASE = "https://x39matrix.org"
ATTACK = '\"><img src=x onerror="probe()"><script>probe()</script>&'


class Parsed(HTMLParser):
    def __init__(self, source):
        super().__init__(convert_charrefs=True)
        self.tags = []
        self.text = []
        self.feed(source)
        self.close()

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, attrs))

    def handle_data(self, data):
        self.text.append(data)

    def shape(self):
        # Incluye todos los nombres (tambien duplicados), no solo un diccionario.
        return [(tag, [name for name, _ in attrs]) for tag, attrs in self.tags]

    def meta(self, name):
        return next(dict(attrs)["content"] for tag, attrs in self.tags
                    if tag == "meta" and
                    (dict(attrs).get("property") == name or dict(attrs).get("name") == name))

    def hrefs(self):
        return [dict(attrs)["href"] for tag, attrs in self.tags if tag == "a"]


class MissingProof(Exception):
    def __init__(self, status, detail):
        self.status_code = status
        self.detail = detail


@pytest.fixture
def render():
    source = ast.parse((ROOT / "backend/notaria.py").read_text())
    functions = [node for node in source.body
                 if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                 and node.name in {"_clean", "public_html"}]
    assert {node.name for node in functions} == {"_clean", "public_html"}
    for node in functions:
        node.decorator_list = []
    safe = [node for node in source.body if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "SAFE" for target in node.targets)]
    imports = [node for node in source.body if isinstance(node, ast.ImportFrom)
               and node.module in {"html", "urllib.parse"}]
    code = compile(ast.fix_missing_locations(ast.Module(body=imports + safe + functions,
                                                        type_ignores=[])), "public_html", "exec")

    def call(*, changes=None, block=None, aid=AID, base=BASE, exists=True):
        doc = {"title": "Acuerdo de prueba", "content_hash": "a" * 64,
               "proof": {"proof_hash": "b" * 64}, "sealed_at": "2026-09-08T16:14:47+00:00"}
        for name, value in (changes or {}).items():
            if name == "proof_hash":
                doc["proof"][name] = value
            else:
                doc[name] = value
        original = copy.deepcopy(doc)
        queries, refreshes = [], []

        def find(query, projection):
            queries.append((query, projection))
            return doc if exists else None

        async def refresh(item):
            refreshes.append(item)
            return {"status": "anchored_btc" if block is not None else "pending", "btc_block": block}

        ns = {"re": re, "os": SimpleNamespace(environ={} if base is None else {"REACT_APP_BACKEND_URL": base}),
              "na": SimpleNamespace(find_one=find), "_refresh_ots": refresh,
              "Request": object, "HTTPException": MissingProof, "HTMLResponse": lambda body: body}
        exec(code, ns)
        # Las cabeceras no pueden intervenir en el origen configurado.
        request = SimpleNamespace(headers={"host": 'evil.invalid/\"><script>probe()</script>',
                                           "x-forwarded-host": "evil.invalid"})
        try:
            html = asyncio.run(ns["public_html"](aid, request))
        finally:
            assert queries == [({"agreement_id": aid, "status": "sealed"}, {"_id": 0})]
            assert doc == original, "escapar la salida no debe alterar los datos almacenados"
            assert len(refreshes) == int(exists)
        return html, Parsed(html)

    return call


@pytest.mark.parametrize("block", [None, 966105], ids=["pendiente", "confirmado"])
def test_pagina_normal_conserva_datos_y_enlaces(render, block):
    html, page = render(block=block)
    assert page.meta("og:url") == f"{BASE}/api/notaria/p/{AID}"
    assert page.meta("og:image") == f"{BASE}/og_notaria.jpg"
    assert page.meta("og:title") == "X-39 Notaria — Acuerdo de prueba"
    assert page.meta("twitter:title") == page.meta("og:title")
    assert page.meta("twitter:description") == page.meta("og:description")
    assert page.meta("twitter:image") == page.meta("og:image")
    expected = [f"{BASE}/certificado/{AID}", f"{BASE}/verificar"]
    if block is not None:
        expected.insert(0, "https://mempool.space/block/966105")
        assert "Confirmado en bloque Bitcoin #966105" in "".join(page.text)
    else:
        assert "Pendiente de confirmacion" in "".join(page.text)
        assert "mempool.space/block/" not in html
    assert page.hrefs() == expected
    assert "a" * 64 in page.text and "b" * 64 in page.text
    assert "2026-09-08T16:14:47+00:00" in page.text
    assert "evil.invalid" not in html


@pytest.mark.parametrize("field", ["content_hash", "proof_hash", "sealed_at"])
def test_campos_mongo_son_texto_y_no_etiquetas(render, field):
    _, normal = render()
    _, page = render(changes={field: ATTACK})
    assert page.shape() == normal.shape()
    assert ATTACK in page.text


@pytest.mark.parametrize("title", ['Ana & Beto "equipo" \'prueba\' &quot;',
                                   'acuerdo" onmouseover="probe()',
                                   "a" * 79 + '&"fuera'])
def test_titulo_no_abre_atributos_y_se_escapa_una_vez(render, title):
    _, normal = render()
    _, page = render(changes={"title": title})
    expected = title[:80]
    assert page.shape() == normal.shape()
    assert page.meta("og:title") == "X-39 Notaria — " + expected
    assert page.meta("twitter:title") == page.meta("og:title")
    assert expected in page.text


def test_bloque_malformado_no_inyecta_html_ni_atributos(render):
    _, normal = render(block=966105)
    _, page = render(block=ATTACK)
    assert page.shape() == normal.shape()
    assert page.meta("og:description") == (
        f"Prueba de acuerdo anclada en Bitcoin. Confirmado en bloque Bitcoin #{ATTACK}. "
        "Verificable por cualquiera, gratis.")
    assert "mempool.space/block/" + ATTACK in page.text
    href = page.hrefs()[0]
    assert href.startswith("https://mempool.space/block/")
    assert not any(char in href for char in '\"<>#&')


def test_id_malformado_no_sale_del_segmento_ni_abre_atributos(render):
    _, normal = render()
    _, page = render(aid=ATTACK + "?x=1#fragmento")
    assert page.shape() == normal.shape()
    cert = page.hrefs()[0]
    assert cert.startswith(BASE + "/certificado/")
    assert not any(char in cert for char in '\"<>?&#')
    assert page.meta("og:url").split("/api/notaria/p/", 1)[1] == cert.split("/certificado/", 1)[1]


@pytest.mark.parametrize("base", [None, "", BASE + "/", BASE + "///"])
def test_base_por_defecto_y_barras_finales(render, base):
    _, page = render(base=base)
    assert page.hrefs() == [f"{BASE}/certificado/{AID}", f"{BASE}/verificar"]
    assert page.meta("og:url") == f"{BASE}/api/notaria/p/{AID}"


def test_base_configurada_no_inyecta_atributos(render):
    base = 'https://example.test/" onload="probe()&quot;'
    _, normal = render()
    _, page = render(base=base)
    assert page.shape() == normal.shape()
    assert page.hrefs() == [f"{base}/certificado/{AID}", f"{base}/verificar"]
    assert page.meta("og:url") == f"{base}/api/notaria/p/{AID}"
    assert page.meta("og:image") == f"{base}/og_notaria.jpg"


def test_ausente_conserva_404_sin_refrescar(render):
    with pytest.raises(MissingProof) as error:
        render(exists=False)
    assert error.value.status_code == 404
    assert error.value.detail == "Prueba no encontrada"

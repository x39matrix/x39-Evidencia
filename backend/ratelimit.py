"""Limites de peticiones por IP (slowapi).
La IP real llega en X-Forwarded-For: Caddy la sobrescribe con {remote_host} y uvicorn la acepta
solo desde 127.0.0.1 (--proxy-headers --forwarded-allow-ips=127.0.0.1)."""
import logging

from slowapi import Limiter
from slowapi.util import get_remote_address


class _SinIP(logging.Filter):
    """slowapi registra la IP en el aviso 'ratelimit ... (IP) exceeded'; se descarta ese aviso
    para que la IP no llegue al journal. Los errores operativos de slowapi se siguen registrando."""
    def filter(self, record):
        return not str(record.msg).startswith("ratelimit ")


logging.getLogger("slowapi").addFilter(_SinIP())

# Limite global por IP para cualquier ruta sin limite propio.
# NOTA: headers_enabled=True exige que cada endpoint decorado reciba response: Response o devuelva un Response; si no, 500.
limiter = Limiter(key_func=get_remote_address, default_limits=["300/minute"])

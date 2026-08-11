#!/usr/bin/env python3
"""
Proxy local para el enriquecimiento de PhishTriage.

Para que las claves de API NO vivan en el navegador. Levanta esto en tu equipo,
pon http://127.0.0.1:8787 en el campo "Proxy" de la web y listo: la pagina pide
al proxy, el proxy pone la clave desde una variable de entorno y devuelve el JSON
con las cabeceras CORS necesarias.

    export VT_API_KEY=...
    export ABUSEIPDB_API_KEY=...
    python3 cli/proxy.py                 # escucha en 127.0.0.1:8787

Rutas:
    GET /vt/{files|domains|urls|ip_addresses}/{id}
    GET /abuseipdb/check?ipAddress=1.2.3.4&maxAgeInDays=90
    GET /health

Escucha solo en loopback y solo acepta Origin de localhost/127.0.0.1 y, si lo
indicas con --allow-origin, del dominio que le digas (por ejemplo tu GitHub Pages).
Es una herramienta de desarrollo: no la expongas a Internet.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from phishtriage import load_dotenv
except ImportError:  # ejecutado desde otro sitio
    def load_dotenv():
        return None

VT_KINDS = {"files", "domains", "urls", "ip_addresses"}
ALLOWED = {"http://127.0.0.1", "http://localhost", "https://127.0.0.1", "https://localhost"}
EXTRA_ORIGIN = None


def origin_ok(origin: str) -> bool:
    if not origin:
        return True
    base = re.sub(r"(:\d+)$", "", origin)
    if base in ALLOWED:
        return True
    return bool(EXTRA_ORIGIN and origin.rstrip("/") == EXTRA_ORIGIN.rstrip("/"))


class Handler(BaseHTTPRequestHandler):
    server_version = "PhishTriageProxy/1.0"

    def log_message(self, fmt, *args):
        sys.stderr.write("  %s - %s\n" % (self.address_string(), fmt % args))

    def _cors(self, origin):
        self.send_header("Access-Control-Allow-Origin", origin or "*")
        self.send_header("Access-Control-Allow-Headers", "content-type, accept")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Vary", "Origin")

    def _send(self, code, payload, origin):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._cors(origin)
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):  # noqa: N802
        origin = self.headers.get("Origin", "")
        self.send_response(204)
        self._cors(origin if origin_ok(origin) else "null")
        self.end_headers()

    def do_GET(self):  # noqa: N802
        origin = self.headers.get("Origin", "")
        if not origin_ok(origin):
            self._send(403, {"error": "origen no permitido: " + origin}, "null")
            return

        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path in ("/health", ""):
            self._send(200, {"ok": True,
                             "virustotal": bool(os.environ.get("VT_API_KEY")),
                             "abuseipdb": bool(os.environ.get("ABUSEIPDB_API_KEY"))}, origin)
            return

        try:
            if path.startswith("/vt/"):
                parts = path[4:].split("/", 1)
                if len(parts) != 2 or parts[0] not in VT_KINDS:
                    self._send(400, {"error": "ruta VT invalida"}, origin)
                    return
                key = os.environ.get("VT_API_KEY", "")
                if not key:
                    self._send(503, {"error": "VT_API_KEY no configurada en el proxy"}, origin)
                    return
                ident = urllib.parse.unquote(parts[1])
                url = "https://www.virustotal.com/api/v3/%s/%s" % (
                    parts[0], urllib.parse.quote(ident, safe=""))
                data = self._fetch(url, {"x-apikey": key, "accept": "application/json"})
            elif path == "/abuseipdb/check":
                key = os.environ.get("ABUSEIPDB_API_KEY", "")
                if not key:
                    self._send(503, {"error": "ABUSEIPDB_API_KEY no configurada en el proxy"}, origin)
                    return
                qs = urllib.parse.parse_qs(parsed.query)
                ip = (qs.get("ipAddress") or [""])[0]
                days = (qs.get("maxAgeInDays") or ["90"])[0]
                if not ip:
                    self._send(400, {"error": "falta ipAddress"}, origin)
                    return
                url = ("https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=%s"
                       % (urllib.parse.quote(ip), urllib.parse.quote(days)))
                data = self._fetch(url, {"Key": key, "Accept": "application/json"})
            else:
                self._send(404, {"error": "ruta desconocida"}, origin)
                return
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            try:
                payload = json.loads(body)
            except ValueError:
                payload = {"error": body[:400]}
            self._send(e.code, payload, origin)
            return
        except Exception as e:  # noqa: BLE001
            self._send(502, {"error": str(e)}, origin)
            return

        self._send(200, data, origin)

    def _fetch(self, url, headers):
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=25) as res:
            return json.loads(res.read().decode("utf-8", errors="replace"))


def main():
    global EXTRA_ORIGIN
    load_dotenv()
    ap = argparse.ArgumentParser(description="Proxy local de enriquecimiento para PhishTriage")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--allow-origin", default=None,
                    help="origen extra permitido, p.ej. https://usuario.github.io")
    args = ap.parse_args()
    EXTRA_ORIGIN = args.allow_origin

    if args.host not in ("127.0.0.1", "localhost", "::1"):
        sys.stderr.write("AVISO: escuchando fuera de loopback. Tus claves quedan expuestas "
                         "a cualquiera que alcance este puerto.\n")

    print(f"PhishTriage proxy en http://{args.host}:{args.port}")
    print("  VirusTotal :", "configurado" if os.environ.get("VT_API_KEY") else "SIN CLAVE")
    print("  AbuseIPDB  :", "configurado" if os.environ.get("ABUSEIPDB_API_KEY") else "SIN CLAVE")
    if EXTRA_ORIGIN:
        print("  origen extra permitido:", EXTRA_ORIGIN)
    print("Ctrl+C para parar.")
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nadios")

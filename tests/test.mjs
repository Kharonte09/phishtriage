/**
 * Pruebas de PhishTriage. Un solo fichero, sin dependencias obligatorias.
 *
 *   node tests/test.mjs                  motor
 *   npm i jsdom && node tests/test.mjs   motor + interfaz
 *
 * Si jsdom no está instalado, la parte de interfaz se salta sin fallar.
 */
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const PT = require(path.join(ROOT, 'assets/parser.js'));

let ok = 0, mal = 0;
const check = (n, c, extra) => c
  ? (ok++, console.log('  ok   ' + n))
  : (mal++, console.log('  FALLA ' + n + (extra ? '  -> ' + extra : '')));
const analizar = (txt, nombre) => PT.analyze(PT.bytesToLatin1(new TextEncoder().encode(txt)), { filename: nombre });

// --- correo de phishing sintético (inofensivo: los adjuntos son texto) -------
const HTML = '<html><body><p><b>Su cuenta ser&aacute; suspendida en 24 horas.</b></p>'
  + '<p><a href="http://microsoft-login.verify-account.tk/o365/login.php">https://login.microsoftonline.com</a></p>'
  + '<p><a href="http://185.199.110.153:8080/update">Revisar</a></p>'
  + '<p><a href="https://xn--micrsoft-y0a.com/portal">Portal</a></p>'
  + '<form action="http://microsoft-login.verify-account.tk/collect.php"><input type="password" name="p"></form>'
  + '</body></html>';
const b64 = s => Buffer.from(s, 'utf8').toString('base64').match(/.{1,76}/g).join('\r\n');

const PHISHING = [
  'Received: from vps.cheap-hosting.ru (vps.cheap-hosting.ru [185.220.101.44])',
  ' by mx1.corp.es (Postfix) with ESMTP id 3D19A; Mon, 10 Aug 2026 09:14:31 +0200',
  'Received: from localhost (unknown [45.155.205.233]) by vps.cheap-hosting.ru',
  ' (Exim 4.94) with SMTP id 1rXk2P; Mon, 10 Aug 2026 07:12:03 +0000',
  'Authentication-Results: mx1.corp.es; spf=fail smtp.mailfrom=bounce@cheap-hosting.ru;',
  ' dkim=none header.d=none; dmarc=fail header.from=microsoft.com',
  'Return-Path: <bounce@cheap-hosting.ru>',
  'From: =?utf-8?B?TWljcm9zb2Z0IDM2NSBTZWd1cmlkYWQ=?= <no-reply@micros0ft-security.tk>',
  'Reply-To: "Soporte" <recovery@mail-verify.xyz>',
  'To: maria@corp.es',
  'Subject: =?utf-8?Q?ACCI=C3=93N_REQUERIDA=3A_cuenta_suspendida?=',
  'Message-ID: <20260810@vps.cheap-hosting.ru>',
  'Date: Mon, 10 Aug 2026 09:12:01 +0200',
  'X-Mailer: PHPMailer 6.8.0',
  'MIME-Version: 1.0',
  'Content-Type: multipart/mixed; boundary="=_b1"',
  '',
  '--=_b1',
  'Content-Type: text/html; charset="utf-8"',
  'Content-Transfer-Encoding: base64',
  '',
  b64(HTML),
  '--=_b1',
  'Content-Type: application/vnd.ms-word.document.macroEnabled.12; name="Detalles.docm"',
  'Content-Transfer-Encoding: base64',
  'Content-Disposition: attachment; filename="Factura.pdf.docm"',
  '',
  b64('PKFALSO-OOXML-CON-MACROS'),
  '--=_b1--',
  ''
].join('\r\n');

const BOLETIN = [
  'Authentication-Results: mx.corp.es; spf=pass smtp.mailfrom=news.tienda.com;',
  ' dkim=pass header.d=tienda.com; dmarc=pass header.from=tienda.com',
  'Received: from mx.news.tienda.com (mx.news.tienda.com [93.184.216.34]) by mx.corp.es',
  ' with ESMTPS id A1; Mon, 10 Aug 2026 09:00:00 +0200',
  'From: Tienda <ofertas@tienda.com>',
  'To: maria@corp.es',
  'Subject: Tu factura de julio ya esta disponible',
  'Message-ID: <a1@tienda.com>',
  'Date: Mon, 10 Aug 2026 09:00:00 +0200',
  'Content-Type: text/html; charset="utf-8"',
  '',
  '<html><body><p>Tu factura: <a href="https://tienda.com/facturas">Verla</a></p></body></html>',
  ''
].join('\r\n');

// --- motor -------------------------------------------------------------------
console.log('\n== motor ==');
const r = await analizar(PHISHING, 'phishing.eml');
const n = await analizar(BOLETIN, 'boletin.eml');
const ids = r.findings.map(f => f.id);

check('el phishing sale CRÍTICO', r.verdict === 'CRITICO', r.verdict + ' ' + r.score);
check('el correo legítimo sale BAJO', n.verdict === 'BAJO', n.verdict + ' ' + n.score + ' ' + n.findings.map(f => f.id));
check('los separa por más de 60 puntos', r.score - n.score >= 60, r.score + ' vs ' + n.score);
check('asunto RFC 2047 decodificado', /ACCIÓN REQUERIDA/.test(r.summary.subject), r.summary.subject);
check('cadena Received en orden cronológico', r.received.length === 2 && r.received[0].from === 'localhost');
check('primera IP pública como origen', r.summary.originIP === '45.155.205.233', String(r.summary.originIP));
check('IP privada no cuenta como origen', PT.isPrivateIP('10.20.0.5') && !PT.isPrivateIP('45.155.205.233'));
check('dominio organizativo con sufijo doble', PT.orgDomain('mail.foo.co.uk') === 'foo.co.uk');
check('defang', PT.defang('http://evil.com/a') === 'hxxp://evil[.]com/a');
check('md5 conocido', PT.md5(new TextEncoder().encode('abc')) === '900150983cd24fb0d6963f7d28e17f72');
check('sha256 del adjunto', /^[0-9a-f]{64}$/.test(r.attachments[0].sha256 || ''), String(r.attachments[0].sha256));
check('detecta el enlace que engaña', ids.includes('url-mismatch'));
check('detecta el dominio punycode', ids.includes('url-punycode'));
check('detecta el enlace a una IP', ids.includes('url-ip'));
check('detecta el adjunto con macros', ids.includes('att-macro'));
check('detecta la doble extensión', ids.includes('att-double'));
check('detecta el campo de contraseña', ids.includes('body-password'));
check('detecta el remitente suplantado', ids.includes('dn-brand'));

console.log('\n== ponderación ==');
const pesos = (() => {
  const src = fs.readFileSync(path.join(ROOT, 'assets/parser.js'), 'utf8');
  const bloque = src.slice(src.search(/const PESOS = \{/));
  return new Set(Array.from(bloque.slice(0, bloque.search(/\n\s*\};/))
    .matchAll(/'([a-z0-9-]+)':\s*\{ cat:/g)).map(m => m[1]));
})();
check('los techos suman 100', r.scoreBreakdown.reduce((s, d) => s + d.techo, 0) === 100);
check('ninguna categoría se pasa de su techo', r.scoreBreakdown.every(d => d.puntos <= d.techo));
check('el total es la suma del desglose', r.scoreBreakdown.reduce((s, d) => s + d.puntos, 0) === r.score);
check('cada regla que dispara tiene su peso', ids.every(i => pesos.has(i)),
  ids.filter(i => !pesos.has(i)).join());

// --- interfaz (solo si hay jsdom) --------------------------------------------
let JSDOM;
try { ({ JSDOM } = require('jsdom')); } catch (e) { /* opcional */ }

if (!JSDOM) {
  console.log('\n(sin jsdom: se salta la interfaz. npm i jsdom para probarla)');
} else {
  console.log('\n== interfaz ==');
  const dom = new JSDOM(fs.readFileSync(path.join(ROOT, 'index.html'), 'utf8'), {
    url: 'http://127.0.0.1:8000/', runScripts: 'dangerously',
    beforeParse(w) {
      Object.defineProperty(w, 'crypto', { value: globalThis.crypto, configurable: true });
      w.alert = m => console.log('ALERT:', m);
      w.scrollTo = () => {};
    }
  });
  const w = dom.window, d = w.document;
  for (const f of ['assets/parser.js', 'assets/ui.js']) {
    const s = d.createElement('script');
    s.textContent = fs.readFileSync(path.join(ROOT, f), 'utf8');
    d.body.appendChild(s);
  }

  // Se simula que el usuario suelta el fichero. Un objeto con name y
  // arrayBuffer() basta y evita depender de la versión de jsdom.
  const bytes = new TextEncoder().encode(PHISHING);
  const ev = new w.Event('drop', { bubbles: true });
  Object.defineProperty(ev, 'dataTransfer', {
    value: { files: [{ name: 'phishing.eml', arrayBuffer: async () => bytes.buffer }] }
  });
  d.querySelector('#drop').dispatchEvent(ev);

  const t0 = Date.now();
  while (d.querySelector('#result').hidden && Date.now() - t0 < 20000) {
    await new Promise(res => setTimeout(res, 50));
  }

  check('la interfaz pinta el resultado', !d.querySelector('#result').hidden);
  check('el veredicto sale en pantalla', /CRITICO/.test(d.querySelector('#verdictTitle').textContent));
  check('la vista sencilla es la primera', d.querySelector('.panel[data-p="simple"]').classList.contains('active'));
  check('con consejos accionables', d.querySelectorAll('#p-simple ol li').length >= 3);
  check('y con enlaces a VirusTotal / AbuseIPDB',
    d.querySelectorAll('#p-simple a[href*="virustotal.com"], #p-simple a[href*="abuseipdb.com"]').length > 0);
  check('los enlaces no filtran de dónde vienen',
    Array.from(d.querySelectorAll('#p-simple a')).every(a => /noreferrer/.test(a.getAttribute('rel') || '')));
  check('el desglose de la nota se pinta', /reparte la nota/.test(d.querySelector('#p-hallazgos').textContent));
  check('los hashes llegan a la pantalla', /[0-9a-f]{64}/.test(d.querySelector('#p-adjuntos').textContent));
  // La importante: si esto falla, la web ejecutaría el phishing en vez de analizarlo
  check('EL HTML DEL CORREO NO SE EJECUTA',
    d.querySelectorAll('#p-cuerpo form, #p-cuerpo input, #p-cuerpo script, #p-cuerpo img').length === 0);
}

console.log('\n' + ok + ' ok, ' + mal + ' fallos\n');
process.exit(mal ? 1 : 0);

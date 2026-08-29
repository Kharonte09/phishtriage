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
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PT = require(path.join(ROOT, 'assets/parser.js'));

let ok = 0, mal = 0;
const check = (n, c, extra) => c
  ? (ok++, console.log('  ok   ' + n))
  : (mal++, console.log('  FALLA ' + n + (extra ? '  -> ' + extra : '')));
const analizar = (txt, nombre) => PT.analyze(PT.bytesToLatin1(new TextEncoder().encode(txt)), { filename: nombre });

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

const BEC = [
  'Authentication-Results: mx.corp.es; spf=pass smtp.mailfrom=gmail.com; dkim=pass header.d=gmail.com; dmarc=pass header.from=gmail.com',
  'Received: from mail-wr1.google.com (mail-wr1.google.com [209.85.221.50]) by mx.corp.es',
  ' with ESMTPS id A1; Mon, 10 Aug 2026 09:00:00 +0200',
  'From: "Carlos Ruiz (CEO)" <carlos.ruiz.director@gmail.com>',
  'Reply-To: carlos.ruiz.pagos@gmail.com',
  'To: maria@corp.es', 'Subject: Transferencia urgente',
  'Message-ID: <bec1@gmail.com>', 'Date: Mon, 10 Aug 2026 09:00:00 +0200',
  'Content-Type: text/html; charset="utf-8"', '',
  '<html><body><p>Necesito una transferencia hoy. Nuevo IBAN ES91 2100 0418 4502 0005 1332.',
  ' No me llames, estoy en una reunion.</p></body></html>', ''
].join('\r\n');

const BANCO = [
  'Authentication-Results: mx.corp.es; spf=pass smtp.mailfrom=bbva.es; dkim=pass header.d=bbva.es; dmarc=pass header.from=bbva.es',
  'Received: from mx.bbva.es (mx.bbva.es [195.55.20.30]) by mx.corp.es with ESMTPS id A1;',
  ' Mon, 10 Aug 2026 09:00:00 +0200',
  'From: BBVA <avisos@bbva.es>', 'To: maria@corp.es',
  'Subject: Accion requerida: verifica tu operacion en 24 horas',
  'Message-ID: <b1@bbva.es>', 'Date: Mon, 10 Aug 2026 09:00:00 +0200',
  'Content-Type: text/html; charset="utf-8"', '',
  '<html><body><p><a href="https://www.bbva.es/personas/operaciones.html">Revisar en la app</a></p></body></html>', ''
].join('\r\n');

const TIENDA = [
  'Authentication-Results: mx.corp.es; spf=pass smtp.mailfrom=steampowered.com;',
  ' dkim=pass header.d=steampowered.com; dmarc=pass header.from=steampowered.com',
  'Received: from mail.steampowered.com (mail.steampowered.com [208.64.202.36])',
  ' by mx.corp.es with ESMTPS id A1; Mon, 10 Aug 2026 09:00:00 +0200',
  'From: Steam <noreply@steampowered.com>', 'To: maria@corp.es',
  'Subject: Un juego de tu lista de deseados ya esta disponible',
  'Message-ID: <s1@steampowered.com>', 'Date: Mon, 10 Aug 2026 09:00:00 +0200',
  'Content-Type: text/html; charset="utf-8"', '',
  '<html><body>',
  '<div style="display:none;font-size:0;max-height:0;color:#ffffff">Ya disponible</div>',
  '<div style="display:none;font-size:0">preheader</div>',
  '<img src="https://cdn.akamai.steamstatic.com/store/email/logo.png">',
  '<img src="https://shared.akamai.steamstatic.com/store_item_assets/apps/374.jpg">',
  '<p><a href="https://store.steampowered.com/app/374/">Ver en la tienda</a></p>',
  '<p><a href="https://store.steampowered.com/account/notificationsettings?token=18ca">Ajustes de notificaciones</a></p>',
  '</body></html>', ''
].join('\r\n');

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
check('detecta el dominio que imita a la marca', ids.includes('from-lookalike'));

console.log('\n== casos difíciles ==');
const bec = await analizar(BEC, 'bec.eml');
const banco = await analizar(BANCO, 'banco.eml');
check('el fraude del jefe (sin enlaces ni adjuntos) llega a ALTO',
  bec.score >= 50, bec.verdict + ' ' + bec.score + ' ' + bec.findings.map(f => f.id));
check('y lo identifica como tal', bec.findings.some(f => f.id === 'combo-bec'));
check('un aviso real del banco, alarmista pero legítimo, se queda en BAJO',
  banco.verdict === 'BAJO', banco.verdict + ' ' + banco.score + ' ' + banco.findings.map(f => f.id));

const tienda = await analizar(TIENDA, 'tienda.eml');
check('un boletín real de una tienda se queda en BAJO',
  tienda.verdict === 'BAJO', tienda.verdict + ' ' + tienda.score + ' ' + tienda.findings.map(f => f.id));
check('los enlaces a la casa del propio remitente no cuentan como indicio',
  !tienda.findings.some(f => f.id === 'url-creds'));
check('"steamstatic" no se confunde con la marca "teams"',
  !tienda.findings.some(f => f.id === 'url-brand'));
check('el texto oculto de plantilla no cuenta si el correo autentica',
  !tienda.findings.some(f => f.id === 'body-hidden'));
check('las imágenes y las fuentes no se cuentan como enlaces',
  tienda.summary.urlCount === 2 && tienda.summary.resourceCount === 2,
  tienda.summary.urlCount + ' enlaces / ' + tienda.summary.resourceCount + ' recursos');

console.log('\n== ponderación ==');
const pesos = (() => {
  const src = fs.readFileSync(path.join(ROOT, 'assets/parser.js'), 'utf8');
  const bloque = src.slice(src.search(/const PESOS = \{/));
  return new Set(Array.from(bloque.slice(0, bloque.search(/\n\s*\};/))
    .matchAll(/'([a-z0-9-]+)':\s*\{ cat:/g)).map(m => m[1]));
})();
const TECHOS = (() => {
  const src = fs.readFileSync(path.join(ROOT, 'assets/parser.js'), 'utf8');
  const b = src.slice(src.indexOf('const CATEGORIAS = {'));
  const o = {};
  for (const m of b.slice(0, b.indexOf('};')).matchAll(/(\w+):\s*\{ techo: (\d+)/g)) o[m[1]] = +m[2];
  return o;
})();
check('los techos de las categorías suman 100',
  r.scoreBreakdown.filter(d => d.cat !== 'combinacion').reduce((s, d) => s + d.techo, 0) === 100);
const TECHO_COMBOS = +fs.readFileSync(path.join(ROOT, 'assets/parser.js'), 'utf8')
  .match(/const TECHO_COMBOS = (\d+)/)[1];
check('las combinaciones no pasan de su techo',
  r.scoreBreakdown.filter(d => d.cat === 'combinacion').every(d => d.puntos <= TECHO_COMBOS));
check('ninguna categoría se pasa de su techo', r.scoreBreakdown.every(d => d.puntos <= d.techo));
check('el total es la suma del desglose, con tope 100',
  Math.min(100, r.scoreBreakdown.reduce((s, d) => s + d.puntos, 0)) === r.score);
check('cada regla que dispara tiene su peso',
  ids.filter(i => !i.startsWith('combo-')).every(i => pesos.has(i)),
  ids.filter(i => !i.startsWith('combo-') && !pesos.has(i)).join());



const ESP = [
  'Authentication-Results: mx.corp.es; spf=pass smtp.mailfrom=mail112.suw15.mcsv.net;',
  ' dkim=pass header.d=marca.com; dmarc=pass header.from=marca.com',
  'Received: from mail112.suw15.mcsv.net (mail112.suw15.mcsv.net [198.2.134.112])',
  ' by mx.corp.es with ESMTPS id A1; Mon, 10 Aug 2026 09:00:00 +0200',
  'Return-Path: <bounce-mc.us1_123@mail112.suw15.mcsv.net>',
  'From: Marca <hola@marca.com>', 'Reply-To: hola@marca.com', 'To: maria@corp.es',
  'Subject: Novedades de agosto', 'Message-ID: <1@mail112.suw15.mcsv.net>',
  'List-Unsubscribe: <https://marca.us1.list-manage.com/unsubscribe?u=1>',
  'Date: Mon, 10 Aug 2026 09:00:00 +0200', 'Content-Type: text/html; charset="utf-8"', '',
  '<html><body><p>Hola, esto es el boletin de agosto con las novedades de la tienda',
  ' y algunas ofertas que te pueden interesar durante todo el mes.</p>',
  '<a href="https://marca.us1.list-manage.com/track/click?u=1&id=2">Ver las ofertas</a>',
  '</body></html>', ''
].join('\r\n');

const LISTA = [
  'ARC-Seal: i=1; a=rsa-sha256; d=lista.org; s=arc; b=abc',
  'ARC-Authentication-Results: i=1; lista.org; spf=pass smtp.mailfrom=autor.com;',
  ' dkim=pass header.d=autor.com; dmarc=pass header.from=autor.com',
  'Authentication-Results: mx.corp.es; spf=fail smtp.mailfrom=lista.org;',
  ' dkim=fail header.d=autor.com; dmarc=fail header.from=autor.com',
  'Received: from mx.lista.org (mx.lista.org [93.184.216.34]) by mx.corp.es',
  ' with ESMTPS id A1; Mon, 10 Aug 2026 09:00:00 +0200',
  'Return-Path: <bounces@lista.org>',
  'From: Autor <autor@autor.com>', 'To: lista@lista.org', 'Subject: [lista] Acta de la reunion',
  'Message-ID: <1@autor.com>', 'Date: Mon, 10 Aug 2026 09:00:00 +0200',
  'Content-Type: text/plain; charset="utf-8"', '', 'Adjunto el acta de la reunion de ayer.', ''
].join('\r\n');

const SINAR = [
  'Received: from mx.proveedor.es (mx.proveedor.es [81.44.1.10]) by mx.corp.es',
  ' with ESMTPS id A1; Mon, 10 Aug 2026 09:00:00 +0200',
  'From: Ana Lopez <ana@proveedor.es>', 'To: maria@corp.es', 'Subject: Presupuesto revisado',
  'Message-ID: <1@proveedor.es>', 'Date: Mon, 10 Aug 2026 09:00:00 +0200',
  'Content-Type: text/plain; charset="utf-8"', '', 'Te adjunto el presupuesto. Un saludo.', ''
].join('\r\n');

const ESLAVO = [
  'Authentication-Results: mx.corp.es; spf=pass smtp.mailfrom=firma.pl;',
  ' dkim=pass header.d=firma.pl; dmarc=pass header.from=firma.pl',
  'Received: from mx.firma.pl (mx.firma.pl [93.184.216.34]) by mx.corp.es',
  ' with ESMTPS id A1; Mon, 10 Aug 2026 09:00:00 +0200',
  'From: =?utf-8?B?TWljaGHFgiBOb3dhaw==?= <michal@firma.pl>', 'To: maria@corp.es',
  'Subject: Oferta', 'Message-ID: <1@firma.pl>', 'Date: Mon, 10 Aug 2026 09:00:00 +0200',
  'Content-Type: text/plain; charset="utf-8"', '', 'Buenos dias, le paso la oferta.', ''
].join('\r\n');

const HOMOGLIFO = [
  'Authentication-Results: mx.corp.es; spf=fail smtp.mailfrom=evil.com; dkim=none;',
  ' dmarc=fail header.from=evil.com',
  'Received: from x.evil.com (x.evil.com [45.9.1.2]) by mx.corp.es with ESMTPS id A1;',
  ' Mon, 10 Aug 2026 09:00:00 +0200',
  'From: =?utf-8?B?' + Buffer.from('Seguridad pаypal', 'utf8').toString('base64') + '?= <a@evil.com>',
  'To: maria@corp.es', 'Subject: Verifica tu cuenta', 'Message-ID: <1@evil.com>',
  'Date: Mon, 10 Aug 2026 09:00:00 +0200', 'Content-Type: text/plain; charset="utf-8"', '',
  'Verifica tu cuenta.', ''
].join('\r\n');

console.log('\n== correo legitimo que la version anterior suspendia ==');
const esp = await analizar(ESP, 'esp.eml');
const lista = await analizar(LISTA, 'lista.eml');
const sinar = await analizar(SINAR, 'sinar.eml');
const eslavo = await analizar(ESLAVO, 'eslavo.eml');

check('boletin de un proveedor de envio masivo (antes 43)',
  esp.verdict === 'BAJO', esp.verdict + ' ' + esp.score + ' ' + esp.findings.map(f => f.id));
check('el Return-Path del proveedor ya no cuenta si el correo autentica',
  !esp.findings.some(f => f.id === 'rp-mismatch'));
check('lista de correo reenviada con ARC valido (antes 48)',
  lista.verdict === 'BAJO', lista.verdict + ' ' + lista.score + ' ' + lista.findings.map(f => f.id));
check('la cadena ARC se tiene en cuenta y resta',
  lista.findings.some(f => f.id === 'ok-arc' && f.points < 0));
check('un DMARC fail ya no puntua tres veces',
  lista.scoreBreakdown.find(d => d.cat === 'auth').bruto <= 15,
  'bruto de auth: ' + lista.scoreBreakdown.find(d => d.cat === 'auth').bruto);
check('correo sin Authentication-Results (antes 29)',
  sinar.score === 0, sinar.verdict + ' ' + sinar.score + ' ' + sinar.findings.map(f => f.id));
check('un nombre polaco no es un homoglifo (antes 15)',
  eslavo.verdict === 'BAJO' && !eslavo.findings.some(f => f.id === 'dn-mixed-script'),
  eslavo.verdict + ' ' + eslavo.score);

const homo = await analizar(HOMOGLIFO, 'homoglifo.eml');
check('pero una "a" cirilica dentro de "paypal" si lo es',
  homo.findings.some(f => f.id === 'dn-mixed-script'), homo.findings.map(f => f.id).join());

console.log('\n== robustez ==');
const roto = await analizar('From: a@b.com\r\nSubject: x\r\nContent-Type: text/html\r\n\r\n<p>&#x110000;</p>\r\n', 'roto.eml');
check('una entidad HTML fuera de rango no tumba el analisis', roto.verdict === 'BAJO');

const noSonCorreos = {
  'un PDF': '%PDF-1.7\n1 0 obj<</Type/Catalog>>endobj',
  'un ZIP o un .docx': 'PK\x03\x04\x14\x00\x00\x00\x08\x00basura',
  'una imagen PNG': '\x89PNG\r\n\x1a\n\x00\x00\x00\x00',
  'un .msg de Outlook': '\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1basura',
  'un fichero vacio': '',
  'solo el cuerpo, sin cabeceras': 'Hola Juan, te confirmo la reunion del martes.'
};
for (const [queEs, contenido] of Object.entries(noSonCorreos)) {
  let aviso = null;
  try { await PT.analyze(contenido, { filename: 'x' }); }
  catch (e) { aviso = e.formatoNoSoportado; }
  check('no da un veredicto sobre ' + queEs + ': avisa', !!aviso, aviso || 'devolvio una nota');
}

const hondo = (prof) => {
  let c = 'Content-Type: application/x-msdownload; name="factura.exe"\r\n' +
    'Content-Disposition: attachment; filename="factura.exe"\r\n\r\nMZ...\r\n';
  for (let i = prof; i > 0; i--) {
    c = 'Content-Type: multipart/mixed; boundary=b' + i + '\r\n\r\n--b' + i + '\r\n' + c + '--b' + i + '--\r\n';
  }
  return 'From: a@b.com\r\nSubject: factura\r\n' + c;
};
const anidado = await analizar(hondo(20), 'anidado.eml');
check('un adjunto anidado 20 niveles no se pierde', anidado.attachments.length === 1,
  anidado.attachments.length + ' adjuntos');
const anidadisimo = await analizar(hondo(40), 'anidadisimo.eml');
check('y si aun asi hay que parar, se dice en vez de callarlo',
  anidadisimo.findings.some(f => f.id === 'mime-profundo'),
  anidadisimo.findings.map(f => f.id).join(' '));

console.log('\n== los pesos vienen de algun sitio ==');
const conFuente = (() => {
  const src = fs.readFileSync(path.join(ROOT, 'assets/parser.js'), 'utf8');
  const b = src.slice(src.indexOf('const PESOS = {'));
  return Array.from(b.slice(0, b.indexOf('\n  };'))
    .matchAll(/'([a-z0-9-]+)':\s*\{ cat: '([a-z]+)', pts: (-?\d+), sev: '(\w+)',?\s*(?:\r?\n\s*)?fuente: '([^']*)'/g))
    .map(m => ({ id: m[1], cat: m[2], pts: +m[3], fuente: m[5] }));
})();
check('todas las reglas declaran de donde sale su peso',
  conFuente.length === pesos.size, conFuente.length + ' de ' + pesos.size);
const medidas = conFuente.filter(r => /^LR /.test(r.fuente));
const sinMedir = conFuente.filter(r => r.pts > 0 && !/^LR /.test(r.fuente));
check('la mayoria de los pesos sale de una medida, no de mi criterio',
  medidas.length >= conFuente.length / 2,
  medidas.length + ' medidas de ' + conFuente.length);
check('y las que no estan medidas lo dicen',
  sinMedir.every(r => /sin validar|a mano/.test(r.fuente)),
  sinMedir.filter(r => !/sin validar|a mano/.test(r.fuente)).map(r => r.id).join());
check('hay pesos negativos: sin mitigantes todo correo reenviado es sospechoso',
  conFuente.some(r => r.pts < 0));
check('ninguna regla se pasa sola del techo de su categoria',
  conFuente.every(r => r.pts <= TECHOS[r.cat]),
  conFuente.filter(r => r.pts > TECHOS[r.cat]).map(r => r.id + '=' + r.pts + '>' + TECHOS[r.cat]).join());

console.log('\n== la vista sencilla no se queda muda ==');
const uiSrc = fs.readFileSync(path.join(ROOT, 'assets/ui.js'), 'utf8');
const bloqueUI = uiSrc.slice(uiSrc.indexOf('const EN_CRISTIANO = {'));
const frases = new Set(Array.from(bloqueUI.slice(0, bloqueUI.indexOf('\n  };'))
  .matchAll(/'([a-z0-9-]+)':/g)).map(m => m[1]));
const mudas = conFuente.filter(r => r.pts > 0 && !frases.has(r.id)).map(r => r.id);
check('toda regla que suma tiene su frase en castellano llano', mudas.length === 0, mudas.join(' '));

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
  check('el veredicto se lee sin saber de esto',
    /estafa/i.test(d.querySelector('#verdictTitle').textContent),
    d.querySelector('#verdictTitle').textContent);
  check('y la etiqueta tecnica sigue estando',
    /CRÍTICO/.test(d.querySelector('#verdictNota').textContent) &&
    /100 de 100/.test(d.querySelector('#verdictNota').textContent),
    d.querySelector('#verdictNota').textContent);
  check('se ve de quién viene el correo',
    /micros0ft-security\.tk/.test(d.querySelector('#sobre').textContent),
    d.querySelector('#sobre').textContent.slice(0, 90));
  check('la vista sencilla se ve sin tocar nada', !!d.querySelector('#p-simple').textContent.trim());
  check('y no queda encerrada en el detalle',
    !d.querySelector('#advanced').contains(d.querySelector('#p-simple')));
  check('con consejos accionables', d.querySelectorAll('#p-simple ol li').length >= 3);

  const adv = d.querySelector('#advanced'), btnAdv = d.querySelector('#btnAdv');
  check('el detalle tecnico arranca oculto', adv.hidden === true);
  check('y el boton lo anuncia', btnAdv.getAttribute('aria-expanded') === 'false');
  btnAdv.click();
  check('el boton lo despliega', adv.hidden === false && btnAdv.getAttribute('aria-expanded') === 'true');
  btnAdv.click();
  check('y lo vuelve a ocultar', adv.hidden === true);
  btnAdv.click();  // se deja abierto para poder mirar dentro

  check('VirusTotal / AbuseIPDB viven en el detalle, no en la vista de todos',
    d.querySelectorAll('#p-resumen a[href*="virustotal.com"], #p-resumen a[href*="abuseipdb.com"]').length > 0 &&
    d.querySelectorAll('#p-simple a[href*="virustotal.com"], #p-simple a[href*="abuseipdb.com"]').length === 0);
  check('los enlaces no filtran de donde vienen',
    Array.from(d.querySelectorAll('#result a[target="_blank"]')).every(a => /noreferrer/.test(a.getAttribute('rel') || '')));
  check('el desglose de la nota se pinta', /reparte la nota/.test(d.querySelector('#p-hallazgos').textContent));
  check('los hashes llegan a la pantalla', /[0-9a-f]{64}/.test(d.querySelector('#p-adjuntos').textContent));
  check('la pestaña de URLs separa enlaces de recursos',
    /Enlaces en los que se puede pinchar/.test(d.querySelector('#p-urls').textContent));
  check('EL HTML DEL CORREO NO SE EJECUTA',
    d.querySelectorAll('#p-cuerpo form, #p-cuerpo input, #p-cuerpo script, #p-cuerpo img').length === 0);
}

console.log('\n' + ok + ' ok, ' + mal + ' fallos\n');
process.exit(mal ? 1 : 0);

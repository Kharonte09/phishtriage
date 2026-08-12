/**
 * Pruebas del motor de análisis.
 *   node tests/run-tests.mjs
 */
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { emlDeEjemplo } from './fixture.mjs';

const require = createRequire(import.meta.url);
const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const PT = require(path.join(ROOT, 'assets/parser.js'));

let pass = 0, fail = 0;
function check(name, cond, extra) {
  if (cond) { pass++; console.log('  ok   ' + name); }
  else { fail++; console.log('  FAIL ' + name + (extra ? '  -> ' + extra : '')); }
}
const analizar = (bytes, nombre) => PT.analyze(PT.bytesToLatin1(bytes), { filename: nombre });

console.log('\n== utilidades ==');
check('orgDomain con sufijo doble', PT.orgDomain('mail.foo.co.uk') === 'foo.co.uk', PT.orgDomain('mail.foo.co.uk'));
check('orgDomain simple', PT.orgDomain('a.b.example.com') === 'example.com');
check('defang', PT.defang('http://evil.com/a') === 'hxxp://evil[.]com/a', PT.defang('http://evil.com/a'));
check('isPrivateIP 10/8', PT.isPrivateIP('10.20.0.5') === true);
check('isPrivateIP pública', PT.isPrivateIP('185.220.101.44') === false);
check('md5 de cadena vacía', PT.md5(new Uint8Array(0)) === 'd41d8cd98f00b204e9800998ecf8427e');
check('md5 abc', PT.md5(new TextEncoder().encode('abc')) === '900150983cd24fb0d6963f7d28e17f72');
check('RFC2047 base64', PT.decodeRFC2047('=?utf-8?B?SG9sYSBtdW5kbw==?=') === 'Hola mundo');
check('RFC2047 quoted', PT.decodeRFC2047('=?utf-8?Q?Acci=C3=B3n?=') === 'Acción');

console.log('\n== correo de phishing de manual ==');
const r = await analizar(emlDeEjemplo(), 'ejemplo.eml');
check('veredicto CRÍTICO', r.verdict === 'CRITICO', r.verdict + ' ' + r.score);
check('SPF fail', r.auth.spf === 'fail');
check('DMARC fail', r.auth.dmarc === 'fail');
check('SPF no alineado', r.auth.alignment.spf === false);
check('3 saltos Received', r.received.length === 3, String(r.received.length));
check('orden cronológico correcto', r.received[0].from === 'localhost' && r.received[2].by === 'imap.corp-victima.es');
check('IP de origen detectada', r.summary.originIP === '45.155.205.233', String(r.summary.originIP));
check('IP privada marcada', PT.isPrivateIP(r.received[2].ips[0]) === true);
check('asunto decodificado', /ACCIÓN REQUERIDA/.test(r.summary.subject), r.summary.subject);
check('7 URLs', r.urls.length === 7, String(r.urls.length));
check('detecta desajuste texto/href', r.findings.some(f => f.id === 'url-mismatch'));
check('detecta punycode', r.findings.some(f => f.id === 'url-punycode'));
check('detecta URL con IP', r.findings.some(f => f.id === 'url-ip'));
check('detecta acortador', r.findings.some(f => f.id === 'url-shortener'));
check('2 adjuntos', r.attachments.length === 2, String(r.attachments.length));
check('doble extensión', r.findings.some(f => f.id === 'att-double'));
check('macros docm', r.findings.some(f => f.id === 'att-macro'));
check('md5 del adjunto', r.attachments[0].md5 === 'edc063210e77cde76bb7f9bb351fe1d5', r.attachments[0].md5);
check('sha256 del adjunto',
  r.attachments[0].sha256 === '7675017ab33adfcde523e434366c71c2827064a5975759fa31fdfd19d47a19e7',
  String(r.attachments[0].sha256));
check('magic ZIP en el docm', r.attachments[1].magic === 'ZIP/OOXML', String(r.attachments[1].magic));
check('IOCs sin marcas de tiempo coladas',
  r.iocs.ips.every(ip => !ip.includes(':') || ip.split(':').length > 3), r.iocs.ips.join(','));
check('informe serializable', JSON.stringify(r).length > 5000);

console.log('\n== ponderación ==');
const pesos = (() => {
  const src = fs.readFileSync(path.join(ROOT, 'assets/parser.js'), 'utf8');
  const bloque = src.slice(src.search(/const PESOS = \{/));
  return new Map(Array.from(bloque.slice(0, bloque.search(/\n\s*\};/))
    .matchAll(/'([a-z0-9-]+)':\s*\{ cat: '(\w+)', pts: (\d+), sev: '(\w+)' \}/g))
    .map(m => [m[1], { cat: m[2], pts: +m[3], sev: m[4] }]));
})();
check('la tabla de pesos se lee', pesos.size > 50, String(pesos.size));
check('cada regla disparada tiene su peso declarado',
  r.findings.every(f => pesos.has(f.id)),
  r.findings.filter(f => !pesos.has(f.id)).map(f => f.id).join());
check('los techos de las categorías suman 100',
  r.scoreBreakdown.reduce((s, d) => s + d.techo, 0) === 100,
  String(r.scoreBreakdown.reduce((s, d) => s + d.techo, 0)));
check('ninguna categoría se pasa de su techo', r.scoreBreakdown.every(d => d.puntos <= d.techo));
check('el total es la suma del desglose',
  r.scoreBreakdown.reduce((s, d) => s + d.puntos, 0) === r.score);
check('toda categoría con reglas aporta o está topada',
  r.scoreBreakdown.every(d => d.bruto === 0 || d.puntos > 0));
check('cada peso apunta a una categoría real',
  [...pesos.values()].every(p => r.scoreBreakdown.some(d => d.cat === p.cat)));

console.log('\n== correos que NO son phishing ==');
const benigno = new TextEncoder().encode(
  'From: Ana <ana@ejemplo.es>\r\nTo: bob@ejemplo.es\r\nSubject: comida\r\n' +
  'Message-ID: <1@ejemplo.es>\r\n\r\nNos vemos a las dos.\r\n');
const b = await analizar(benigno, 'benigno.eml');
check('riesgo BAJO en correo inocuo', b.verdict === 'BAJO',
  b.verdict + ' ' + b.score + ' ' + JSON.stringify(b.findings.map(f => f.id)));
check('avisa de que faltan cabeceras de transporte', b.findings.some(f => f.id === 'no-transport'));

const boletin = new TextEncoder().encode(
  'Authentication-Results: mx.corp.es; spf=pass smtp.mailfrom=news.tienda.com;' +
  ' dkim=pass header.d=tienda.com; dmarc=pass header.from=tienda.com\r\n' +
  'Received: from mx.news.tienda.com (mx.news.tienda.com [93.184.216.34]) by mx.corp.es' +
  ' with ESMTPS id A1; Mon, 10 Aug 2026 09:00:00 +0200\r\n' +
  'From: Tienda <ofertas@tienda.com>\r\nTo: maria@corp.es\r\n' +
  'Subject: Tu factura de julio ya esta disponible\r\nMessage-ID: <a1@tienda.com>\r\n' +
  'Date: Mon, 10 Aug 2026 09:00:00 +0200\r\nMIME-Version: 1.0\r\n' +
  'Content-Type: text/html; charset="utf-8"\r\n\r\n' +
  '<html><body><p>Hola,</p><p>Tu factura: <a href="https://bit.ly/3abc">Ver factura</a></p></body></html>\r\n');
const n = await analizar(boletin, 'boletin.eml');
check('un boletín legítimo con acortador no pasa de BAJO', n.verdict === 'BAJO',
  n.verdict + ' ' + n.score + ' ' + JSON.stringify(n.findings.map(f => f.id)));
check('"factura" ya no cuenta como urgencia', !n.findings.some(f => f.id === 'subj-urgency'));
check('el phishing puntúa muy por encima del boletín', r.score - n.score >= 60,
  r.score + ' vs ' + n.score);

console.log('\n' + pass + ' ok, ' + fail + ' fallos\n');
process.exit(fail ? 1 : 0);

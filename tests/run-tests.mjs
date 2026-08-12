/**
 * Pruebas del motor JS + paridad con el CLI de Python.
 *   node tests/run-tests.mjs
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const PT = require(path.join(ROOT, 'assets/eml.js'));

let pass = 0, fail = 0;
function check(name, cond, extra) {
  if (cond) { pass++; console.log('  ok   ' + name); }
  else { fail++; console.log('  FAIL ' + name + (extra ? '  -> ' + extra : '')); }
}
async function analyzeFile(p) {
  const raw = PT.bytesToLatin1(new Uint8Array(fs.readFileSync(p)));
  return PT.analyze(raw, { filename: path.basename(p) });
}

console.log('\n== utilidades ==');
check('orgDomain con sufijo doble', PT.orgDomain('mail.foo.co.uk') === 'foo.co.uk', PT.orgDomain('mail.foo.co.uk'));
check('orgDomain simple', PT.orgDomain('a.b.example.com') === 'example.com');
check('defang', PT.defang('http://evil.com/a') === 'hxxp://evil[.]com/a', PT.defang('http://evil.com/a'));
check('isPrivateIP 10/8', PT.isPrivateIP('10.20.0.5') === true);
check('isPrivateIP pública', PT.isPrivateIP('185.220.101.44') === false);
check('md5 de cadena vacia', PT.md5(new Uint8Array(0)) === 'd41d8cd98f00b204e9800998ecf8427e');
check('md5 abc', PT.md5(new TextEncoder().encode('abc')) === '900150983cd24fb0d6963f7d28e17f72');
check('RFC2047 base64', PT.decodeRFC2047('=?utf-8?B?SG9sYSBtdW5kbw==?=') === 'Hola mundo');
check('RFC2047 quoted', PT.decodeRFC2047('=?utf-8?Q?Acci=C3=B3n?=') === 'Acción');

console.log('\n== correo de ejemplo ==');
const samplePath = path.join(ROOT, 'samples/sample-phishing.eml');
const r = await analyzeFile(samplePath);
check('veredicto CRITICO', r.verdict === 'CRITICO', r.verdict + ' ' + r.score);
check('SPF fail', r.auth.spf === 'fail');
check('DMARC fail', r.auth.dmarc === 'fail');
check('SPF no alineado', r.auth.alignment.spf === false);
check('3 saltos Received', r.received.length === 3, String(r.received.length));
check('orden cronologico correcto', r.received[0].from === 'localhost' && r.received[2].by === 'imap.corp-victima.es');
check('IP de origen detectada', r.summary.originIP === '45.155.205.233', String(r.summary.originIP));
check('IP privada marcada', PT.isPrivateIP(r.received[2].ips[0]) === true);
check('asunto decodificado', /ACCIÓN REQUERIDA/.test(r.summary.subject), r.summary.subject);
check('7 URLs', r.urls.length === 7, String(r.urls.length));
check('detecta desajuste texto/href', r.findings.some(f => /El texto muestra/.test(f.msg)));
check('detecta punycode', r.urls.some(u => u.flags.some(f => f.id === 'url-punycode')));
check('detecta URL con IP', r.urls.some(u => u.flags.some(f => f.id === 'url-ip')));
check('detecta acortador', r.urls.some(u => u.flags.some(f => f.id === 'url-shortener')));
check('2 adjuntos', r.attachments.length === 2, String(r.attachments.length));
check('doble extensión', r.attachments[0].flags.some(f => f.id === 'att-double'));
check('macros docm', r.attachments[1].flags.some(f => f.id === 'att-macro'));
check('sha256 calculado', /^[0-9a-f]{64}$/.test(r.attachments[0].sha256 || ''), r.attachments[0].sha256);
check('magic ZIP en docm', r.attachments[1].magic === 'ZIP/OOXML', String(r.attachments[1].magic));
check('IOCs sin timestamps colados', r.iocs.ips.every(ip => !ip.includes(':') || ip.split(':').length > 3), r.iocs.ips.join(','));
check('markdown se genera', PT.toMarkdown(r).length > 1500);
check('informe serializable', JSON.stringify(r).length > 5000);

console.log('\n== correo mínimo (sin cabeceras de transporte) ==');
const tmp = path.join(os.tmpdir(), 'phishtriage-benigno.eml');
fs.writeFileSync(tmp, 'From: Ana <ana@ejemplo.es>\r\nTo: bob@ejemplo.es\r\nSubject: comida\r\nMessage-ID: <1@ejemplo.es>\r\n\r\nNos vemos a las dos.\r\n');
const b = await analyzeFile(tmp);
check('riesgo BAJO en correo inocuo', b.verdict === 'BAJO', b.verdict + ' ' + b.score + ' ' + JSON.stringify(b.findings.map(f => f.id)));
check('avisa de cabeceras ausentes', b.findings.some(f => f.id === 'no-transport'));
try { fs.unlinkSync(tmp); } catch (e) { /* da igual */ }

console.log('\n== paridad con el CLI de Python ==');
const salidaPy = path.join(os.tmpdir(), 'phishtriage-parity.json');
try {
  execFileSync('python3', [path.join(ROOT, 'cli/phishtriage.py'), samplePath, '--quiet',
    '--json', salidaPy], { stdio: ['ignore', 'ignore', 'ignore'] });
} catch (e) {
  // el CLI sale con código 3 en CRITICO: es lo esperado
}
const py = JSON.parse(fs.readFileSync(salidaPy, 'utf8'));
check('mismo score', py.score === r.score, py.score + ' vs ' + r.score);
check('mismo veredicto', py.verdict === r.verdict);
check('mismo número de URLs', py.urls.length === r.urls.length, py.urls.length + ' vs ' + r.urls.length);
check('mismos adjuntos', py.attachments.length === r.attachments.length);
check('mismos sha256', py.attachments.map(a => a.sha256).join() === r.attachments.map(a => a.sha256).join());
check('mismo número de saltos', py.received.length === r.received.length);

// Comparar los ids de regla, no el recuento: contando, dos motores pueden dar
// el mismo número disparando reglas distintas y nadie se entera. Ya pasó.
const idsJs = r.findings.map(f => f.id).sort();
const idsPy = py.findings.map(f => f.id).sort();
check('mismas reglas disparadas', idsJs.join() === idsPy.join(),
  'solo JS: [' + idsJs.filter(x => !idsPy.includes(x)) + '] solo PY: [' + idsPy.filter(x => !idsJs.includes(x)) + ']');
check('mismo desglose por categoría',
  JSON.stringify(r.scoreBreakdown) === JSON.stringify(py.scoreBreakdown));

console.log('\n== la tabla de ponderación no puede divergir ==');
function tablaDe(texto, reIni, reRegla) {
  const bloque = texto.slice(texto.search(reIni));
  const fin = bloque.search(/\n\s*\}\s*;?\s*\n/);
  return new Map(Array.from(bloque.slice(0, fin).matchAll(reRegla))
    .map(m => [m[1], m[2] + '/' + m[3] + '/' + m[4]]));
}
const src = f => fs.readFileSync(path.join(ROOT, f), 'utf8');
const pesosJs = tablaDe(src('assets/eml.js'), /const PESOS = \{/,
  /'([a-z0-9-]+)':\s*\{ cat: '(\w+)', pts: (\d+), sev: '(\w+)' \}/g);
const pesosPy = tablaDe(src('cli/phishtriage.py'), /^PESOS = \{/m,
  /"([a-z0-9-]+)":\s*\{"cat": "(\w+)", "pts": (\d+), "sev": "(\w+)"\}/g);
check('las dos tablas se leen y no están vacías', pesosJs.size > 50 && pesosPy.size > 50,
  pesosJs.size + ' / ' + pesosPy.size);
const dif = [...pesosJs].filter(([k, v]) => pesosPy.get(k) !== v).map(([k]) => k)
  .concat([...pesosPy].filter(([k]) => !pesosJs.has(k)).map(([k]) => k));
check('mismos pesos en JS y en Python', dif.length === 0, dif.slice(0, 6).join(', '));
check('cada regla disparada tiene su peso declarado',
  r.findings.every(f => pesosJs.has(f.id)),
  r.findings.filter(f => !pesosJs.has(f.id)).map(f => f.id).join());
check('los techos de las categorías suman 100',
  r.scoreBreakdown.reduce((s, d) => s + d.techo, 0) === 100,
  String(r.scoreBreakdown.reduce((s, d) => s + d.techo, 0)));
check('ninguna categoría se pasa de su techo',
  r.scoreBreakdown.every(d => d.puntos <= d.techo));

console.log('\n' + pass + ' ok, ' + fail + ' fallos\n');
process.exit(fail ? 1 : 0);

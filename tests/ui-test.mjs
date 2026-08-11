/**
 * Prueba de la interfaz web con jsdom: carga index.html, dispara el boton de
 * ejemplo y comprueba que cada panel se pinta con lo que toca.
 *
 *   npm install jsdom      (unica dependencia, y solo para esta prueba)
 *   node tests/ui-test.mjs
 *
 * Si jsdom no esta instalado, la prueba se salta sin fallar.
 */
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const require = createRequire(import.meta.url);

let JSDOM, VirtualConsole;
try {
  ({ JSDOM, VirtualConsole } = require('jsdom'));
} catch (e) {
  console.log('jsdom no instalado: se salta la prueba de interfaz (npm install jsdom)');
  process.exit(0);
}

const html = fs.readFileSync(path.join(ROOT, 'index.html'), 'utf8');
const sample = fs.readFileSync(path.join(ROOT, 'samples/sample-phishing.eml'));

const vc = new VirtualConsole();
vc.on('jsdomError', e => {
  // scrollTo y la carga de config.local.js no estan implementados en jsdom
  if (!/scrollTo|config\.local\.js/.test(String(e.message))) console.log('JSDOM ERROR:', e.message);
});

const dom = new JSDOM(html, {
  url: 'http://127.0.0.1:8000/',
  runScripts: 'dangerously',
  virtualConsole: vc,
  beforeParse(w) {
    Object.defineProperty(w, 'crypto', { value: globalThis.crypto, configurable: true });
    w.fetch = async () => ({
      ok: true, status: 200,
      arrayBuffer: async () => sample.buffer.slice(sample.byteOffset, sample.byteOffset + sample.byteLength)
    });
    w.alert = m => console.log('ALERT:', m);
  }
});

const w = dom.window, d = w.document;
for (const f of ['assets/eml.js', 'assets/enrich.js', 'assets/app.js']) {
  const s = d.createElement('script');
  s.textContent = fs.readFileSync(path.join(ROOT, f), 'utf8');
  d.body.appendChild(s);
}

let ok = 0, bad = 0;
const chk = (n, c, x) => c ? (ok++, console.log('  ok   ' + n)) : (bad++, console.log('  FAIL ' + n + (x ? ' -> ' + x : '')));

// El render es asincrono (hashes con WebCrypto): esperar a que aparezca,
// no dormir un rato fijo. En un runner de CI lento eso daba falsos negativos.
async function waitFor(cond, ms = 20000, label = '') {
  const t0 = Date.now();
  while (Date.now() - t0 < ms) {
    try { if (cond()) return true; } catch (e) { /* aun no */ }
    await new Promise(r => setTimeout(r, 50));
  }
  console.log('  (timeout esperando ' + label + ' tras ' + ms + ' ms)');
  return false;
}

console.log('\n== interfaz ==');
chk('motor cargado', typeof w.PhishTriage === 'object');
chk('enriquecimiento cargado', typeof w.PhishEnrich === 'object');
console.log('  info  crypto.subtle disponible: ' + !!(w.crypto && w.crypto.subtle));

d.querySelector('#btnSample').dispatchEvent(new w.Event('click'));
await waitFor(() => !d.querySelector('#result').hidden, 20000, 'el panel de resultados');
await waitFor(() => d.querySelectorAll('#p-adjuntos .att-item').length === 2, 20000, 'los adjuntos');

chk('resultado visible', !d.querySelector('#result').hidden);
chk('veredicto critico', /CRITICO/.test(d.querySelector('#verdictTitle').textContent));
chk('score en el anillo', d.querySelector('#ringTxt').textContent === '100');
chk('chips de autenticacion', /SPF/.test(d.querySelector('#authChips').textContent));
chk('vista sencilla activa por defecto', d.querySelector('.panel[data-p="simple"]').classList.contains('active'));
chk('titular en cristiano', /fraude/i.test(d.querySelector('#p-simple').textContent),
  d.querySelector('#p-simple').textContent.slice(0, 60));
chk('consejos accionables', d.querySelectorAll('#p-simple ol li').length >= 3);
chk('razones traducidas', /contrasena|enlace|adjunto/i.test(d.querySelector('#p-simple').textContent));
chk('enlaces de consulta sin clave a VT',
  d.querySelector('#p-simple a[href^="https://www.virustotal.com/gui/file/"]') !== null);
chk('enlace a AbuseIPDB',
  d.querySelector('#p-simple a[href^="https://www.abuseipdb.com/check/"]') !== null);
chk('los enlaces salen a pestana nueva y sin referrer',
  Array.from(d.querySelectorAll('#p-simple a')).every(a =>
    a.getAttribute('target') === '_blank' && /noreferrer/.test(a.getAttribute('rel') || '')));
chk('resumen con el remitente', /micros0ft-security\.tk/.test(d.querySelector('#p-resumen').textContent));
chk('arbol MIME', /multipart\/mixed/.test(d.querySelector('#p-resumen').textContent));
chk('hallazgos pintados', d.querySelectorAll('#p-hallazgos .finding').length === 33,
  String(d.querySelectorAll('#p-hallazgos .finding').length));
chk('cabeceras en tabla', d.querySelectorAll('#p-cabeceras tr').length > 15);
chk('3 saltos pintados', d.querySelectorAll('#p-received .hop').length === 3);
chk('7 urls pintadas', d.querySelectorAll('#p-urls .url-item').length === 7);
chk('2 adjuntos pintados', d.querySelectorAll('#p-adjuntos .att-item').length === 2);
// Hashes concretos del adjunto Factura_88213.pdf.html del correo de ejemplo.
// MD5 va en JS puro y debe estar siempre; SHA depende de WebCrypto.
const attText = d.querySelector('#p-adjuntos').textContent;
chk('md5 correcto', attText.includes('edc063210e77cde76bb7f9bb351fe1d5'));
if (w.crypto && w.crypto.subtle) {
  chk('sha256 correcto',
    attText.includes('7675017ab33adfcde523e434366c71c2827064a5975759fa31fdfd19d47a19e7'));
} else {
  console.log('  skip sha256 (sin WebCrypto en este entorno)');
}
chk('el HTML del correo NO se renderiza',
  d.querySelectorAll('#p-cuerpo form, #p-cuerpo input, #p-cuerpo img, #p-cuerpo script').length === 0);
chk('el HTML se muestra como codigo', /&lt;form/.test(d.querySelectorAll('#p-cuerpo pre')[1].innerHTML));
chk('iocs listados', /verify-account/.test(d.querySelector('#p-iocs').textContent));
chk('json pintado', d.querySelector('#p-json pre').textContent.length > 5000);
chk('aviso de enriquecimiento sin configurar', /Sin configurar/.test(d.querySelector('#p-enriquecimiento').textContent));
chk('contadores de pestanas', d.querySelector('#nUrls').textContent === '7' && d.querySelector('#nAtt').textContent === '2');

d.querySelector('#tabs button[data-p="urls"]').dispatchEvent(new w.MouseEvent('click', { bubbles: true }));
chk('cambio de pestana', d.querySelector('.panel[data-p="urls"]').classList.contains('active'));

d.querySelector('#btnReset').dispatchEvent(new w.Event('click'));
chk('reset oculta el resultado', d.querySelector('#result').hidden === true);
chk('reset deshabilita las descargas', d.querySelector('#btnJson').disabled === true);

console.log('\n' + ok + ' ok, ' + bad + ' fallos\n');
process.exit(bad ? 1 : 0);

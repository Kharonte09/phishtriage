/**
 * Pasa PhishTriage por encima de una carpeta de correos y dice como le ha ido.
 *
 *   node tools/corpus.mjs <carpeta>
 *   node tools/corpus.mjs <carpeta> --esperado phishing
 *   node tools/corpus.mjs <carpeta> --esperado legitimo --csv notas.csv
 *
 * Acepta ficheros sueltos (.eml) y buzones mbox, que parte por su cabecera
 * "From " de separacion.
 *
 * Con --esperado le dices que deberia salir, y en vez de un resumen te saca
 * los correos en los que se ha equivocado, que son los unicos que enseñan algo.
 *
 * No abre ningun adjunto ni sigue ningun enlace: el motor solo lee bytes.
 * Un corpus de phishing lleva malware de verdad dentro, asi que Defender va a
 * protestar al descomprimirlo. Que proteste; esto no lo ejecuta.
 */
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PT = require(path.join(ROOT, 'assets/parser.js'));

const args = process.argv.slice(2);
const carpeta = args.find(a => !a.startsWith('--'));
const opt = k => { const i = args.indexOf('--' + k); return i >= 0 ? args[i + 1] : null; };
const esperado = opt('esperado');
const csv = opt('csv');

if (!carpeta) {
  console.error('Uso: node tools/corpus.mjs <carpeta> [--esperado phishing|legitimo] [--csv salida.csv]');
  process.exit(2);
}
if (esperado && !['phishing', 'legitimo'].includes(esperado)) {
  console.error('--esperado solo acepta "phishing" o "legitimo"');
  process.exit(2);
}

// --- recoger los correos ----------------------------------------------------
function* ficheros(dir) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) yield* ficheros(p);
    else if (!/\.(png|jpe?g|gif|pdf|zip|md|json|csv|ya?ml)$/i.test(e.name)) yield p;
  }
}

// Un mbox es un fichero con muchos correos pegados, separados por una linea
// "From remitente fecha" a principio de linea.
function partirMbox(txt) {
  const trozos = txt.split(/^From \S+.*$/m).map(t => t.replace(/^\r?\n/, ''));
  return trozos.filter(t => /^[\w-]+\s*:/m.test(t) && t.trim().length > 40);
}

const correos = [];
for (const f of ficheros(carpeta)) {
  let bytes;
  try { bytes = fs.readFileSync(f); } catch (e) { continue; }
  const txt = PT.bytesToLatin1(new Uint8Array(bytes));
  // Un mbox se reconoce porque empieza por "From " en el primer byte. Un .eml
  // suelto empieza por una cabecera con dos puntos.
  const partes = /^From \S+/.test(txt) ? partirMbox(txt) : [txt];
  partes.forEach((p, i) => {
    if (/^[\w-]+\s*:/m.test(p)) {
      correos.push({ nombre: path.relative(carpeta, f) + (partes.length > 1 ? '#' + (i + 1) : ''), raw: p });
    }
  });
}

if (!correos.length) {
  console.error('No he encontrado ningun correo en ' + carpeta);
  process.exit(1);
}
console.log('Analizando ' + correos.length + ' correos de ' + carpeta + '\n');

// --- analizar ---------------------------------------------------------------
const resultados = [];
let fallos = 0;
for (const c of correos) {
  try {
    const r = await PT.analyze(c.raw, { filename: c.nombre });
    resultados.push({
      nombre: c.nombre, score: r.score, verdict: r.verdict,
      from: r.summary.from || '', asunto: (r.summary.subject || '').slice(0, 60),
      reglas: r.findings.filter(f => f.points > 0).map(f => f.id)
    });
  } catch (e) {
    fallos++;
    console.log('  ERROR en ' + c.nombre + ': ' + e.message);
  }
}

// --- reparto de notas -------------------------------------------------------
const ORDEN = ['BAJO', 'MEDIO', 'ALTO', 'CRITICO'];
const cuenta = Object.fromEntries(ORDEN.map(v => [v, 0]));
for (const r of resultados) cuenta[r.verdict]++;
const total = resultados.length;
const media = (resultados.reduce((s, r) => s + r.score, 0) / total).toFixed(1);

console.log('Reparto de notas');
for (const v of ORDEN) {
  const n = cuenta[v], pct = (100 * n / total);
  console.log('  ' + v.padEnd(8) + String(n).padStart(6) + '  ' + pct.toFixed(1).padStart(5) + '%  ' +
    '#'.repeat(Math.round(pct / 2)));
}
console.log('  media ' + media + '/100' + (fallos ? '   (' + fallos + ' no se pudieron analizar)' : ''));

// --- en que se ha equivocado ------------------------------------------------
if (esperado) {
  const acierta = r => esperado === 'phishing' ? r.score >= 50 : r.score < 20;
  const mal = resultados.filter(r => !acierta(r))
    .sort((a, b) => esperado === 'phishing' ? a.score - b.score : b.score - a.score);
  const tasa = (100 * (total - mal.length) / total).toFixed(1);

  console.log('\nEsperado: ' + esperado + '. Acierta en el ' + tasa + '% (' + (total - mal.length) + '/' + total + ')');
  if (mal.length) {
    console.log('\nLos 20 peores ' + (esperado === 'phishing' ? 'falsos negativos' : 'falsos positivos') + ':');
    for (const r of mal.slice(0, 20)) {
      console.log('  ' + String(r.score).padStart(3) + ' ' + r.verdict.padEnd(8) + ' ' + r.nombre.slice(0, 40).padEnd(40) +
        ' ' + r.from.slice(0, 34));
      if (r.reglas.length) console.log('      ' + r.reglas.join(' '));
    }
  }

  // Que reglas mandan en los correos que falla: por ahi se empieza a afinar
  const frec = {};
  for (const r of mal) for (const id of new Set(r.reglas)) frec[id] = (frec[id] || 0) + 1;
  const top = Object.entries(frec).sort((a, b) => b[1] - a[1]).slice(0, 12);
  if (top.length) {
    console.log('\nReglas que mas aparecen en los fallos:');
    for (const [id, n] of top) console.log('  ' + String(n).padStart(5) + '  ' + id);
  }
}

// --- cuanto dispara cada regla en todo el corpus ----------------------------
// Con esto y un corpus de cada clase sale la razon de verosimilitud de cada
// indicio, que es lo que de verdad deberia decidir su peso.
const disparos = {};
for (const r of resultados) for (const id of new Set(r.reglas)) disparos[id] = (disparos[id] || 0) + 1;
console.log('\nCuanto dispara cada regla (sobre ' + total + ' correos)');
for (const [id, n] of Object.entries(disparos).sort((a, b) => b[1] - a[1])) {
  console.log('  ' + (100 * n / total).toFixed(1).padStart(5) + '%  ' + String(n).padStart(6) + '  ' + id);
}

if (csv) {
  const esc = v => '"' + String(v).replace(/"/g, '""') + '"';
  fs.writeFileSync(csv, 'fichero,nota,veredicto,from,asunto,reglas\n' +
    resultados.map(r => [r.nombre, r.score, r.verdict, r.from, r.asunto, r.reglas.join(' ')].map(esc).join(',')).join('\n'));
  console.log('\nEscrito ' + csv);
}

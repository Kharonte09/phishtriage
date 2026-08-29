/**
 * Pasa PhishTriage por encima de correo real y dice como le ha ido.
 *
 *   node tools/corpus.mjs <carpeta>
 *   node tools/corpus.mjs <carpeta> --esperado phishing
 *   node tools/corpus.mjs <carpeta> --esperado legitimo --csv notas.csv
 *   node tools/corpus.mjs <carpeta-phishing> <carpeta-legitimo>
 *
 * Con una carpeta saca el reparto de notas, en que se equivoca y cuanto dispara
 * cada regla. Con dos saca la razon de verosimilitud de cada indicio: cuantas
 * veces mas aparece en el fraude que en el correo bueno. Eso es lo que deberia
 * decidir su peso, y no lo que le parezca a nadie. Una regla con razon 1 no
 * distingue nada aunque suene muy grave; una con razon 30 vale su peso en oro
 * aunque suene tonta.
 *
 * Acepta ficheros sueltos (.eml) y buzones mbox, que parte por su cabecera
 * "From " de separacion.
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
const sueltos = args.filter((a, i) => !a.startsWith('--') && !(i > 0 && args[i - 1].startsWith('--')));
const opt = k => { const i = args.indexOf('--' + k); return i >= 0 ? args[i + 1] : null; };
const [carpeta, carpetaHam] = sueltos;
const esperado = opt('esperado');
const csv = opt('csv');

if (!carpeta) {
  console.error('Uso: node tools/corpus.mjs <carpeta> [--esperado phishing|legitimo] [--csv salida.csv]');
  console.error('     node tools/corpus.mjs <carpeta-phishing> <carpeta-legitimo>');
  process.exit(2);
}
if (esperado && !['phishing', 'legitimo'].includes(esperado)) {
  console.error('--esperado solo acepta "phishing" o "legitimo"');
  process.exit(2);
}

function* ficheros(dir) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) yield* ficheros(p);
    else if (!/\.(png|jpe?g|gif|pdf|zip|gz|bz2|md|json|csv|ya?ml)$/i.test(e.name)) yield p;
  }
}

function partirMbox(txt) {
  return txt.split(/^From \S+.*$/m).map(t => t.replace(/^\r?\n/, ''))
    .filter(t => /^[\w-]+\s*:/m.test(t) && t.trim().length > 40);
}

async function analizar(carpeta) {
  const salida = [];
  let fallos = 0;
  for (const f of ficheros(carpeta)) {
    let txt;
    try { txt = PT.bytesToLatin1(new Uint8Array(fs.readFileSync(f))); } catch (e) { continue; }
    const partes = /^From \S+/.test(txt) ? partirMbox(txt) : [txt];
    for (let i = 0; i < partes.length; i++) {
      if (!/^[\w-]+\s*:/m.test(partes[i])) continue;
      const nombre = path.relative(carpeta, f) + (partes.length > 1 ? '#' + (i + 1) : '');
      try {
        const r = await PT.analyze(partes[i], { filename: nombre });
        salida.push({
          nombre, score: r.score, verdict: r.verdict,
          from: r.summary.from || '', asunto: (r.summary.subject || '').slice(0, 60),
          reglas: r.findings.filter(x => x.points > 0).map(x => x.id)
        });
      } catch (e) { fallos++; }
    }
  }
  if (!salida.length) { console.error('No he encontrado ningun correo en ' + carpeta); process.exit(1); }
  return { r: salida, fallos };
}

const disparos = res => {
  const d = {};
  for (const x of res) for (const id of new Set(x.reglas)) d[id] = (d[id] || 0) + 1;
  return d;
};

if (carpetaHam) {
  const A = await analizar(carpeta), B = await analizar(carpetaHam);
  const dA = disparos(A.r), dB = disparos(B.r);
  console.log('phishing: ' + A.r.length + ' correos    legitimo: ' + B.r.length + ' correos');

  const filas = [...new Set([...Object.keys(dA), ...Object.keys(dB)])].map(id => ({
    id,
    phish: 100 * (dA[id] || 0) / A.r.length,
    ham: 100 * (dB[id] || 0) / B.r.length,
    razon: (((dA[id] || 0) + 0.5) / (A.r.length + 1)) / (((dB[id] || 0) + 0.5) / (B.r.length + 1))
  })).sort((a, b) => b.razon - a.razon);

  console.log('\n' + 'regla'.padEnd(22) + 'phishing   legitimo      razon   pts');
  console.log('-'.repeat(62));
  for (const f of filas) {
    console.log(f.id.padEnd(22) + (f.phish.toFixed(1) + '%').padStart(8) + (f.ham.toFixed(1) + '%').padStart(11) +
      (f.razon >= 100 ? '>100' : f.razon.toFixed(1)).padStart(11) +
      (f.razon < 1.5 ? '   (no distingue)' : String(Math.round(3.5 * Math.log2(f.razon))).padStart(6)));
  }
  console.log('\npts = redondeo(3,5 x log2(razon)), recortado luego al techo de su categoria.');
  process.exit(0);
}

const { r: resultados, fallos } = await analizar(carpeta);
const total = resultados.length;
console.log('Analizando ' + total + ' correos de ' + carpeta + '\n');

const ORDEN = ['BAJO', 'MEDIO', 'ALTO', 'CRITICO'];
const cuenta = Object.fromEntries(ORDEN.map(v => [v, 0]));
for (const r of resultados) cuenta[r.verdict]++;

console.log('Reparto de notas');
for (const v of ORDEN) {
  const pct = 100 * cuenta[v] / total;
  console.log('  ' + v.padEnd(8) + String(cuenta[v]).padStart(6) + '  ' + pct.toFixed(1).padStart(5) + '%  ' +
    '#'.repeat(Math.round(pct / 2)));
}
console.log('  media ' + (resultados.reduce((s, r) => s + r.score, 0) / total).toFixed(1) + '/100' +
  (fallos ? '   (' + fallos + ' no se pudieron analizar)' : ''));

if (esperado) {
  const phish = esperado === 'phishing';
  const mal = resultados.filter(r => phish ? r.score < 50 : r.score >= 18)
    .sort((a, b) => phish ? a.score - b.score : b.score - a.score);
  console.log('\nEsperado: ' + esperado + '. Acierta en el ' + (100 * (total - mal.length) / total).toFixed(1) +
    '% (' + (total - mal.length) + '/' + total + ')');

  if (mal.length) {
    console.log('\nLos 20 peores ' + (phish ? 'falsos negativos' : 'falsos positivos') + ':');
    for (const r of mal.slice(0, 20)) {
      console.log('  ' + String(r.score).padStart(3) + ' ' + r.verdict.padEnd(8) + ' ' +
        r.nombre.slice(0, 40).padEnd(40) + ' ' + r.from.slice(0, 34));
      if (r.reglas.length) console.log('      ' + r.reglas.join(' '));
    }
  }
  const top = Object.entries(disparos(mal)).sort((a, b) => b[1] - a[1]).slice(0, 12);
  if (top.length) {
    console.log('\nReglas que mas aparecen en los fallos:');
    for (const [id, n] of top) console.log('  ' + String(n).padStart(5) + '  ' + id);
  }
}

console.log('\nCuanto dispara cada regla (sobre ' + total + ' correos)');
for (const [id, n] of Object.entries(disparos(resultados)).sort((a, b) => b[1] - a[1])) {
  console.log('  ' + (100 * n / total).toFixed(1).padStart(5) + '%  ' + String(n).padStart(6) + '  ' + id);
}

if (csv) {
  const esc = v => '"' + String(v).replace(/"/g, '""') + '"';
  fs.writeFileSync(csv, 'fichero,nota,veredicto,from,asunto,reglas\n' +
    resultados.map(r => [r.nombre, r.score, r.verdict, r.from, r.asunto, r.reglas.join(' ')].map(esc).join(',')).join('\n'));
  console.log('\nEscrito ' + csv);
}

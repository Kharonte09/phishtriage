/**
 * Compara dos corpus -uno de phishing y uno de correo legitimo- y saca, para
 * cada regla, cuanto dispara en cada clase.
 *
 *   node tools/verosimilitud.mjs <carpeta-phishing> <carpeta-legitimo>
 *
 * La columna que importa es la razon: cuantas veces mas aparece el indicio en
 * el fraude que en el correo bueno. Eso es lo que deberia decidir su peso, y no
 * lo que le parezca a nadie. Una regla con razon 1 no distingue nada aunque
 * suene muy grave; una con razon 30 vale su peso en oro aunque suene tonta.
 *
 * La ultima columna es el peso que le tocaria si la escala fuese logaritmica,
 * normalizada para que la regla mas discriminante valga el techo de su
 * categoria. Es una sugerencia, no un dogma: mirala antes de copiarla.
 */
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PT = require(path.join(ROOT, 'assets/parser.js'));

const [dirPhish, dirHam] = process.argv.slice(2);
if (!dirPhish || !dirHam) {
  console.error('Uso: node tools/verosimilitud.mjs <carpeta-phishing> <carpeta-legitimo>');
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

async function medir(dir, etiqueta) {
  const cuenta = {};
  let total = 0, notas = [];
  for (const f of ficheros(dir)) {
    let txt;
    try { txt = PT.bytesToLatin1(new Uint8Array(fs.readFileSync(f))); } catch (e) { continue; }
    for (const parte of (/^From \S+/.test(txt) ? partirMbox(txt) : [txt])) {
      if (!/^[\w-]+\s*:/m.test(parte)) continue;
      let r;
      try { r = await PT.analyze(parte, { filename: path.basename(f) }); } catch (e) { continue; }
      total++;
      notas.push(r.score);
      for (const id of new Set(r.findings.filter(x => x.points > 0).map(x => x.id))) {
        cuenta[id] = (cuenta[id] || 0) + 1;
      }
    }
  }
  notas.sort((a, b) => a - b);
  console.error(etiqueta + ': ' + total + ' correos, mediana ' + notas[Math.floor(notas.length / 2)]);
  return { cuenta, total };
}

const phish = await medir(dirPhish, 'phishing');
const ham = await medir(dirHam, 'legitimo');

const ids = [...new Set([...Object.keys(phish.cuenta), ...Object.keys(ham.cuenta)])];
// Correccion de Laplace: sin ella una regla que no aparece nunca en el correo
// bueno da razon infinita, que es mentira, solo es que no hay bastantes datos.
const filas = ids.map(id => {
  const pP = ((phish.cuenta[id] || 0) + 0.5) / (phish.total + 1);
  const pH = ((ham.cuenta[id] || 0) + 0.5) / (ham.total + 1);
  return {
    id,
    phish: 100 * (phish.cuenta[id] || 0) / phish.total,
    ham: 100 * (ham.cuenta[id] || 0) / ham.total,
    razon: pP / pH
  };
}).sort((a, b) => b.razon - a.razon);

const maxLog = Math.max(...filas.map(f => Math.log2(Math.max(f.razon, 1))));

console.log('\n' + 'regla'.padEnd(22) + 'phishing   legitimo      razon   sugerido');
console.log('-'.repeat(66));
for (const f of filas) {
  const peso = Math.log2(Math.max(f.razon, 1)) / maxLog;
  console.log(
    f.id.padEnd(22) +
    (f.phish.toFixed(1) + '%').padStart(8) +
    (f.ham.toFixed(1) + '%').padStart(11) +
    (f.razon >= 100 ? '>100' : f.razon.toFixed(1)).padStart(11) +
    (f.razon < 1.5 ? '   (no distingue)' : ('   x' + peso.toFixed(2)).padStart(11))
  );
}

/* PhishTriage - interfaz. Todo el trabajo real esta en eml.js y enrich.js. */
(function () {
  'use strict';

  const PT = window.PhishTriage;
  const EN = window.PhishEnrich;
  const $ = s => document.querySelector(s);
  const $$ = s => Array.from(document.querySelectorAll(s));

  let current = null;      // informe activo
  let batch = [];          // [{name, report}]

  // --- helpers -------------------------------------------------------------
  const esc = s => String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

  function el(html) { const t = document.createElement('template'); t.innerHTML = html.trim(); return t.content.firstElementChild; }

  function download(name, text, type) {
    const blob = new Blob([text], { type: type || 'text/plain;charset=utf-8' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = name;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 4000);
  }

  async function copy(text, btn) {
    try { await navigator.clipboard.writeText(text); }
    catch (e) {
      const ta = document.createElement('textarea');
      ta.value = text; document.body.appendChild(ta); ta.select();
      try { document.execCommand('copy'); } catch (e2) {}
      ta.remove();
    }
    if (btn) { const t = btn.textContent; btn.textContent = 'Copiado'; setTimeout(() => btn.textContent = t, 1200); }
  }

  const SEVLABEL = { high: 'ALTO', medium: 'MEDIO', low: 'BAJO', info: 'INFO' };

  // --- carga de ficheros ---------------------------------------------------
  async function handleFiles(files) {
    batch = [];
    for (const f of files) {
      const buf = await f.arrayBuffer();
      const raw = PT.bytesToLatin1(new Uint8Array(buf));
      try {
        const report = await PT.analyze(raw, { filename: f.name });
        batch.push({ name: f.name, report });
      } catch (e) {
        console.error(e);
        alert('No se pudo analizar ' + f.name + ': ' + e.message);
      }
    }
    if (!batch.length) return;
    renderBatchList();
    show(batch[0].report);
  }

  function renderBatchList() {
    const box = $('#multi');
    if (batch.length < 2) { box.hidden = true; box.innerHTML = ''; return; }
    box.hidden = false;
    box.innerHTML = '<div class="card"><h3>Lote (' + batch.length + ' correos)</h3><table><thead><tr>' +
      '<th>Fichero</th><th>Veredicto</th><th>Score</th><th>From</th><th>URLs</th><th>Adj.</th></tr></thead><tbody>' +
      batch.map((b, i) =>
        '<tr data-i="' + i + '" style="cursor:pointer"><td>' + esc(b.name) + '</td>' +
        '<td class="v-' + b.report.verdict + '">' + b.report.verdict + '</td>' +
        '<td class="mono">' + b.report.score + '</td>' +
        '<td class="mono">' + esc(b.report.summary.from || '-') + '</td>' +
        '<td class="mono">' + b.report.urls.length + '</td>' +
        '<td class="mono">' + b.report.attachments.length + '</td></tr>').join('') +
      '</tbody></table></div>';
    box.querySelectorAll('tr[data-i]').forEach(tr => tr.onclick = () => show(batch[+tr.dataset.i].report));
  }

  // --- render principal ----------------------------------------------------
  function show(r) {
    current = r;
    $('#result').hidden = false;
    ['#btnJson', '#btnMd', '#btnIocs', '#btnReset', '#btnEnrich'].forEach(s => $(s).disabled = false);

    // veredicto
    const ring = $('#ring'), svg = $('.score-ring');
    const circ = 2 * Math.PI * 17;
    ring.setAttribute('stroke-dasharray', (circ * r.score / 100).toFixed(1) + ' ' + circ.toFixed(1));
    $('#ringTxt').textContent = r.score;
    svg.style.color = r.score >= 50 ? 'var(--high)' : r.score >= 20 ? 'var(--med)' : 'var(--accent)';
    const t = $('#verdictTitle');
    t.textContent = 'Riesgo ' + r.verdict + ' - ' + r.score + '/100';
    t.className = 'v-' + r.verdict;
    $('#verdictSub').innerHTML = '<b>' + esc(r.summary.subject || '(sin asunto)') + '</b><br>' +
      esc(r.summary.fromDisplay || '') + ' &lt;' + esc(r.summary.from || '?') + '&gt;' +
      (r.meta.filename ? ' <span class="muted">- ' + esc(r.meta.filename) + '</span>' : '');

    const cls = v => !v ? '' : /^pass$/i.test(v) ? 'pass' : /^(fail|softfail)$/i.test(v) ? 'fail' : 'warn';
    $('#authChips').innerHTML =
      ['spf', 'dkim', 'dmarc'].map(k =>
        '<span class="chip ' + cls(r.auth[k]) + '">' + k.toUpperCase() + ' <b>' + (r.auth[k] || 'n/d') + '</b></span>').join('') +
      '<span class="chip">saltos <b>' + r.received.length + '</b></span>' +
      '<span class="chip">urls <b>' + r.urls.length + '</b></span>' +
      '<span class="chip">adj <b>' + r.attachments.length + '</b></span>';

    $('#nFind').textContent = r.findings.length;
    $('#nHead').textContent = r.headers.length;
    $('#nHops').textContent = r.received.length;
    $('#nUrls').textContent = r.urls.length;
    $('#nAtt').textContent = r.attachments.length;

    renderResumen(r); renderHallazgos(r); renderCabeceras(r); renderAuth(r);
    renderReceived(r); renderUrls(r); renderAdjuntos(r); renderCuerpo(r);
    renderIocs(r); renderEnrich(r); renderJson(r);
    window.scrollTo({ top: $('#result').offsetTop - 20, behavior: 'smooth' });
  }

  function kv(rows) {
    return '<table>' + rows.map(([k, v, hl]) =>
      '<tr' + (hl ? ' class="hl"' : '') + '><td class="k">' + esc(k) + '</td><td class="v">' + (v || '<span class="muted">-</span>') + '</td></tr>'
    ).join('') + '</table>';
  }

  function renderResumen(r) {
    const s = r.summary;
    const top = r.findings.filter(f => f.sev === 'high').slice(0, 6);
    $('#p-resumen').innerHTML =
      '<div class="card"><h3>Identidades</h3>' + kv([
        ['From', '<b>' + esc(s.fromDisplay || '') + '</b> &lt;' + esc(s.from || '-') + '&gt;', true],
        ['Dominio organizativo', esc(s.fromOrgDomain)],
        ['Reply-To', s.replyTo.length ? esc(s.replyTo.join(', ')) : '', !!s.replyTo.length],
        ['Return-Path', esc(s.returnPath)],
        ['To', esc(s.to.join(', '))],
        ['Cc', esc(s.cc.join(', '))],
        ['Asunto', esc(s.subject)],
        ['Fecha', esc(s.date)],
        ['Message-ID', esc(s.messageId)],
        ['IP de origen', s.originIP ? esc(PT.defang(s.originIP)) : '', !!s.originIP]
      ]) + '</div>' +
      (top.length ? '<div class="card"><h3>Motivos principales</h3>' +
        top.map(f => '<div class="finding"><span class="sev sev-high">ALTO</span><span>' + esc(f.msg) + '</span></div>').join('') +
        '</div>' : '') +
      '<div class="card"><h3>Estructura MIME</h3><div class="tree">' + tree(r.structure, '') + '</div></div>';
  }

  function tree(node, prefix) {
    let out = '<div><span class="muted">' + esc(prefix) + '</span><span class="n">' + esc(node.label) + '</span></div>';
    node.children.forEach((c, i) => {
      const last = i === node.children.length - 1;
      out += tree(c, prefix + (last ? '  └─ ' : '  ├─ '));
    });
    return out;
  }

  function renderHallazgos(r) {
    const order = { high: 0, medium: 1, low: 2, info: 3 };
    const list = r.findings.slice().sort((a, b) => order[a.sev] - order[b.sev]);
    $('#p-hallazgos').innerHTML = '<div class="card">' + (list.length ? list.map(f =>
      '<div class="finding"><span class="sev sev-' + f.sev + '">' + SEVLABEL[f.sev] + '</span>' +
      '<span>' + esc(f.msg) + '</span>' + (f.points ? '<span class="pts">+' + f.points + '</span>' : '') + '</div>'
    ).join('') : '<span class="muted">Sin hallazgos.</span>') + '</div>';
  }

  function renderCabeceras(r) {
    const rows = r.headers.map(h =>
      '<tr' + (h.interesting ? ' class="hl"' : '') + '><td class="k">' + esc(h.name) + '</td>' +
      '<td class="v">' + esc(h.decoded) + '</td></tr>').join('');
    $('#p-cabeceras').innerHTML =
      '<div class="card"><h3>Cabeceras <span class="muted">(en orden de aparicion; resaltadas las relevantes)</span></h3>' +
      '<table>' + rows + '</table></div>';
  }

  function renderAuth(r) {
    const a = r.auth;
    const al = v => v === true ? '<span class="pill good">alineado</span>' : v === false ? '<span class="pill bad">NO alineado</span>' : '<span class="pill">n/d</span>';
    $('#p-auth').innerHTML =
      '<div class="card"><h3>Resultado de autenticacion</h3>' + kv([
        ['SPF', esc(a.spf || 'n/d') + ' <span class="muted">smtp.mailfrom=' + esc(a.spfDomain || 'n/d') + '</span> ' + al(a.alignment.spf), true],
        ['DKIM', esc(a.dkim || 'n/d') + ' <span class="muted">header.d=' + esc(a.dkimDomain || 'n/d') + '</span> ' + al(a.alignment.dkim), true],
        ['DMARC', esc(a.dmarc || 'n/d') + ' <span class="muted">header.from=' + esc(a.dmarcFrom || 'n/d') + '</span>', true],
        ['compauth', esc(a.compauth)],
        ['ARC seals', String(a.arcSeals)]
      ]) + '</div>' +
      (a.dkimSignatures.length ? '<div class="card"><h3>Firmas DKIM</h3><table><thead><tr><th>d=</th><th>s=</th><th>a=</th><th>c=</th><th>len(b)</th></tr></thead><tbody>' +
        a.dkimSignatures.map(s => '<tr><td class="v">' + esc(s.d) + '</td><td class="v">' + esc(s.s) + '</td><td class="v">' + esc(s.a) + '</td><td class="v">' + esc(s.c) + '</td><td class="v">' + s.bLen + '</td></tr>').join('') +
        '</tbody></table></div>' : '') +
      '<div class="card"><h3>Cabeceras en bruto</h3><pre class="block">' + esc(a.raw.join('\n\n') || 'Sin Authentication-Results.') + '</pre></div>' +
      '<div class="card"><h3>Como leerlo</h3><p class="small">SPF valida la IP emisora frente al dominio del <i>sobre</i> (Return-Path), no frente al From visible. ' +
      'DKIM valida una firma criptografica del dominio <code>d=</code>. DMARC exige que al menos uno de los dos <b>pase y alinee</b> con el dominio del From. ' +
      'Un SPF=pass con DMARC=fail es la firma clasica del spoofing: el atacante autentica su propio dominio, no el que muestra.</p></div>';
  }

  function renderReceived(r) {
    if (!r.received.length) { $('#p-received').innerHTML = '<div class="card muted">Sin cabeceras Received.</div>'; return; }
    $('#p-received').innerHTML = '<div class="card"><h3>Cadena de saltos <span class="muted">(orden cronologico: abajo el mas cercano al buzon)</span></h3>' +
      r.received.map((h, i) => {
        const isOrigin = i === 0;
        return '<div class="hop' + (isOrigin ? ' origin' : '') + '">' +
          '<div class="hop-h">hop ' + h.hop + (h.delaySeconds !== null ? ' &middot; +' + h.delaySeconds + 's' : '') + (h.date ? ' &middot; ' + esc(h.date) : '') + '</div>' +
          '<div class="hop-b">' + esc(h.from || '?') + ' <span class="arrow">&rarr;</span> ' + esc(h.by || '?') +
          (h.with ? ' <span class="muted">(' + esc(h.with) + ')</span>' : '') + '</div>' +
          (h.ips.length ? '<div class="hop-b muted">' + h.ips.map(ip =>
            '<span class="pill' + (PT.isPrivateIP(ip) ? '' : ' bad') + '">' + esc(PT.defang(ip)) + (PT.isPrivateIP(ip) ? ' priv' : '') + '</span>').join(' ') + '</div>' : '') +
          (h.for ? '<div class="hop-b muted">for ' + esc(h.for) + '</div>' : '') +
          '<details><summary>cabecera en bruto</summary><pre>' + esc(h.raw) + '</pre></details>' +
          '</div>';
      }).join('') + '</div>';
  }

  function renderUrls(r) {
    if (!r.urls.length) { $('#p-urls').innerHTML = '<div class="card muted">No se han encontrado URLs.</div>'; return; }
    const sorted = r.urls.slice().sort((a, b) => b.flags.length - a.flags.length);
    $('#p-urls').innerHTML =
      '<div class="toolbar" style="margin:0 0 12px"><button id="copyUrls">Copiar URLs defanged</button></div>' +
      sorted.map(u =>
        '<div class="url-item"><div class="u">' + esc(u.defanged) + '</div>' +
        '<div class="meta">host <b>' + esc(u.host) + '</b>' + (u.port ? ':' + esc(u.port) : '') +
        ' &middot; org <b>' + esc(u.orgDomain) + '</b> &middot; origen ' + esc(u.sources.join(', ')) +
        (u.anchorTexts.length ? '<br>texto: ' + u.anchorTexts.map(t => '"' + esc(t) + '"').join(' / ') : '') + '</div>' +
        u.flags.map(f => '<div class="finding"><span class="sev sev-' + f.sev + '">' + SEVLABEL[f.sev] + '</span><span>' + esc(f.msg) + '</span></div>').join('') +
        '</div>').join('');
    const b = $('#copyUrls');
    if (b) b.onclick = () => copy(r.urls.map(u => u.defanged).join('\n'), b);
  }

  function renderAdjuntos(r) {
    if (!r.attachments.length) { $('#p-adjuntos').innerHTML = '<div class="card muted">Sin adjuntos.</div>'; return; }
    $('#p-adjuntos').innerHTML = r.attachments.map(a =>
      '<div class="att-item"><div class="name">' + esc(a.filename) + '</div>' +
      '<div class="meta">' + esc(a.mime) + ' &middot; ' + esc(a.sizeHuman) + ' &middot; transfer: ' + esc(a.declaredEncoding) +
      (a.magic ? ' &middot; magic: <b>' + esc(a.magic) + '</b>' : '') + '</div>' +
      '<div class="hashline"><b>md5</b> ' + esc(a.md5) + '</div>' +
      (a.sha1 ? '<div class="hashline"><b>sha1</b> ' + esc(a.sha1) + '</div>' : '') +
      (a.sha256 ? '<div class="hashline"><b>sha256</b> ' + esc(a.sha256) +
        ' &middot; <a target="_blank" rel="noopener noreferrer" href="https://www.virustotal.com/gui/file/' + esc(a.sha256) + '">VT</a></div>' : '') +
      a.flags.map(f => '<div class="finding"><span class="sev sev-' + f.sev + '">' + SEVLABEL[f.sev] + '</span><span>' + esc(f.msg) + '</span></div>').join('') +
      '</div>').join('') +
      '<p class="small">Los hashes se calculan en local (SHA-1/256 con WebCrypto, MD5 en JS). El contenido del adjunto nunca se envia a ningun sitio salvo que pulses "Enriquecer".</p>';
  }

  function renderCuerpo(r) {
    $('#p-cuerpo').innerHTML =
      '<div class="card"><h3>Texto plano</h3><pre class="block">' + esc(r.bodies.plain || '(vacio)') + '</pre></div>' +
      '<div class="card"><h3>HTML <span class="muted">(' + r.bodies.htmlLength + ' bytes, mostrado como codigo, nunca renderizado)</span></h3>' +
      '<pre class="block">' + esc(r.bodies.htmlSource || '(vacio)') + '</pre></div>';
  }

  function renderIocs(r) {
    const blocks = [
      ['Dominios', r.iocs.domainsDefanged],
      ['IPs', r.iocs.ips.map(PT.defang)],
      ['URLs', r.iocs.urlsDefanged],
      ['Hashes', r.iocs.hashes],
      ['Direcciones', r.iocs.emails.map(PT.defang)]
    ];
    $('#p-iocs').innerHTML = blocks.map(([t, arr]) =>
      '<div class="card"><h3>' + t + ' <span class="muted">(' + arr.length + ')</span></h3>' +
      '<pre class="block">' + esc(arr.join('\n') || '-') + '</pre></div>').join('') +
      '<div class="toolbar"><button id="copyAll">Copiar todo</button>' +
      '<button id="copyCsv">Descargar CSV</button></div>';
    $('#copyAll').onclick = e => copy(iocText(r), e.target);
    $('#copyCsv').onclick = () => {
      const rows = [['tipo', 'valor', 'defanged']];
      r.iocs.domains.forEach(d => rows.push(['domain', d, PT.defang(d)]));
      r.iocs.ips.forEach(d => rows.push(['ip', d, PT.defang(d)]));
      r.iocs.urls.forEach(d => rows.push(['url', d, PT.defang(d)]));
      r.iocs.hashes.forEach(d => rows.push(['hash', d, d]));
      r.iocs.emails.forEach(d => rows.push(['email', d, PT.defang(d)]));
      download(base(r) + '-iocs.csv', rows.map(x => x.map(v => '"' + String(v).replace(/"/g, '""') + '"').join(',')).join('\n'), 'text/csv');
    };
  }

  function iocText(r) {
    return ['# dominios', ...r.iocs.domainsDefanged, '', '# ips', ...r.iocs.ips.map(PT.defang),
      '', '# urls', ...r.iocs.urlsDefanged, '', '# hashes', ...r.iocs.hashes].join('\n');
  }

  function renderJson(r) {
    $('#p-json').innerHTML = '<div class="toolbar" style="margin:0 0 12px"><button id="copyJson">Copiar JSON</button></div>' +
      '<pre class="block">' + esc(JSON.stringify(r, null, 2)) + '</pre>';
    $('#copyJson').onclick = e => copy(JSON.stringify(r, null, 2), e.target);
  }

  function renderEnrich(r) {
    const s = EN.loadSettings();
    const configured = !!(s.proxyBase || s.vtKey || s.abuseKey);
    if (!r.enrichment) {
      const directoDesdeWeb = configured && !s.proxyBase;
      $('#p-enriquecimiento').innerHTML = '<div class="card">' +
        (configured
          ? '<div class="ok-box">Configurado (' + (s.proxyBase ? 'via proxy ' + esc(s.proxyBase) : 'claves en este navegador') +
            '). Pulsa <b>Enriquecer</b> para consultar VirusTotal y AbuseIPDB.</div>' +
            (directoDesdeWeb ? '<div class="warn-box" style="margin-top:10px">Aviso: VirusTotal y AbuseIPDB ' +
              '<b>no envian cabeceras CORS</b>, asi que el navegador bloqueara estas peticiones aunque la clave ' +
              'sea correcta. Es una limitacion de sus APIs, no un fallo tuyo. Levanta <code>cli/proxy.py</code> ' +
              'y pon su URL en Ajustes, o usa el CLI con <code>--enrich</code>.</div>' : '') +
            (location.protocol === 'https:' && /^http:\/\//i.test(s.proxyBase || '')
              ? '<div class="warn-box" style="margin-top:10px">Esta pagina va por HTTPS y el proxy por HTTP: ' +
                'el navegador cortara la peticion por contenido mixto. Sirve la app en local ' +
                '(<code>python -m http.server 8000</code>) y entra por <code>http://127.0.0.1:8000</code>.</div>' : '')
          : '<div class="warn-box">Sin configurar. Abre <b>Ajustes</b> y pon un proxy local o tus claves de API. ' +
            'Sin esto, PhishTriage sigue funcionando entero salvo la reputacion externa.</div>') +
        '<p class="small">Aviso: consultar una URL en VirusTotal la hace visible para terceros. En un incidente real puede alertar al atacante.</p></div>';
      return;
    }
    const e = r.enrichment;
    const vtRow = (k, d) => {
      const v = d.virustotal;
      if (!v) return '';
      const bad = (v.malicious || 0) + (v.suspicious || 0);
      return '<tr><td class="v">' + esc(k) + '</td>' +
        '<td class="v"><span class="pill ' + (bad ? 'bad' : 'good') + '">' + (v.malicious || 0) + '/' + ((v.malicious || 0) + (v.harmless || 0) + (v.undetected || 0) + (v.suspicious || 0)) + '</span></td>' +
        '<td class="v">' + (v.suspicious || 0) + '</td>' +
        '<td class="v">' + esc([v.asOwner, v.country, v.registrar, v.creationDate, (v.tags || []).slice(0, 3).join(' ')].filter(Boolean).join(' &middot; ')) + '</td>' +
        '<td><a target="_blank" rel="noopener noreferrer" href="' + esc(v.permalink) + '">ver</a></td></tr>';
    };
    const table = (title, obj) => {
      const keys = Object.keys(obj);
      if (!keys.length) return '';
      return '<div class="card"><h3>' + title + '</h3><table><thead><tr><th>IOC</th><th>VT malicioso</th><th>Sosp.</th><th>Contexto</th><th></th></tr></thead><tbody>' +
        keys.map(k => vtRow(k, obj[k])).join('') + '</tbody></table></div>';
    };
    const ipRows = Object.keys(e.ips).map(ip => {
      const a = e.ips[ip].abuseipdb, v = e.ips[ip].virustotal;
      return '<tr><td class="v">' + esc(PT.defang(ip)) + '</td>' +
        '<td class="v">' + (v ? '<span class="pill ' + (v.malicious ? 'bad' : 'good') + '">' + v.malicious + '</span>' : '-') + '</td>' +
        '<td class="v">' + (a ? '<span class="pill ' + (a.abuseScore >= 25 ? 'bad' : 'good') + '">' + a.abuseScore + '%</span> ' + (a.totalReports || 0) + ' rep.' : '-') + '</td>' +
        '<td class="v">' + esc([a && a.isp, a && a.countryCode, a && a.usageType, a && a.isTor ? 'TOR' : ''].filter(Boolean).join(' &middot; ')) + '</td>' +
        '<td>' + (a ? '<a target="_blank" rel="noopener noreferrer" href="' + esc(a.permalink) + '">abuse</a> ' : '') +
        (v ? '<a target="_blank" rel="noopener noreferrer" href="' + esc(v.permalink) + '">vt</a>' : '') + '</td></tr>';
    }).join('');

    $('#p-enriquecimiento').innerHTML =
      '<div class="card"><h3>Fuente</h3><p class="small">' + esc(e.via) + ' &middot; ' + esc(e.completedAt || '') + '</p>' +
      (e.errors.length ? '<div class="warn-box">' + e.errors.map(x => esc(x.kind + ': ' + x.message + ' (' + x.target + ')')).join('<br>') + '</div>' : '') + '</div>' +
      table('Hashes de adjuntos', e.files) +
      table('Dominios', e.domains) +
      table('URLs', e.urls) +
      (ipRows ? '<div class="card"><h3>IPs</h3><table><thead><tr><th>IP</th><th>VT</th><th>AbuseIPDB</th><th>Contexto</th><th></th></tr></thead><tbody>' + ipRows + '</tbody></table></div>' : '');
  }

  function base(r) {
    return (r.meta.filename || 'correo').replace(/\.[^.]+$/, '').replace(/[^\w.-]+/g, '_').slice(0, 60);
  }

  // --- eventos -------------------------------------------------------------
  const drop = $('#drop');
  drop.onclick = () => $('#file').click();
  $('#file').onchange = e => handleFiles(Array.from(e.target.files));
  ['dragenter', 'dragover'].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.add('hover'); }));
  ['dragleave', 'drop'].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.remove('hover'); }));
  drop.addEventListener('drop', e => { if (e.dataTransfer.files.length) handleFiles(Array.from(e.dataTransfer.files)); });

  document.addEventListener('paste', async e => {
    const txt = (e.clipboardData || window.clipboardData).getData('text');
    if (!txt || txt.length < 40 || !/^[\w-]+\s*:/m.test(txt)) return;
    const report = await PT.analyze(txt, { filename: 'portapapeles.eml' });
    batch = [{ name: 'portapapeles.eml', report }];
    renderBatchList();
    show(report);
  });

  $('#btnSample').onclick = async () => {
    try {
      const res = await fetch('samples/sample-phishing.eml');
      if (!res.ok) throw new Error('HTTP ' + res.status);
      const buf = await res.arrayBuffer();
      const report = await PT.analyze(PT.bytesToLatin1(new Uint8Array(buf)), { filename: 'sample-phishing.eml' });
      batch = [{ name: 'sample-phishing.eml', report }];
      renderBatchList();
      show(report);
    } catch (err) {
      alert('No se pudo cargar el ejemplo (' + err.message + '). Si abres el fichero con file://, sirvelo con "python3 -m http.server".');
    }
  };

  $('#btnJson').onclick = () => download(base(current) + '-phishtriage.json', JSON.stringify(current, null, 2), 'application/json');
  $('#btnMd').onclick = () => download(base(current) + '-informe.md', PT.toMarkdown(current), 'text/markdown');
  $('#btnIocs').onclick = e => copy(iocText(current), e.target);
  $('#btnReset').onclick = () => {
    current = null; batch = [];
    $('#result').hidden = true; $('#multi').hidden = true; $('#file').value = '';
    ['#btnJson', '#btnMd', '#btnIocs', '#btnReset', '#btnEnrich'].forEach(s => $(s).disabled = true);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  $('#btnEnrich').onclick = async e => {
    const s = EN.loadSettings();
    if (!s.proxyBase && !s.vtKey && !s.abuseKey) { openDlg(); return; }
    const btn = e.target;
    btn.disabled = true;
    const orig = btn.textContent;
    try {
      current.enrichment = await EN.enrichReport(current, s, (d, t, k) => {
        btn.textContent = 'Consultando ' + d + '/' + t + '...';
      });
    } catch (err) {
      alert('Error de enriquecimiento: ' + err.message);
    }
    btn.textContent = orig; btn.disabled = false;
    renderEnrich(current); renderJson(current);
    $$('#tabs button').forEach(b => b.classList.toggle('active', b.dataset.p === 'enriquecimiento'));
    $$('.panel').forEach(p => p.classList.toggle('active', p.dataset.p === 'enriquecimiento'));
  };

  $('#tabs').onclick = e => {
    const b = e.target.closest('button');
    if (!b) return;
    $$('#tabs button').forEach(x => x.classList.toggle('active', x === b));
    $$('.panel').forEach(p => p.classList.toggle('active', p.dataset.p === b.dataset.p));
  };

  // --- ajustes -------------------------------------------------------------
  const dlg = $('#dlg');
  function openDlg() {
    const s = EN.loadSettings();
    $('#inProxy').value = s.proxyBase || '';
    $('#inVt').value = s.vtKey || '';
    $('#inAbuse').value = s.abuseKey || '';
    $('#inMax').value = s.maxItems || 12;
    $('#inDelay').value = s.delayMs || 1000;
    if (window.PHISHTRIAGE_CONFIG) {
      $('#dlgWarn').innerHTML = 'Detectado <code>assets/config.local.js</code>: esos valores tienen prioridad ' +
        'salvo que guardes algo aqui. Recuerda que ese fichero esta en <code>.gitignore</code> y no debe subirse nunca.';
      $('#dlgWarn').className = 'ok-box';
    }
    dlg.showModal();
  }
  $('#btnSettings').onclick = openDlg;
  $('#dlgClose').onclick = () => dlg.close();
  $('#dlgSave').onclick = () => {
    EN.saveSettings({
      proxyBase: $('#inProxy').value.trim(), vtKey: $('#inVt').value.trim(), abuseKey: $('#inAbuse').value.trim(),
      maxItems: parseInt($('#inMax').value, 10) || 12, delayMs: parseInt($('#inDelay').value, 10) || 1000, enabled: true
    });
    dlg.close();
    if (current) renderEnrich(current);
  };
  $('#dlgClear').onclick = () => {
    EN.clearSettings();
    $('#inProxy').value = $('#inVt').value = $('#inAbuse').value = '';
    if (current) renderEnrich(current);
  };

  // Aviso si la pagina no se sirve por HTTPS/localhost (WebCrypto desactivado)
  if (!window.isSecureContext) {
    $('#offlineBadge').textContent = 'sin contexto seguro: SHA no disponible';
    $('#offlineBadge').style.color = 'var(--med)';
  }
})();

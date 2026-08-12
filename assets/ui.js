/* PhishTriage - interfaz: pinta lo que devuelve parser.js y gestiona los clics. */
(function () {
  'use strict';

  const PT = window.PhishTriage;
  const $ = s => document.querySelector(s);
  const $$ = s => Array.from(document.querySelectorAll(s));

  let current = null;      // informe activo
  let batch = [];          // [{name, report}]

  // --- helpers -------------------------------------------------------------
  const esc = s => String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

  function el(html) { const t = document.createElement('template'); t.innerHTML = html.trim(); return t.content.firstElementChild; }

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
    ['#btnReset'].forEach(s => $(s).disabled = false);

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

    renderSimple(r); renderResumen(r); renderHallazgos(r); renderCabeceras(r); renderAuth(r);
    renderReceived(r); renderUrls(r); renderAdjuntos(r); renderCuerpo(r);
    renderIocs(r); renderJson(r);
    // Cada correo nuevo empieza en la vista sencilla
    $$('#tabs button').forEach(b => b.classList.toggle('active', b.dataset.p === 'simple'));
    $$('.panel').forEach(p => p.classList.toggle('active', p.dataset.p === 'simple'));
    window.scrollTo({ top: $('#result').offsetTop - 20, behavior: 'smooth' });
  }

  function kv(rows) {
    return '<table>' + rows.map(([k, v, hl]) =>
      '<tr' + (hl ? ' class="hl"' : '') + '><td class="k">' + esc(k) + '</td><td class="v">' + (v || '<span class="muted">-</span>') + '</td></tr>'
    ).join('') + '</table>';
  }

  // --- Vista para gente que no es de esto -------------------------------------
  // Traduce los ids de hallazgo a frases que entienda cualquiera.
  const EN_CRISTIANO = {
    'dkim-absent': 'El correo no viene firmado por el dominio del que dice venir.',
    'compauth': 'El propio filtro de Microsoft ya lo marcó como autenticación dudosa.',
    'mid-mismatch': 'El identificador interno del correo lo generó un dominio distinto.',
    'url-tld': 'Hay enlaces a dominios del tipo que usan casi siempre los fraudes.',
    'url-http': 'Un enlace pide datos por una conexión sin cifrar.',
    'url-port': 'Un enlace usa un puerto raro, cosa de servidores montados a mano.',
    'url-creds': 'Hay enlaces que llevan a páginas de "inicio de sesión" o "verificar cuenta".',
    'dmarc-fail': 'El correo no pasa la verificación del dominio que dice ser.',
    'spf-fail': 'El servidor que lo envió no está autorizado por ese dominio.',
    'dkim-fail': 'La firma del correo no es válida: alguien lo ha manipulado o falsificado.',
    'align-none': 'Quien lo envió de verdad no tiene nada que ver con el remitente que se muestra.',
    'rp-mismatch': 'La dirección real del remitente no coincide con la que aparece.',
    'replyto-mismatch': 'Si respondes, tu respuesta iría a una dirección distinta de la que ves.',
    'dn-brand': 'El nombre que se muestra imita a una marca conocida, pero la dirección real es otra.',
    'dn-email': 'El nombre del remitente lleva escrita una dirección falsa para despistar.',
    'from-punycode': 'El dominio del remitente usa letras raras que imitan a otro dominio.',
    'from-tld': 'El remitente usa un tipo de dominio muy barato, tipico de fraudes.',
    'subj-urgency': 'El asunto mete prisa o amenaza: es la técnica más vieja del manual.',
    'subj-nothread': 'Simula ser la respuesta a una conversacion que nunca existió.',
    'body-password': 'Trae un formulario que pide tu contraseña. Ningún banco ni empresa hace eso.',
    'body-form': 'Trae un formulario incrustado para que escribas datos dentro del correo.',
    'body-script': 'Trae código de programa escondido dentro del mensaje.',
    'body-refresh': 'Intenta redirigirte solo a otra página al abrirlo.',
    'body-hidden': 'Lleva texto invisible para colarse en el filtro antispam.',
    'body-image': 'Es casi todo una imagen, para que los filtros no puedan leerlo.',
    'body-bec': 'Pide cambiar datos bancarios o hacer un pago.',
    'body-crypto': 'Habla de criptomonedas: tipico de estafas de inversión o de extorsión.',
    'xmailer': 'Se ha enviado con una herramienta de correo masivo, no con un cliente normal.',
    'url-mismatch': 'Un enlace enseña una dirección pero lleva a otra distinta.',
    'url-ip': 'Un enlace apunta a una IP en vez de a una web con nombre.',
    'url-punycode': 'Un enlace usa un dominio con letras que imitan a otro conocido.',
    'url-brand': 'Un enlace mete el nombre de una marca dentro de un dominio que no es suyo.',
    'url-shortener': 'Hay enlaces acortados que esconden a donde llevan de verdad.',
    'url-creds': 'Hay enlaces que llevan a páginas de "inicio de sesion" o "verificar cuenta".',
    'url-userinfo': 'Un enlace esta construido para aparentar un destino que no es el real.',
    'att-exec': 'Trae un adjunto que es un programa: abrirlo instalaria algo en tu equipo.',
    'att-macro': 'Trae un documento de Office con macros, que pueden ejecutar programas.',
    'att-html': 'Trae una página web como adjunto: truco habitual para robar contraseñas.',
    'att-double': 'Un adjunto tiene doble extensión para parecer un PDF o una foto.',
    'att-mismatch': 'Un adjunto dice ser una cosa y por dentro es otra.',
    'att-rtlo': 'El nombre de un adjunto usa un truco para verse del reves.'
  };

  const CONSEJOS = {
    CRITICO: ['No pulses ningún enlace ni abras los adjuntos.',
      'No respondas ni llames a los teléfonos que aparezcan en el correo.',
      'Si ya pusiste tu contraseña en algún sitio, cambiala YA desde otra pestaña entrando tu a la web oficial, y activa la verificación en dos pasos.',
      'Si dice ser tu banco, tu empresa o la administracion, llama al teléfono que aparece en su web oficial o en el reverso de tu tarjeta, nunca al del correo.',
      'Reenvialo a tu departamento de seguridad o denuncialo, y después borralo.'],
    ALTO: ['No pulses ningún enlace ni abras los adjuntos.',
      'No respondas al correo.',
      'Verifica por otro canal: entra tu a la web oficial escribiendo la dirección a mano, o llama al teléfono de siempre.',
      'Si te lo esperabas de verdad, pregunta al remitente por otra via antes de tocar nada.'],
    MEDIO: ['Trata el correo con desconfianza: no pulses enlaces ni abras adjuntos por ahora.',
      'Confirma por otro canal que el remitente te ha escrito de verdad.',
      'Si te pide dinero, datos personales o una contraseña, da por hecho que es fraude hasta que lo confirmes.'],
    BAJO: ['No he visto indicios claros de fraude, pero esto no es una garantia.',
      'Si el correo te pide dinero, contraseñas o datos personales, verificalo igualmente por otro canal.',
      'Ante la duda, no pulses el enlace: entra tu a la web escribiendo la dirección a mano.']
  };

  const TITULARES = {
    CRITICO: ['Esto es un fraude casi con total seguridad', 'No toques nada de este correo.'],
    ALTO: ['Muy sospechoso: trátalo como fraude', 'Tiene varias señales claras de phishing.'],
    MEDIO: ['Sospechoso: no te fies todavia', 'Hay cosas que no cuadran en este correo.'],
    BAJO: ['No he encontrado señales claras de fraude', 'Aun así, revisa lo de siempre antes de fiarte.']
  };

  const vtSearch = q => 'https://www.virustotal.com/gui/search/' + encodeURIComponent(q);
  const vtFile = h => 'https://www.virustotal.com/gui/file/' + encodeURIComponent(h);
  const abuseIp = ip => 'https://www.abuseipdb.com/check/' + encodeURIComponent(ip);

  function renderSimple(r) {
    const [titulo, sub] = TITULARES[r.verdict];
    const vistos = [];
    for (const f of r.findings) {
      const txt = EN_CRISTIANO[f.id];
      if (txt && vistos.indexOf(txt) < 0) vistos.push(txt);
    }
    const razones = vistos.slice(0, 8);

    const quien = r.summary.fromDisplay
      ? '<b>' + esc(r.summary.fromDisplay) + '</b> pero la dirección real es <code>' + esc(r.summary.from || '?') + '</code>'
      : '<code>' + esc(r.summary.from || '?') + '</code>';

    // Comprobaciones de un clic: no hacen falta claves de API, abren la web pública.
    const comprobar = [];
    for (const a of r.attachments) {
      if (a.sha256) comprobar.push(['Adjunto: ' + a.filename, vtFile(a.sha256), 'VirusTotal']);
    }
    for (const d of r.iocs.domains.slice(0, 8)) comprobar.push(['Dominio: ' + d, vtSearch(d), 'VirusTotal']);
    for (const ip of r.iocs.ips.slice(0, 5)) comprobar.push(['Servidor: ' + ip, abuseIp(ip), 'AbuseIPDB']);

    $('#p-simple').innerHTML =
      '<div class="card">' +
      '<h2 class="v-' + r.verdict + '" style="margin:0 0 4px;font-size:22px">' + esc(titulo) + '</h2>' +
      '<p class="muted" style="margin:0 0 12px">' + esc(sub) + '</p>' +
      '<table><tr><td class="k">Dice ser de</td><td class="v">' + quien + '</td></tr>' +
      '<tr><td class="k">Asunto</td><td class="v">' + esc(r.summary.subject || '(sin asunto)') + '</td></tr>' +
      '<tr><td class="k">Enlaces / adjuntos</td><td class="v">' + r.urls.length + ' enlaces, ' +
      r.attachments.length + ' adjuntos</td></tr></table></div>' +

      (razones.length ? '<div class="card"><h3>Por que lo digo</h3>' +
        razones.map(t => '<div class="finding"><span class="sev sev-' +
          (r.verdict === 'BAJO' ? 'info' : 'high') + '">&#9679;</span><span>' + esc(t) + '</span></div>').join('') +
        '</div>' : '') +

      '<div class="card"><h3>Que hacer ahora</h3><ol style="margin:0;padding-left:20px">' +
      CONSEJOS[r.verdict].map(c => '<li style="margin-bottom:6px">' + esc(c) + '</li>').join('') +
      '</ol></div>' +

      (comprobar.length ? '<div class="card"><h3>Comprobar en servicios públicos <span class="muted">(sin registrarte)</span></h3>' +
        '<p class="small">Cada boton abre una pestaña nueva con la ficha pública de ese dato. Si sale en rojo, ' +
        'es que ya lo han denunciado otros.</p>' +
        '<div class="chips">' + comprobar.map(([label, url, svc]) =>
          '<a class="btn" target="_blank" rel="noopener noreferrer" href="' + esc(url) + '">' +
          esc(label.length > 46 ? label.slice(0, 46) + '...' : label) + ' &rarr; ' + svc + '</a>').join('') +
        '</div>' +
        '<p class="small" style="margin-top:10px">Ojo: al abrirlos le estas contando a esos servicios que has ' +
        'recibido este correo. Para un correo normal da igual; si estas investigando un ataque dirigido, mejor no.</p>' +
        '</div>' : '') +

      '<div class="card"><h3>Denunciarlo (España)</h3><p class="small">' +
      'INCIBE atiende dudas de ciberseguridad en el <b>017</b>, gratuito y confidencial. ' +
      'Si ha habido perdida de dinero o de datos, se denuncia ante Policia Nacional o Guardia Civil. ' +
      'Si es un correo de tu empresa, reenvialo a tu equipo de seguridad <b>como adjunto</b> ' +
      '(así conserva las cabeceras) antes de borrarlo.</p></div>' +

      '<p class="small">Esto es un análisis automatico y orientativo: acierta con los fraudes de manual, ' +
      'pero ni detecta todo ni acierta siempre. En las otras pestañas tienes el detalle técnico completo.</p>';
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
    // Cómo se reparte la nota: cada categoría suma hasta su techo y nada más
    const desglose = '<div class="card"><h3>Cómo se reparte la nota ' +
      '<span class="muted">(cada categoría tiene un techo; los techos suman 100)</span></h3>' +
      '<table><thead><tr><th>Categoría</th><th>Cuenta</th><th>Reparto</th>' +
      '<th>Bruto</th><th>Reglas</th></tr></thead><tbody>' +
      r.scoreBreakdown.map(d =>
        '<tr><td>' + esc(d.nombre) + '</td>' +
        '<td class="v nowrap">' + d.puntos + '/' + d.techo + '</td>' +
        '<td style="width:40%"><div style="background:var(--bg3);border-radius:3px;height:10px">' +
        '<div style="width:' + (100 * d.puntos / d.techo) + '%;height:10px;border-radius:3px;background:' +
        (d.puntos === d.techo ? 'var(--high)' : d.puntos ? 'var(--med)' : 'transparent') + '"></div></div></td>' +
        '<td class="v">' + d.bruto + '</td><td class="v">' + d.reglas + '</td></tr>').join('') +
      '<tr><td><b>Total</b></td><td class="v"><b>' + r.score + '/100</b></td>' +
      '<td colspan="3" class="muted">' + esc(r.verdict) + '</td></tr>' +
      '</tbody></table></div>';
    $('#p-hallazgos').innerHTML = desglose + '<div class="card">' + (list.length ? list.map(f =>
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
      '<div class="card"><h3>Resultado de autenticación</h3>' + kv([
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
      '<p class="small">Los hashes se calculan en local (SHA-1/256 con WebCrypto, MD5 en JS). El contenido del adjunto nunca se envia a ningún sitio salvo que pulses "Enriquecer".</p>';
  }

  function renderCuerpo(r) {
    $('#p-cuerpo').innerHTML =
      '<div class="card"><h3>Texto plano</h3><pre class="block">' + esc(r.bodies.plain || '(vacio)') + '</pre></div>' +
      '<div class="card"><h3>HTML <span class="muted">(' + r.bodies.htmlLength + ' bytes, mostrado como código, nunca renderizado)</span></h3>' +
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
      '<div class="toolbar"><button id="copyAll">Copiar todo</button></div>';
    $('#copyAll').onclick = e => copy(iocText(r), e.target);
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

  $('#btnReset').onclick = () => {
    current = null; batch = [];
    $('#result').hidden = true; $('#multi').hidden = true; $('#file').value = '';
    ['#btnReset'].forEach(s => $(s).disabled = true);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  $('#tabs').onclick = e => {
    const b = e.target.closest('button');
    if (!b) return;
    $$('#tabs button').forEach(x => x.classList.toggle('active', x === b));
    $$('.panel').forEach(p => p.classList.toggle('active', p.dataset.p === b.dataset.p));
  };

  // Aviso si la página no se sirve por HTTPS/localhost (WebCrypto desactivado)
  if (!window.isSecureContext) {
    $('#offlineBadge').textContent = 'sin contexto seguro: SHA no disponible';
    $('#offlineBadge').style.color = 'var(--med)';
  }
})();

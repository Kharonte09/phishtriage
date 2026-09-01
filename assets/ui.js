/* PhishTriage - interfaz: representa el informe de parser.js y gestiona la interacción. */
(function () {
  'use strict';

  const PT = window.PhishTriage;
  const $ = s => document.querySelector(s);
  const $$ = s => Array.from(document.querySelectorAll(s));

  let batch = [];

  const esc = s => String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

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

  const hallazgo = (sev, cuerpo) =>
    '<div class="finding"><span class="sev sev-' + sev + '">' + SEVLABEL[sev] + '</span><span>' + cuerpo + '</span></div>';

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
        alert(e.formatoNoSoportado ? e.message : 'No se ha podido analizar ' + f.name + ': ' + e.message);
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
        '<td class="mono">' + b.report.summary.urlCount + '</td>' +
        '<td class="mono">' + b.report.attachments.length + '</td></tr>').join('') +
      '</tbody></table></div>';
    box.querySelectorAll('tr[data-i]').forEach(tr => tr.onclick = () => show(batch[+tr.dataset.i].report));
  }

  function show(r) {
    $('#result').hidden = false;
    $('#btnReset').disabled = false;

    const [titulo, lede] = TITULARES[r.verdict];
    $('#verdictBox').className = 'verdict r-' + r.verdict;
    const ring = $('#ring'), svg = $('.score-ring');
    const circ = 2 * Math.PI * 17;
    ring.setAttribute('stroke-dasharray', (circ * r.score / 100).toFixed(1) + ' ' + circ.toFixed(1));
    $('#ringTxt').textContent = r.score;
    svg.style.color = r.score >= 50 ? 'var(--high)' : r.score >= 18 ? 'var(--med)' : 'var(--accent)';
    const t = $('#verdictTitle');
    t.textContent = titulo;
    t.className = 'v-' + r.verdict;
    $('#verdictLede').textContent = lede;
    $('#verdictNota').textContent = 'Riesgo ' + (VERDICTO_ES[r.verdict] || r.verdict) +
      ' · ' + r.score + ' de 100' + (r.meta.filename ? ' · ' + r.meta.filename : '');
    renderSobre(r);

    $('#nFind').textContent = r.findings.length;
    $('#nHead').textContent = r.headers.length;
    $('#nHops').textContent = r.received.length;
    $('#nUrls').textContent = r.summary.urlCount;
    $('#nAtt').textContent = r.attachments.length;

    renderSimple(r); renderResumen(r); renderHallazgos(r); renderCabeceras(r); renderAuth(r);
    renderReceived(r); renderUrls(r); renderAdjuntos(r); renderCuerpo(r);
    renderIocs(r); renderJson(r);
    $$('#tabs button').forEach(b => b.classList.toggle('active', b.dataset.p === 'resumen'));
    $$('.panel').forEach(p => p.classList.toggle('active', p.dataset.p === 'resumen'));
    window.scrollTo({ top: $('#result').offsetTop - 20, behavior: 'smooth' });
  }

  function kv(rows) {
    return '<table>' + rows.map(([k, v, hl]) =>
      '<tr' + (hl ? ' class="hl"' : '') + '><td class="k">' + esc(k) + '</td><td class="v">' + (v || '<span class="muted">-</span>') + '</td></tr>'
    ).join('') + '</table>';
  }

  const EXPLICACIONES = {
    'url-tld': 'Los enlaces apuntan a dominios del tipo que emplean habitualmente los fraudes.',
    'replyto-freemail': 'Si respondes, la respuesta se dirige a una cuenta distinta de la que envía.',
    'from-freemail-cargo': 'Se presenta como responsable de una empresa, pero escribe desde una cuenta gratuita.',
    'body-iban': 'Facilita un número de cuenta para que ingreses el dinero.',
    'body-nocontacto': 'Pide que no llames ni lo comentes con nadie, para que nadie pueda desmentirlo.',
    'combo-bec': 'Suplanta a una persona de confianza para conseguir un pago.',
    'combo-credenciales': 'Dirige a una página falsa preparada para capturar tu contraseña.',
    'combo-malware': 'Adjunta un archivo peligroso y añade urgencia para que lo abras.',
    'combo-extorsion': 'Amenaza y reclama un pago en criptomonedas.',
    'dmarc-fail': 'El correo no procede del dominio que dice representar.',
    'spf-fail': 'Lo ha enviado un servidor que no pertenece a esa empresa.',
    'dkim-fail': 'La firma del correo no valida: el mensaje se ha alterado o es falso.',
    'from-punycode': 'La dirección usa caracteres especiales que imitan a otra conocida.',
    'from-tld': 'Escribe desde un tipo de dominio barato, frecuente en fraudes.',
    'subj-urgency': 'El asunto mete prisa o amenaza: es el recurso más antiguo del fraude.',
    'body-password': 'Solicita la contraseña dentro del propio correo. Ninguna entidad lo hace.',
    'body-refresh': 'Redirige por sí solo a otra página nada más abrirlo.',
    'body-hidden': 'Incluye texto invisible para eludir el filtro de spam.',
    'body-image': 'Es casi todo una imagen, para que los filtros no puedan leer su texto.',
    'body-bec': 'Solicita un pago o un cambio de datos bancarios.',
    'mime-profundo': 'El mensaje anida sus partes unas dentro de otras muchas veces: se hace para que el análisis no llegue al fondo.',
    'dn-suplanta-propio': 'Se hace pasar por tu propia empresa o tu proveedor de correo, pero escribe desde fuera. Tu departamento informático no escribe desde otro dominio.',
    'from-basura': 'El dominio del remitente está generado automáticamente, del tipo que se registra por miles para un fraude y se abandona.',
    'body-buzon': 'Alega que tu buzón está lleno, que tu contraseña caduca o que tienes correo retenido: es el pretexto más habitual para conseguir credenciales.',
    'url-hosting-gratis': 'El enlace lleva a una página en alojamiento gratuito, no al sitio de la empresa que dice representar.',
    'subj-premio': 'Anuncia un premio, un sorteo o un bono que no has solicitado.',
    'att-senuelo': 'Casi todo el mensaje está en el adjunto y no incluye ningún enlace: pretende que abras el fichero sin comprobarlo.',
    'dn-oficial-freemail': 'Firma como un departamento oficial o una marca, pero escribe desde una cuenta gratuita. Una empresa no opera así.',
    'body-crypto': 'Menciona criptomonedas: habitual en fraudes de inversión y en la extorsión.',
    'body-callback': 'Facilita un teléfono para cancelar un cobro que no has realizado. En la llamada te solicitarán tus datos.',
    'xmailer': 'Se ha enviado con una herramienta de envíos masivos, no desde un cliente de correo corriente.',
    'url-mismatch': 'Un enlace muestra una dirección pero conduce a otra distinta.',
    'url-ip': 'Un enlace apunta a una dirección numérica en lugar de a un dominio.',
    'url-punycode': 'Un enlace usa caracteres especiales que imitan a un sitio conocido.',
    'url-shortener': 'Hay enlaces acortados que ocultan su destino real.',
    'url-userinfo': 'Un enlace está construido para aparentar un destino que no es el real.',
    'att-exec': 'Adjunta un programa: abrirlo instalaría software en tu equipo.',
    'att-macro': 'Adjunta un Word o un Excel con macros, capaces de ejecutar programas.',
    'att-html': 'Adjunta una página web como archivo: recurso habitual para robar contraseñas.',
    'att-double': 'Un archivo lleva doble extensión para aparentar un PDF o una imagen.',
    'att-mismatch': 'Un archivo declara un formato y por dentro contiene otro.',
    'att-rtlo': 'El nombre de un archivo emplea un truco para mostrarse invertido.',
    'dn-mixed-script': 'El nombre del remitente mezcla caracteres de otro alfabeto visualmente idénticos a los nuestros.',
    'from-malformed': 'La dirección del remitente está manipulada para que el cliente de correo muestre una cosa y el filtro lea otra.',
    'from-lookalike': 'Escribe desde un dominio que imita el de una marca conocida, con alguna letra cambiada.',
    'dmarc-none': 'El dominio remitente no ha configurado la protección que impide su suplantación.',
    'spf-softfail': 'El servidor que lo ha enviado no es exactamente el autorizado.',
    'spf-neutral': 'El dominio remitente no declara quién puede enviar en su nombre.',
    'compauth': 'Los filtros de Microsoft no han podido confirmar su autenticidad.',
    'from-multi': 'El correo declara varios remitentes a la vez: técnica para confundir a los filtros.',
    'url-zerowidth': 'Un enlace lleva caracteres invisibles intercalados para disimular su destino.',
    'url-rtlo': 'Un enlace emplea un truco para que la dirección se lea invertida.',
    'url-data': 'Un enlace incrusta una página completa dentro del propio correo.',
    'url-multi-at': 'Un enlace muestra al principio una dirección conocida, pero el destino real es otro.',
    'url-subdomains': 'Un enlace encadena tantos nombres que el verdadero queda oculto al final.',
    'att-archive-nested': 'Adjunta un comprimido con otro dentro, para impedir el análisis antivirus.',
    'att-encrypted': 'Adjunta un archivo con contraseña, de modo que ningún antivirus puede examinarlo.',
    'att-ole': 'Un archivo contiene un formato antiguo de Office que no corresponde a su extensión.',
    'body-empty': 'El mensaje no dice nada: solo aporta el archivo adjunto.',
    'rcv-none': 'No consta por dónde ha pasado: se ha inyectado directamente o se ha borrado su rastro.',
    'date-missing': 'El correo no lleva fecha.',
    'date-skew': 'La fecha del correo no concuerda con la de los servidores por los que pasó.',
  };

  const CONSEJOS = {
    CRITICO: ['No abras ningún enlace ni ningún archivo adjunto.',
      'No respondas al mensaje ni llames a los teléfonos que incluye.',
      'Si ya has introducido tu contraseña, cámbiala ahora: accede a la web oficial escribiendo tú la dirección, nunca desde este correo.',
      'Si dice ser tu banco, llama al número que figura en el reverso de tu tarjeta, nunca al que indica el mensaje.',
      'Hecho lo anterior, elimina el correo.'],
    ALTO: ['No abras ningún enlace ni ningún archivo adjunto.',
      'No respondas al mensaje ni llames a los teléfonos que incluye.',
      'Verifícalo por otra vía: accede a la web oficial escribiendo tú la dirección, o llama al teléfono habitual.'],
    MEDIO: ['De momento, no abras enlaces ni archivos adjuntos.',
      'Confirma con el remitente por otra vía: llámale o escríbele a la dirección que ya tenías.',
      'Si solicita dinero, datos o contraseñas, considéralo fraude mientras no se confirme lo contrario.'],
    BAJO: ['No se han detectado indicios claros de fraude, pero esto no es una garantía.',
      'Si solicita dinero, contraseñas o datos personales, verifícalo igualmente por otra vía.',
      'Ante la duda, no abras el enlace: accede a la web escribiendo tú la dirección.']
  };

  const TITULARES = {
    CRITICO: ['Es casi con seguridad un fraude', 'No interactúes con ningún elemento del mensaje.'],
    ALTO: ['Trátalo como un fraude', 'Presenta varias señales claras de engaño.'],
    MEDIO: ['Desconfía de este correo', 'Hay elementos que no encajan.'],
    BAJO: ['No se han detectado señales de fraude', 'Aun así, verifica lo que solicite antes de atenderlo.']
  };

  const VERDICTO_ES = { CRITICO: 'CRÍTICO', ALTO: 'ALTO', MEDIO: 'MEDIO', BAJO: 'BAJO' };

  const vtSearch = q => 'https://www.virustotal.com/gui/search/' + encodeURIComponent(q);
  const vtFile = h => 'https://www.virustotal.com/gui/file/' + encodeURIComponent(h);
  const abuseIp = ip => 'https://www.abuseipdb.com/check/' + encodeURIComponent(ip);

  const RELAYS = {
    'privaterelay.appleid.com': 'un alias de «Ocultar mi correo» de Apple',
    'duck.com': 'un alias de DuckDuckGo',
    'mozmail.com': 'un alias de Firefox Relay',
    'simplelogin.co': 'un alias de SimpleLogin',
    'anonaddy.me': 'un alias de AnonAddy'
  };

  function direccionCorta(addr) {
    if (!addr) return '?';
    const i = addr.lastIndexOf('@');
    if (i < 0) return addr;
    const local = addr.slice(0, i), dominio = addr.slice(i + 1);
    const cortada = local.length > 22 ? local.slice(0, 20) + '…' : local;
    return esc(cortada) + '@<b>' + esc(dominio) + '</b>';
  }

  function renderSobre(r) {
    const relay = RELAYS[r.summary.fromOrgDomain];
    $('#sobre').innerHTML =
      '<div><span class="et">Dice ser</span>' +
      (r.summary.fromDisplay ? '<b>' + esc(r.summary.fromDisplay) + '</b>'
                             : '<span class="muted">no indica ningún nombre</span>') + '</div>' +
      '<div><span class="et">Escribe desde</span><code>' + direccionCorta(r.summary.from) + '</code></div>' +
      (relay ? '<div class="small" style="margin-left:108px">Es ' + relay + ': la dirección real está oculta.</div>' : '') +
      '<div><span class="et">Asunto</span>' + esc(r.summary.subject || '(sin asunto)') + '</div>';
  }

  function renderSimple(r) {
    const vistos = [];
    for (const f of r.findings.slice().sort((a, b) => (b.points || 0) - (a.points || 0))) {
      if (!(f.points > 0)) continue;
      const txt = EXPLICACIONES[f.id];
      if (txt && vistos.indexOf(txt) < 0) vistos.push(txt);
    }
    const razones = vistos.slice(0, 5);
    const calma = r.verdict === 'BAJO';

    $('#p-simple').innerHTML =
      (razones.length
        ? '<div class="card' + (calma ? ' calma' : '') + '"><h3>' +
          (calma ? 'Observaciones' : 'Motivos') + '</h3>' +
          razones.map(t => '<div class="motivo"><span class="punto">&#9679;</span><span>' + esc(t) + '</span></div>').join('') +
          '</div>'
        : '') +

      '<div class="card"><h3>Recomendaciones</h3><ol class="consejos">' +
      CONSEJOS[r.verdict].map(c => '<li>' + esc(c) + '</li>').join('') +
      '</ol></div>' +

      '<div class="aviso-017"><b>¿Necesitas una confirmación?</b><br>' +
      'INCIBE atiende consultas en el <b>017</b>, de forma gratuita y sin facilitar tus datos. ' +
      'Si ya se ha producido una pérdida económica, denúncialo ante la Policía Nacional o la Guardia Civil.</div>';
  }

  function comprobaciones(r) {
    const out = [];
    for (const a of r.attachments) {
      if (a.sha256) out.push(['Adjunto: ' + a.filename, vtFile(a.sha256), 'VirusTotal']);
    }
    const dominiosUtiles = [...new Set(r.urls
      .filter(u => u.tipo === 'enlace' && !u.propio && u.orgDomain)
      .map(u => u.orgDomain))].slice(0, 6);
    for (const d of dominiosUtiles) out.push(['Dominio: ' + d, vtSearch(d), 'VirusTotal']);
    if (r.summary.originIP) out.push(['Servidor de origen: ' + r.summary.originIP, abuseIp(r.summary.originIP), 'AbuseIPDB']);
    return out;
  }

  function renderResumen(r) {
    const s = r.summary;
    const top = r.findings.filter(f => f.sev === 'high').slice(0, 6);
    const cls = v => !v ? '' : /^pass$/i.test(v) ? 'pass' : /^(fail|softfail)$/i.test(v) ? 'fail' : 'warn';
    $('#p-resumen').innerHTML =
      '<div class="card"><h3>De un vistazo</h3><div class="chips">' +
      ['spf', 'dkim', 'dmarc'].map(k =>
        '<span class="chip ' + cls(r.auth[k]) + '">' + k.toUpperCase() + ' <b>' + (r.auth[k] || 'n/d') + '</b></span>').join('') +
      '<span class="chip">saltos <b>' + r.received.length + '</b></span>' +
      '<span class="chip">enlaces <b>' + s.urlCount + '</b></span>' +
      '<span class="chip">adjuntos <b>' + r.attachments.length + '</b></span>' +
      '</div></div>' +
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
        top.map(f => hallazgo('high', esc(f.msg))).join('') +
        '</div>' : '') +
      comprobarCard(r) +
      '<div class="card"><h3>Estructura MIME</h3><div class="tree">' + tree(r.structure, '') + '</div></div>';
  }

  function comprobarCard(r) {
    const lista = comprobaciones(r);
    if (!lista.length) return '';
    return '<div class="card"><h3>Comprobar en servicios públicos <span class="muted">(no requiere registro)</span></h3>' +
      '<div class="chips">' + lista.map(([label, url, svc]) =>
        '<a class="btn" target="_blank" rel="noopener noreferrer" href="' + esc(url) + '">' +
        esc(label.length > 46 ? label.slice(0, 46) + '...' : label) + ' &rarr; ' + svc + '</a>').join('') +
      '</div></div>';
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
    const desglose = '<div class="card"><h3>Reparto de la puntuación ' +
      '<span class="muted">(cada categoría tiene un techo; los techos suman 100)</span></h3>' +
      '<table><thead><tr><th>Categoría</th><th>Cuenta</th><th>Reparto</th>' +
      '<th>Bruto</th><th>Reglas</th></tr></thead><tbody>' +
      r.scoreBreakdown.map(d =>
        '<tr><td>' + esc(d.nombre) + '</td>' +
        '<td class="v nowrap">' + d.puntos + '/' + d.techo + '</td>' +
        '<td style="width:40%"><div style="background:var(--bg3);border-radius:3px;height:10px">' +
        '<div style="width:' + Math.max(0, Math.min(100, 100 * d.puntos / d.techo)) + '%;height:10px;border-radius:3px;background:' +
        (d.puntos === d.techo ? 'var(--high)' : d.puntos ? 'var(--med)' : 'transparent') + '"></div></div></td>' +
        '<td class="v">' + d.bruto + '</td><td class="v">' + d.reglas + '</td></tr>').join('') +
      '<tr><td><b>Total</b></td><td class="v"><b>' + r.score + '/100</b></td>' +
      '<td colspan="3" class="muted">' + esc(r.verdict) + '</td></tr>' +
      '</tbody></table></div>';
    $('#p-hallazgos').innerHTML = desglose + '<div class="card">' + (list.length ? list.map(f =>
      hallazgo(f.sev, esc(f.msg) +
        (f.fuente ? '<br><span class="muted small">peso ' + f.points + ' &middot; ' + esc(f.fuente) + '</span>' : '')) +
      (f.points ? '<span class="pts">' + (f.points > 0 ? '+' : '') + f.points + '</span>' : '')
    ).join('') : '<span class="muted">Sin hallazgos.</span>') + '</div>';
  }

  function renderCabeceras(r) {
    const rows = r.headers.map(h =>
      '<tr' + (h.interesting ? ' class="hl"' : '') + '><td class="k">' + esc(h.name) + '</td>' +
      '<td class="v">' + esc(h.decoded) + '</td></tr>').join('');
    $('#p-cabeceras').innerHTML =
      '<div class="card"><h3>Cabeceras <span class="muted">(en orden de aparición; resaltadas las relevantes)</span></h3>' +
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
      '<div class="card"><h3>Cabeceras en bruto</h3><pre class="block">' + esc(a.raw.join('\n\n') || 'Sin Authentication-Results.') + '</pre></div>';
  }

  function renderReceived(r) {
    if (!r.received.length) { $('#p-received').innerHTML = '<div class="card muted">Sin cabeceras Received.</div>'; return; }
    $('#p-received').innerHTML = '<div class="card"><h3>Cadena de saltos <span class="muted">(orden cronológico: el último es el más cercano al buzón)</span></h3>' +
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

  function agrupar(lista) {
    const mapa = new Map();
    for (const u of lista) {
      const clave = u.scheme + '://' + u.host + u.path.split('?')[0];
      if (!mapa.has(clave)) mapa.set(clave, Object.assign({}, u, { veces: 0 }));
      mapa.get(clave).veces++;
    }
    return Array.from(mapa.values());
  }

  function renderUrls(r) {
    if (!r.urls.length) { $('#p-urls').innerHTML = '<div class="card muted">No se han encontrado URLs.</div>'; return; }
    const pinta = u =>
        '<div class="url-item"><div class="u">' + esc(u.defanged) + '</div>' +
        '<div class="meta">host <b>' + esc(u.host) + '</b>' + (u.port ? ':' + esc(u.port) : '') +
        ' &middot; org <b>' + esc(u.orgDomain) + '</b>' + (u.propio ? ' <span class="pill good">del remitente</span>' : '') +
        (u.veces > 1 ? ' &middot; <b>x' + u.veces + '</b>' : '') +
        (u.anchorTexts.length ? '<br>texto: ' + u.anchorTexts.map(t => '"' + esc(t) + '"').join(' / ') : '') + '</div>' +
        u.flags.map(f => hallazgo(f.sev, esc(f.msg))).join('') +
        '</div>';

    const enlaces = agrupar(r.urls.filter(u => u.tipo === 'enlace')).sort((a, b) => b.flags.length - a.flags.length);
    const recursos = agrupar(r.urls.filter(u => u.tipo === 'recurso')).sort((a, b) => b.flags.length - a.flags.length);

    $('#p-urls').innerHTML =
      '<div class="toolbar" style="margin:0 0 12px"><button id="copyUrls">Copiar todo defanged</button></div>' +
      '<div class="card"><h3>Enlaces del mensaje ' +
      '<span class="muted">(' + enlaces.length + ' destinos distintos)</span></h3></div>' +
      enlaces.map(pinta).join('') +
      (recursos.length
        ? '<details class="card"><summary style="cursor:pointer">Recursos que carga el mensaje por sí solo: ' +
          'imágenes, iconos y fuentes <span class="muted">(' + recursos.length + ' destinos)</span></summary>' +
          recursos.map(pinta).join('') + '</details>'
        : '');
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
        ' &middot; <a target="_blank" rel="noopener noreferrer" href="' + esc(vtFile(a.sha256)) + '">VT</a></div>' : '') +
      a.flags.map(f => hallazgo(f.sev, esc(f.msg))).join('') +
      '</div>').join('') +
      '<p class="small">El contenido del adjunto no sale del navegador: al abrir VirusTotal solo se envía el hash.</p>';
  }

  function renderCuerpo(r) {
    $('#p-cuerpo').innerHTML =
      '<div class="card"><h3>Texto plano</h3><pre class="block">' + esc(r.bodies.plain || '(vacío)') + '</pre></div>' +
      '<div class="card"><h3>HTML <span class="muted">(' + r.bodies.htmlLength + ' bytes, mostrado como código, nunca renderizado)</span></h3>' +
      '<pre class="block">' + esc(r.bodies.htmlSource || '(vacío)') + '</pre></div>';
  }

  function bloquesIoc(r) {
    const d = arr => arr.map(PT.defang);
    return [['Dominios', d(r.iocs.domains)], ['IPs', d(r.iocs.ips)], ['URLs', d(r.iocs.urls)],
            ['Hashes', r.iocs.hashes], ['Direcciones', d(r.iocs.emails)]];
  }

  function renderIocs(r) {
    const bloques = bloquesIoc(r);
    $('#p-iocs').innerHTML = bloques.map(([t, arr]) =>
      '<div class="card"><h3>' + t + ' <span class="muted">(' + arr.length + ')</span></h3>' +
      '<pre class="block">' + esc(arr.join('\n') || '-') + '</pre></div>').join('') +
      '<div class="toolbar"><button id="copyAll">Copiar todo</button></div>';
    $('#copyAll').onclick = e =>
      copy(bloques.map(([t, arr]) => '# ' + t.toLowerCase() + '\n' + arr.join('\n')).join('\n\n'), e.target);
  }

  function renderJson(r) {
    $('#p-json').innerHTML = '<div class="toolbar" style="margin:0 0 12px"><button id="copyJson">Copiar JSON</button></div>' +
      '<pre class="block">' + esc(JSON.stringify(r, null, 2)) + '</pre>';
    $('#copyJson').onclick = e => copy(JSON.stringify(r, null, 2), e.target);
  }

  const drop = $('#drop');
  drop.onclick = () => $('#file').click();
  $('#file').onchange = e => handleFiles(Array.from(e.target.files));
  ['dragenter', 'dragover'].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.add('hover'); }));
  ['dragleave', 'drop'].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.remove('hover'); }));
  drop.addEventListener('drop', e => { if (e.dataTransfer.files.length) handleFiles(Array.from(e.dataTransfer.files)); });

  document.addEventListener('paste', async e => {
    const txt = (e.clipboardData || window.clipboardData).getData('text');
    if (!txt || txt.length < 40 || !/^[\w-]+\s*:/m.test(txt)) return;
    try {
      const report = await PT.analyze(txt, { filename: 'portapapeles.eml' });
      batch = [{ name: 'portapapeles.eml', report }];
      renderBatchList();
      show(report);
    } catch (err) {
      alert(err.formatoNoSoportado ? err.message : 'No se ha podido analizar el texto pegado: ' + err.message);
    }
  });

  $('#btnReset').onclick = () => {
    batch = [];
    $('#result').hidden = true; $('#multi').hidden = true; $('#file').value = '';
    $('#btnReset').disabled = true;
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  $('#tabs').onclick = e => {
    const b = e.target.closest('button');
    if (!b) return;
    $$('#tabs button').forEach(x => x.classList.toggle('active', x === b));
    $$('.panel').forEach(p => p.classList.toggle('active', p.dataset.p === b.dataset.p));
  };

  function setAdvanced(on) {
    $('#advanced').hidden = !on;
    $('#btnAdv').setAttribute('aria-expanded', on ? 'true' : 'false');
    $('#btnAdvTxt').textContent = on ? 'Ocultar el análisis detallado' : 'Ver el análisis detallado';
    try { localStorage.setItem('phishtriage.avanzado', on ? '1' : '0'); } catch (e) {}
  }

  $('#btnAdv').onclick = () => setAdvanced($('#advanced').hidden);

  let avanzadoGuardado = false;
  try { avanzadoGuardado = localStorage.getItem('phishtriage.avanzado') === '1'; } catch (e) {}
  setAdvanced(avanzadoGuardado);

  if (!window.isSecureContext) {
    $('#offlineBadge').textContent = 'Ábrelo por https: faltan algunos datos del análisis';
    $('#offlineBadge').style.color = 'var(--med)';
  }
})();

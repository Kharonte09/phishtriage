/* PhishTriage - interfaz: pinta lo que devuelve parser.js y gestiona los clics. */
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
        alert(e.formatoNoSoportado ? e.message : 'No se pudo analizar ' + f.name + ': ' + e.message);
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
    ['#btnReset'].forEach(s => $(s).disabled = false);

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

  const EN_CRISTIANO = {
    'url-tld': 'Los enlaces llevan a webs del tipo que usan casi siempre las estafas.',
    'replyto-freemail': 'Si respondes, tu respuesta se va a otra cuenta distinta.',
    'from-freemail-cargo': 'Dice ser un jefe de una empresa, pero escribe desde un Gmail o parecido.',
    'body-iban': 'Te da un número de cuenta para que ingreses el dinero ahí.',
    'body-nocontacto': 'Te pide que no llames ni se lo cuentes a nadie, para que nadie pueda desmentirlo.',
    'combo-bec': 'Se hace pasar por alguien de confianza para que pagues algo.',
    'combo-credenciales': 'Es una página falsa montada para robarte la contraseña.',
    'combo-malware': 'Trae un archivo peligroso y te mete prisa para que lo abras.',
    'combo-extorsion': 'Te amenaza y te pide dinero en criptomonedas.',
    'dmarc-fail': 'El correo no viene de donde dice venir.',
    'spf-fail': 'Lo ha enviado un servidor que no es el de esa empresa.',
    'dkim-fail': 'La firma del correo no cuadra: lo han manipulado o es falso.',
    'from-punycode': 'La dirección usa letras raras que imitan a otra conocida.',
    'from-tld': 'Escribe desde un tipo de web muy barata, típica de estafas.',
    'subj-urgency': 'El asunto mete prisa o amenaza. Es el truco más viejo que hay.',
    'body-password': 'Te pide la contraseña dentro del propio correo. Ningún banco hace eso.',
    'body-refresh': 'Intenta llevarte solo a otra página en cuanto lo abres.',
    'body-hidden': 'Lleva texto invisible para colarse en el filtro de spam.',
    'body-image': 'Es casi todo una imagen, para que los filtros no puedan leerlo.',
    'body-bec': 'Pide cambiar datos del banco o hacer un pago.',
    'mime-profundo': 'El correo esconde sus partes unas dentro de otras muchas veces seguidas. Eso se hace para que los análisis no lleguen al fondo.',
    'dn-suplanta-propio': 'Se hace pasar por tu propia empresa o tu proveedor de correo, pero escribe desde fuera. Tu informático no te escribe desde otro dominio.',
    'from-basura': 'La dirección de quien escribe es un dominio inventado a máquina, del tipo que se registra a miles para una estafa y se tira.',
    'body-buzon': 'Te dice que tu buzón se llena, que tu contraseña caduca o que tienes correo retenido. Es la excusa más usada del mundo para que escribas tu contraseña.',
    'url-hosting-gratis': 'El enlace lleva a una página montada en alojamiento gratuito, no a la web de la empresa que dice ser.',
    'subj-premio': 'Te anuncia un premio, un sorteo o un bono que tú no has pedido. Nadie regala nada por correo.',
    'att-senuelo': 'Casi todo el mensaje está en el adjunto y no hay ni un enlace. Es la forma de que abras el fichero sin pensarlo.',
    'dn-oficial-freemail': 'Firma como un departamento oficial o una marca, pero escribe desde un Gmail o parecido. Una empresa de verdad no hace eso.',
    'body-crypto': 'Habla de criptomonedas. Típico de estafas de inversión o de chantaje.',
    'body-callback': 'Te da un teléfono para cancelar un cobro que tú no has hecho. Si llamas, te sacan los datos por voz.',
    'xmailer': 'Se ha mandado con una herramienta de envíos masivos, no desde un correo normal.',
    'url-mismatch': 'Un enlace enseña una dirección pero lleva a otra distinta.',
    'url-ip': 'Un enlace lleva a un número en vez de a una web con nombre.',
    'url-punycode': 'Un enlace usa letras raras que imitan a una web conocida.',
    'url-shortener': 'Hay enlaces acortados que esconden a dónde llevan de verdad.',
    'url-userinfo': 'Un enlace está montado para aparentar un destino que no es el real.',
    'att-exec': 'Trae un programa. Abrirlo instalaría algo en tu ordenador.',
    'att-macro': 'Trae un Word o un Excel con macros, que pueden ejecutar programas.',
    'att-html': 'Trae una página web como archivo. Truco habitual para robar contraseñas.',
    'att-double': 'Un archivo tiene doble extensión para parecer un PDF o una foto.',
    'att-mismatch': 'Un archivo dice ser una cosa y por dentro es otra.',
    'att-rtlo': 'El nombre de un archivo usa un truco para verse del revés.',
    'dn-mixed-script': 'El nombre de quien escribe mezcla letras de otro alfabeto que se ven igual que las nuestras.',
    'from-malformed': 'La dirección de quien escribe está trucada para que tu programa de correo enseñe una cosa y el filtro lea otra.',
    'from-lookalike': 'Escribe desde una web que imita el nombre de una conocida, con alguna letra cambiada.',
    'dmarc-none': 'El dominio desde el que escriben no ha configurado la protección que evita que le suplanten.',
    'spf-softfail': 'El servidor que lo ha enviado no es del todo el que debería.',
    'spf-neutral': 'El dominio desde el que escriben no dice quién puede enviar en su nombre.',
    'compauth': 'Los filtros de Microsoft no han podido confirmar que sea auténtico.',
    'from-multi': 'El correo lleva varios remitentes a la vez. Es una forma de despistar a los filtros.',
    'url-zerowidth': 'Un enlace lleva letras invisibles metidas dentro para disimular a dónde va.',
    'url-rtlo': 'Un enlace usa un truco para que la dirección se lea al revés de como es.',
    'url-data': 'Un enlace lleva una página entera metida dentro del propio correo.',
    'url-multi-at': 'Un enlace enseña una dirección conocida al principio, pero el destino real es otro.',
    'url-subdomains': 'Un enlace encadena tantos nombres que el de verdad queda escondido al final.',
    'att-archive-nested': 'Trae un comprimido con otro dentro. Se hace para que el antivirus no pueda mirar.',
    'att-encrypted': 'Trae un archivo con contraseña. Así ningún antivirus puede ver lo que lleva.',
    'att-ole': 'Un archivo tiene por dentro un formato antiguo de Office que no le corresponde.',
    'body-empty': 'No dice nada: solo trae el archivo adjunto.',
    'rcv-none': 'No se ve por dónde ha pasado. O lo han metido a mano o le han borrado el rastro.',
    'date-missing': 'El correo no lleva fecha.',
    'date-skew': 'La fecha que dice el correo no cuadra con la de los servidores por los que pasó.',
  };

  const CONSEJOS = {
    CRITICO: ['No pulses ningún enlace ni abras los archivos que trae.',
      'No respondas, y no llames a los teléfonos que aparezcan en el correo.',
      'Si ya has escrito tu contraseña en algún sitio, cámbiala ahora. Abre tú la web oficial escribiendo la dirección a mano, no desde aquí.',
      'Si dice ser tu banco, llama al número que hay detrás de tu tarjeta. Nunca al que venga en el correo.',
      'Cuando hayas hecho lo anterior, bórralo.'],
    ALTO: ['No pulses ningún enlace ni abras los archivos que trae.',
      'No respondas ni llames a los teléfonos que aparezcan.',
      'Compruébalo por otro camino: abre tú la web oficial escribiendo la dirección a mano, o llama al teléfono de siempre.'],
    MEDIO: ['De momento no pulses enlaces ni abras archivos.',
      'Pregunta a quien dice enviarlo, pero por otro medio: llámale o escríbele a la dirección que ya tenías.',
      'Si te pide dinero, datos o una contraseña, dalo por estafa hasta que alguien te confirme lo contrario.'],
    BAJO: ['No he visto señales claras de estafa, pero esto no es un certificado.',
      'Si te pide dinero, contraseñas o datos personales, compruébalo igual por otro camino.',
      'Ante la duda, no pulses el enlace: abre tú la web escribiendo la dirección a mano.']
  };

  const TITULARES = {
    CRITICO: ['Casi seguro que es una estafa', 'No toques nada de este correo.'],
    ALTO: ['Trátalo como una estafa', 'Tiene varias señales claras de engaño.'],
    MEDIO: ['Desconfía de este correo', 'Hay cosas que no cuadran.'],
    BAJO: ['No he visto señales de estafa', 'Aun así, comprueba antes de fiarte de lo que te pida.']
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
                             : '<span class="muted">no pone ningún nombre</span>') + '</div>' +
      '<div><span class="et">Escribe desde</span><code>' + direccionCorta(r.summary.from) + '</code></div>' +
      (relay ? '<div class="small" style="margin-left:108px">Es ' + relay + ': la dirección de verdad está oculta.</div>' : '') +
      '<div><span class="et">Asunto</span>' + esc(r.summary.subject || '(sin asunto)') + '</div>';
  }

  function renderSimple(r) {
    const vistos = [];
    for (const f of r.findings.slice().sort((a, b) => (b.points || 0) - (a.points || 0))) {
      if (!(f.points > 0)) continue;
      const txt = EN_CRISTIANO[f.id];
      if (txt && vistos.indexOf(txt) < 0) vistos.push(txt);
    }
    const razones = vistos.slice(0, 5);
    const calma = r.verdict === 'BAJO';

    $('#p-simple').innerHTML =
      (razones.length
        ? '<div class="card' + (calma ? ' calma' : '') + '"><h3>' +
          (calma ? 'Lo único que he visto' : 'Por qué te lo digo') + '</h3>' +
          razones.map(t => '<div class="motivo"><span class="punto">&#9679;</span><span>' + esc(t) + '</span></div>').join('') +
          '</div>'
        : '') +

      '<div class="card"><h3>Qué hacer ahora</h3><ol class="consejos">' +
      CONSEJOS[r.verdict].map(c => '<li>' + esc(c) + '</li>').join('') +
      '</ol></div>' +

      '<div class="aviso-017"><b>¿Necesitas que te lo confirme alguien?</b><br>' +
      'INCIBE atiende dudas por tel&eacute;fono en el <b>017</b>, gratis y sin dar tus datos. ' +
      'Si ya has perdido dinero, denúncialo en la Policía o la Guardia Civil.</div>';
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
        top.map(f => '<div class="finding"><span class="sev sev-high">ALTO</span><span>' + esc(f.msg) + '</span></div>').join('') +
        '</div>' : '') +
      comprobarCard(r) +
      '<div class="card"><h3>Estructura MIME</h3><div class="tree">' + tree(r.structure, '') + '</div></div>';
  }

  function comprobarCard(r) {
    const lista = comprobaciones(r);
    if (!lista.length) return '';
    return '<div class="card"><h3>Comprobar en servicios públicos <span class="muted">(sin registrarte)</span></h3>' +
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
    const desglose = '<div class="card"><h3>Cómo se reparte la nota ' +
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
      '<div class="finding"><span class="sev sev-' + f.sev + '">' + SEVLABEL[f.sev] + '</span>' +
      '<span>' + esc(f.msg) + (f.fuente ? '<br><span class="muted small">peso ' + f.points + ' &middot; ' + esc(f.fuente) + '</span>' : '') + '</span>' +
      (f.points ? '<span class="pts">' + (f.points > 0 ? '+' : '') + f.points + '</span>' : '') + '</div>'
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
      '<div class="card"><h3>Cabeceras en bruto</h3><pre class="block">' + esc(a.raw.join('\n\n') || 'Sin Authentication-Results.') + '</pre></div>';
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
        u.flags.map(f => '<div class="finding"><span class="sev sev-' + f.sev + '">' + SEVLABEL[f.sev] + '</span><span>' + esc(f.msg) + '</span></div>').join('') +
        '</div>';

    const enlaces = agrupar(r.urls.filter(u => u.tipo === 'enlace')).sort((a, b) => b.flags.length - a.flags.length);
    const recursos = agrupar(r.urls.filter(u => u.tipo === 'recurso')).sort((a, b) => b.flags.length - a.flags.length);

    $('#p-urls').innerHTML =
      '<div class="toolbar" style="margin:0 0 12px"><button id="copyUrls">Copiar todo defanged</button></div>' +
      '<div class="card"><h3>Enlaces en los que se puede pinchar ' +
      '<span class="muted">(' + enlaces.length + ' destinos distintos)</span></h3></div>' +
      enlaces.map(pinta).join('') +
      (recursos.length
        ? '<details class="card"><summary style="cursor:pointer">Recursos que carga el correo solo: ' +
          'imágenes, iconos y fuentes <span class="muted">(' + recursos.length + ' destinos)</span></summary>' +
          '</details>' + recursos.map(pinta).join('')
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
        ' &middot; <a target="_blank" rel="noopener noreferrer" href="https://www.virustotal.com/gui/file/' + esc(a.sha256) + '">VT</a></div>' : '') +
      a.flags.map(f => '<div class="finding"><span class="sev sev-' + f.sev + '">' + SEVLABEL[f.sev] + '</span><span>' + esc(f.msg) + '</span></div>').join('') +
      '</div>').join('') +
      '<p class="small">El contenido del adjunto no sale de aquí: si pulsas el enlace de VirusTotal solo viaja el hash.</p>';
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
    batch = [];
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

  function setAdvanced(on) {
    $('#advanced').hidden = !on;
    $('#btnAdv').setAttribute('aria-expanded', on ? 'true' : 'false');
    $('#btnAdvTxt').textContent = on ? 'Ocultar el análisis completo' : 'Ver el análisis completo';
    try { localStorage.setItem('phishtriage.avanzado', on ? '1' : '0'); } catch (e) {}
  }

  $('#btnAdv').onclick = () => setAdvanced($('#advanced').hidden);

  let avanzadoGuardado = false;
  try { avanzadoGuardado = localStorage.getItem('phishtriage.avanzado') === '1'; } catch (e) {}
  setAdvanced(avanzadoGuardado);

  if (!window.isSecureContext) {
    $('#offlineBadge').textContent = 'Ábrelo por https: faltan algunos datos';
    $('#offlineBadge').style.color = 'var(--med)';
  }
})();

/*!
 * PhishTriage - motor de análisis de .eml 100% client-side
 * Sin dependencias. Funciona en navegador y en Node (para los tests).
 * Licencia MIT.
 */
(function (root, factory) {
  const mod = factory();
  if (typeof module === 'object' && module.exports) module.exports = mod;
  root.PhishTriage = mod;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  // ---------------------------------------------------------------------------
  // Utilidades de bytes / codificaciones
  // ---------------------------------------------------------------------------

  function bytesToLatin1(bytes) {
    let out = '';
    const CH = 0x8000;
    for (let i = 0; i < bytes.length; i += CH) {
      out += String.fromCharCode.apply(null, bytes.subarray(i, i + CH));
    }
    return out;
  }

  function latin1ToBytes(str) {
    const out = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) out[i] = str.charCodeAt(i) & 0xff;
    return out;
  }

  function b64ToBytes(str) {
    const clean = String(str).replace(/[^A-Za-z0-9+/=]/g, '');
    let bin = '';
    if (typeof atob === 'function') {
      try { bin = atob(clean.replace(/=+$/, '') + '='.repeat((4 - (clean.replace(/=+$/, '').length % 4)) % 4)); }
      catch (e) { bin = ''; }
    } else if (typeof Buffer !== 'undefined') {
      return new Uint8Array(Buffer.from(clean, 'base64'));
    }
    return latin1ToBytes(bin);
  }

  function decodeQP(str, isHeaderWord) {
    let s = String(str);
    if (isHeaderWord) s = s.replace(/_/g, ' ');
    else s = s.replace(/=\r?\n/g, '');
    return s.replace(/=([0-9A-Fa-f]{2})/g, (m, h) => String.fromCharCode(parseInt(h, 16)));
  }

  const CHARSET_ALIAS = {
    'utf8': 'utf-8', 'utf-8': 'utf-8', 'us-ascii': 'windows-1252', 'ascii': 'windows-1252',
    'iso-8859-1': 'windows-1252', 'latin1': 'windows-1252', 'cp1252': 'windows-1252',
    'windows-1252': 'windows-1252', 'iso-8859-15': 'iso-8859-15', 'koi8-r': 'koi8-r',
    'windows-1251': 'windows-1251', 'gb2312': 'gbk', 'gbk': 'gbk', 'big5': 'big5',
    'shift_jis': 'shift_jis', 'euc-kr': 'euc-kr', 'utf-16': 'utf-16le', 'utf-16le': 'utf-16le'
  };

  function decodeBytes(bytes, charset) {
    const cs = CHARSET_ALIAS[String(charset || 'utf-8').toLowerCase().trim()] || 'utf-8';
    try {
      if (typeof TextDecoder === 'function') return new TextDecoder(cs, { fatal: false }).decode(bytes);
    } catch (e) { /* charset no soportado */ }
    try { if (typeof TextDecoder === 'function') return new TextDecoder('utf-8').decode(bytes); } catch (e) {}
    return bytesToLatin1(bytes);
  }

  // RFC 2047: =?charset?B|Q?texto?=
  function decodeRFC2047(input) {
    if (!input) return '';
    let s = String(input);
    // Palabras codificadas consecutivas separadas solo por espacios se concatenan
    s = s.replace(/(=\?[^?]+\?[BbQq]\?[^?]*\?=)\s+(?==\?)/g, '$1');
    return s.replace(/=\?([^?]+)\?([BbQq])\?([^?]*)\?=/g, (m, cs, enc, txt) => {
      try {
        const bytes = enc.toUpperCase() === 'B' ? b64ToBytes(txt) : latin1ToBytes(decodeQP(txt, true));
        return decodeBytes(bytes, cs);
      } catch (e) { return m; }
    });
  }

  // ---------------------------------------------------------------------------
  // MD5 puro JS (WebCrypto no lo soporta, pero los analistas lo piden)
  // ---------------------------------------------------------------------------
  function md5(bytes) {
    function add32(a, b) { return (a + b) & 0xffffffff; }
    function cmn(q, a, b, x, s, t) {
      a = add32(add32(a, q), add32(x, t));
      return add32((a << s) | (a >>> (32 - s)), b);
    }
    function ff(a, b, c, d, x, s, t) { return cmn((b & c) | (~b & d), a, b, x, s, t); }
    function gg(a, b, c, d, x, s, t) { return cmn((b & d) | (c & ~d), a, b, x, s, t); }
    function hh(a, b, c, d, x, s, t) { return cmn(b ^ c ^ d, a, b, x, s, t); }
    function ii(a, b, c, d, x, s, t) { return cmn(c ^ (b | ~d), a, b, x, s, t); }

    const n = bytes.length;
    const words = [];
    for (let i = 0; i < n; i++) words[i >> 2] = (words[i >> 2] || 0) | (bytes[i] << ((i % 4) << 3));
    words[n >> 2] = (words[n >> 2] || 0) | (0x80 << ((n % 4) << 3));
    const len = (((n + 8) >> 6) + 1) * 16;
    for (let i = (n >> 2) + 1; i < len; i++) words[i] = 0;
    words[len - 2] = n * 8;

    let a = 1732584193, b = -271733879, c = -1732584194, d = 271733878;
    for (let i = 0; i < len; i += 16) {
      const x = words.slice(i, i + 16).map(v => v | 0);
      const oa = a, ob = b, oc = c, od = d;
      a = ff(a, b, c, d, x[0], 7, -680876936); d = ff(d, a, b, c, x[1], 12, -389564586);
      c = ff(c, d, a, b, x[2], 17, 606105819); b = ff(b, c, d, a, x[3], 22, -1044525330);
      a = ff(a, b, c, d, x[4], 7, -176418897); d = ff(d, a, b, c, x[5], 12, 1200080426);
      c = ff(c, d, a, b, x[6], 17, -1473231341); b = ff(b, c, d, a, x[7], 22, -45705983);
      a = ff(a, b, c, d, x[8], 7, 1770035416); d = ff(d, a, b, c, x[9], 12, -1958414417);
      c = ff(c, d, a, b, x[10], 17, -42063); b = ff(b, c, d, a, x[11], 22, -1990404162);
      a = ff(a, b, c, d, x[12], 7, 1804603682); d = ff(d, a, b, c, x[13], 12, -40341101);
      c = ff(c, d, a, b, x[14], 17, -1502002290); b = ff(b, c, d, a, x[15], 22, 1236535329);
      a = gg(a, b, c, d, x[1], 5, -165796510); d = gg(d, a, b, c, x[6], 9, -1069501632);
      c = gg(c, d, a, b, x[11], 14, 643717713); b = gg(b, c, d, a, x[0], 20, -373897302);
      a = gg(a, b, c, d, x[5], 5, -701558691); d = gg(d, a, b, c, x[10], 9, 38016083);
      c = gg(c, d, a, b, x[15], 14, -660478335); b = gg(b, c, d, a, x[4], 20, -405537848);
      a = gg(a, b, c, d, x[9], 5, 568446438); d = gg(d, a, b, c, x[14], 9, -1019803690);
      c = gg(c, d, a, b, x[3], 14, -187363961); b = gg(b, c, d, a, x[8], 20, 1163531501);
      a = gg(a, b, c, d, x[13], 5, -1444681467); d = gg(d, a, b, c, x[2], 9, -51403784);
      c = gg(c, d, a, b, x[7], 14, 1735328473); b = gg(b, c, d, a, x[12], 20, -1926607734);
      a = hh(a, b, c, d, x[5], 4, -378558); d = hh(d, a, b, c, x[8], 11, -2022574463);
      c = hh(c, d, a, b, x[11], 16, 1839030562); b = hh(b, c, d, a, x[14], 23, -35309556);
      a = hh(a, b, c, d, x[1], 4, -1530992060); d = hh(d, a, b, c, x[4], 11, 1272893353);
      c = hh(c, d, a, b, x[7], 16, -155497632); b = hh(b, c, d, a, x[10], 23, -1094730640);
      a = hh(a, b, c, d, x[13], 4, 681279174); d = hh(d, a, b, c, x[0], 11, -358537222);
      c = hh(c, d, a, b, x[3], 16, -722521979); b = hh(b, c, d, a, x[6], 23, 76029189);
      a = hh(a, b, c, d, x[9], 4, -640364487); d = hh(d, a, b, c, x[12], 11, -421815835);
      c = hh(c, d, a, b, x[15], 16, 530742520); b = hh(b, c, d, a, x[2], 23, -995338651);
      a = ii(a, b, c, d, x[0], 6, -198630844); d = ii(d, a, b, c, x[7], 10, 1126891415);
      c = ii(c, d, a, b, x[14], 15, -1416354905); b = ii(b, c, d, a, x[5], 21, -57434055);
      a = ii(a, b, c, d, x[12], 6, 1700485571); d = ii(d, a, b, c, x[3], 10, -1894986606);
      c = ii(c, d, a, b, x[10], 15, -1051523); b = ii(b, c, d, a, x[1], 21, -2054922799);
      a = ii(a, b, c, d, x[8], 6, 1873313359); d = ii(d, a, b, c, x[15], 10, -30611744);
      c = ii(c, d, a, b, x[6], 15, -1560198380); b = ii(b, c, d, a, x[13], 21, 1309151649);
      a = ii(a, b, c, d, x[4], 6, -145523070); d = ii(d, a, b, c, x[11], 10, -1120210379);
      c = ii(c, d, a, b, x[2], 15, 718787259); b = ii(b, c, d, a, x[9], 21, -343485551);
      a = add32(a, oa); b = add32(b, ob); c = add32(c, oc); d = add32(d, od);
    }
    return [a, b, c, d].map(v => {
      let s = '';
      for (let i = 0; i < 4; i++) s += ('0' + ((v >>> (i * 8)) & 0xff).toString(16)).slice(-2);
      return s;
    }).join('');
  }

  function toHex(buf) {
    return Array.from(new Uint8Array(buf)).map(b => ('0' + b.toString(16)).slice(-2)).join('');
  }

  async function hashBytes(bytes) {
    const out = { md5: md5(bytes), sha1: null, sha256: null };
    const subtle = (typeof crypto !== 'undefined' && crypto.subtle) ? crypto.subtle : null;
    if (subtle) {
      try {
        const view = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
        out.sha1 = toHex(await subtle.digest('SHA-1', view));
        out.sha256 = toHex(await subtle.digest('SHA-256', view));
      } catch (e) { /* contexto no seguro */ }
    }
    return out;
  }

  // ---------------------------------------------------------------------------
  // Dominios
  // ---------------------------------------------------------------------------

  // PSL reducida: sufijos de dos niveles mas habituales.
  const MULTI_SUFFIX = new Set([
    'co.uk', 'org.uk', 'me.uk', 'gov.uk', 'ac.uk', 'net.uk', 'sch.uk',
    'com.es', 'org.es', 'gob.es', 'edu.es', 'nom.es',
    'com.ar', 'com.br', 'com.mx', 'com.co', 'com.pe', 'com.cl', 'com.ve', 'com.uy',
    'com.au', 'net.au', 'org.au', 'gov.au', 'edu.au',
    'co.jp', 'or.jp', 'ne.jp', 'ac.jp', 'go.jp',
    'co.kr', 'or.kr', 'co.in', 'net.in', 'org.in', 'gov.in',
    'co.za', 'org.za', 'com.tr', 'gov.tr', 'com.cn', 'net.cn', 'org.cn', 'gov.cn',
    'com.tw', 'com.hk', 'com.sg', 'com.my', 'co.nz', 'com.pt', 'com.pl', 'com.ua',
    'com.ru', 'org.ru', 'net.ru', 'co.il', 'com.sa', 'com.eg', 'com.ng'
  ]);

  function orgDomain(host) {
    if (!host) return '';
    let h = String(host).toLowerCase().replace(/\.$/, '').replace(/^\[|\]$/g, '');
    if (isIP(h)) return h;
    const parts = h.split('.').filter(Boolean);
    if (parts.length <= 2) return parts.join('.');
    const last2 = parts.slice(-2).join('.');
    if (MULTI_SUFFIX.has(last2)) return parts.slice(-3).join('.');
    return last2;
  }

  const RE_IPV4 = /\b((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})\b/;
  // {3,7} grupos evita confundir marcas de tiempo hh:mm:ss con IPv6
  const RE_IPV6 = /\b(?:[0-9A-Fa-f]{1,4}:){3,7}[0-9A-Fa-f]{1,4}\b|\b(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}\b/;

  function isIP(s) { return new RegExp('^(?:' + RE_IPV4.source.replace(/\\b/g, '') + '|' + RE_IPV6.source.replace(/\\b/g, '') + ')$').test(String(s)); }

  function isPrivateIP(ip) {
    if (!ip) return false;
    if (ip.indexOf(':') >= 0) return /^(::1$|fe80:|fc|fd)/i.test(ip);
    const p = ip.split('.').map(Number);
    if (p.length !== 4) return false;
    return p[0] === 10 || p[0] === 127 || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
      (p[0] === 192 && p[1] === 168) || (p[0] === 169 && p[1] === 254) || p[0] === 0;
  }

  // Homoglifos de verdad. Lo que delata un ataque IDN no es que haya letras
  // no ASCII -medio mundo se llama Michał o Tomáš-, es que dentro de UNA MISMA
  // palabra se mezclen alfabetos: la "а" cirilica colada en "pаypal".
  // Rspamd puntua esto (R_MIXED_CHARSET) mas alto que cualquier fallo de SPF.
  const SCRIPTS = [
    ['cirílico', /[\u0400-\u04FF\u0500-\u052F]/],
    ['griego',   /[\u0370-\u03FF\u1F00-\u1FFF]/],
    ['armenio',  /[\u0530-\u058F]/],
    ['latino',   /[A-Za-z\u00C0-\u024F]/]
  ];

  // Normaliza los cambios de letra habituales del typosquatting antes de
  // comparar: 0 por o, 1 por l, rn por m, vv por w.
  function normalizaLeet(s) {
    return String(s || '').toLowerCase()
      .replace(/rn/g, 'm').replace(/vv/g, 'w')
      .replace(/0/g, 'o').replace(/1/g, 'l').replace(/3/g, 'e')
      .replace(/4/g, 'a').replace(/5/g, 's').replace(/7/g, 't')
      .replace(/[^a-z]/g, '');
  }

  // Distancia de edicion, cortando en cuanto pasa del maximo que nos interesa.
  function distancia(a, b, max) {
    if (Math.abs(a.length - b.length) > max) return max + 1;
    let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
    for (let i = 1; i <= a.length; i++) {
      const fila = [i];
      let mejor = i;
      for (let j = 1; j <= b.length; j++) {
        fila[j] = Math.min(prev[j] + 1, fila[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
        if (fila[j] < mejor) mejor = fila[j];
      }
      if (mejor > max) return max + 1;
      prev = fila;
    }
    return prev[b.length];
  }

  // ¿El dominio imita a una marca conocida sin ser suyo? "paypa1-secure.com"
  // no lleva la marca dentro como subcadena, asi que la regla de tokens de las
  // URLs no lo ve.
  function dominioParecido(orgDomain) {
    if (!orgDomain) return null;
    const etiqueta = String(orgDomain).split('.')[0];
    if (!etiqueta || etiqueta.length < 4) return null;
    const norm = normalizaLeet(etiqueta);
    // Sin sustituir letras: si YA es la marca tal cual, es la marca de verdad.
    // Si solo lo es despues de deshacer los cambios (arnazon -> amazon), es
    // justo lo contrario: un typosquat.
    const crudo = String(etiqueta).toLowerCase().replace(/[^a-z]/g, );
    if (!norm) return null;
    for (const marca of BRANDS) {
      if (marca.length < 4) continue;
      if (crudo === marca) return null;            // es la marca de verdad
      if (norm === marca) return marca;            // lo es solo tras deshacer los cambios
      // La marca aparece pegada a otras letras: "paypal-secure", "micros0ft-security"
      if (norm.length > marca.length && norm.indexOf(marca) >= 0) return marca;
      // O es la marca con una o dos letras cambiadas
      const d = distancia(norm, marca, 2);
      if (d > 0 && d <= (marca.length >= 8 ? 2 : 1)) return marca;
    }
    return null;
  }

  function scriptMixto(texto) {
    for (const palabra of String(texto || '').split(/[\s@._\-<>()"',;:]+/)) {
      if (palabra.length < 2) continue;
      const vistos = SCRIPTS.filter(([, re]) => re.test(palabra));
      if (vistos.length > 1) return palabra;
    }
    return null;
  }

  function defang(s) {
    if (!s) return '';
    return String(s)
      .replace(/^https?:\/\//i, m => m.toLowerCase().replace('http', 'hxxp'))
      .replace(/\bhttps?:\/\//gi, m => m.toLowerCase().replace('http', 'hxxp'))
      .replace(/\./g, '[.]')
      .replace(/@/g, '[@]');
  }

  // ---------------------------------------------------------------------------
  // Cabeceras y MIME
  // ---------------------------------------------------------------------------

  function splitHeadersBody(raw) {
    const idx = raw.search(/\r?\n\r?\n/);
    if (idx < 0) return [raw, ''];
    const m = raw.slice(idx).match(/^\r?\n\r?\n/);
    return [raw.slice(0, idx), raw.slice(idx + m[0].length)];
  }

  function parseHeaderBlock(block) {
    const lines = block.split(/\r?\n/);
    const out = [];
    let cur = null;
    for (const line of lines) {
      if (/^[ \t]/.test(line) && cur) { cur[1] += ' ' + line.replace(/^[ \t]+/, ''); continue; }
      const m = line.match(/^([!-9;-~]+)[ \t]*:([\s\S]*)$/);
      if (m) { cur = [m[1], m[2].replace(/^[ \t]+/, '')]; out.push(cur); }
      else if (line.trim() && cur) { cur[1] += ' ' + line.trim(); }
    }
    return out;
  }

  function headerGet(headers, name) {
    const n = name.toLowerCase();
    for (const [k, v] of headers) if (k.toLowerCase() === n) return v;
    return null;
  }

  function headerAll(headers, name) {
    const n = name.toLowerCase();
    return headers.filter(([k]) => k.toLowerCase() === n).map(([, v]) => v);
  }

  function parseParams(value) {
    const out = { value: '', params: {} };
    if (!value) return out;
    const parts = [];
    let buf = '', inQ = false;
    for (const ch of value) {
      if (ch === '"') { inQ = !inQ; buf += ch; continue; }
      if (ch === ';' && !inQ) { parts.push(buf); buf = ''; continue; }
      buf += ch;
    }
    parts.push(buf);
    out.value = (parts.shift() || '').trim().toLowerCase();
    const cont = {};
    for (const p of parts) {
      const m = p.match(/^\s*([^=]+?)\s*=\s*([\s\S]*)$/);
      if (!m) continue;
      let key = m[1].trim().toLowerCase();
      let val = m[2].trim().replace(/^"|"$/g, '');
      // RFC 2231: name*0*, name*1*, name*
      const cm = key.match(/^([^*]+)\*(\d+)?\*?$/);
      if (cm) {
        cont[cm[1]] = cont[cm[1]] || [];
        cont[cm[1]].push([cm[2] ? parseInt(cm[2], 10) : 0, val]);
        continue;
      }
      out.params[key] = decodeRFC2047(val);
    }
    for (const k of Object.keys(cont)) {
      let joined = cont[k].sort((a, b) => a[0] - b[0]).map(x => x[1]).join('');
      const em = joined.match(/^([^']*)'([^']*)'([\s\S]*)$/);
      if (em) joined = decodeBytes(latin1ToBytes(decodeURIComponent_safe(em[3])), em[1] || 'utf-8');
      else joined = decodeRFC2047(joined);
      out.params[k] = joined;
    }
    return out;
  }

  function decodeURIComponent_safe(s) {
    try { return decodeURIComponent(s); } catch (e) { return s.replace(/%([0-9A-Fa-f]{2})/g, (m, h) => String.fromCharCode(parseInt(h, 16))); }
  }

  function parseNode(raw, depth) {
    depth = depth || 0;
    const [hBlock, body] = splitHeadersBody(raw);
    const headers = parseHeaderBlock(hBlock);
    const ct = parseParams(headerGet(headers, 'content-type') || 'text/plain');
    const cd = parseParams(headerGet(headers, 'content-disposition') || '');
    const enc = (headerGet(headers, 'content-transfer-encoding') || '7bit').trim().toLowerCase();
    const node = {
      headers, rawHeaders: hBlock, mime: ct.value || 'text/plain', params: ct.params,
      disposition: cd.value || '', dispParams: cd.params, encoding: enc,
      body, children: [], depth
    };
    if (depth > 12) return node;
    if (node.mime.startsWith('multipart/') && ct.params.boundary) {
      const b = ct.params.boundary;
      const chunks = splitOnBoundary(body, b);
      node.children = chunks.map(c => parseNode(c, depth + 1));
    } else if (node.mime === 'message/rfc822') {
      node.children = [parseNode(body, depth + 1)];
    }
    return node;
  }

  function splitOnBoundary(body, boundary) {
    const marker = '--' + boundary;
    const lines = body.split(/\r?\n/);
    const chunks = [];
    let cur = null;
    for (const line of lines) {
      const t = line.trimEnd();
      if (t === marker) { if (cur !== null) chunks.push(cur.join('\n')); cur = []; continue; }
      if (t === marker + '--') { if (cur !== null) chunks.push(cur.join('\n')); cur = null; break; }
      if (cur !== null) cur.push(line);
    }
    if (cur !== null) chunks.push(cur.join('\n'));
    return chunks.filter(c => c.trim() !== '');
  }

  function nodeBytes(node) {
    if (node.encoding === 'base64') return b64ToBytes(node.body);
    if (node.encoding === 'quoted-printable') return latin1ToBytes(decodeQP(node.body, false));
    return latin1ToBytes(node.body);
  }

  function nodeText(node) {
    return decodeBytes(nodeBytes(node), node.params.charset || 'utf-8');
  }

  // ---------------------------------------------------------------------------
  // Direcciones
  // ---------------------------------------------------------------------------

  function parseAddressList(value) {
    if (!value) return [];
    const raw = String(value);
    const items = [];
    let buf = '', inQ = false, inC = 0;
    for (const ch of raw) {
      if (ch === '"') inQ = !inQ;
      if (ch === '(' && !inQ) inC++;
      if (ch === ')' && !inQ && inC) inC--;
      if (ch === ',' && !inQ && !inC) { items.push(buf); buf = ''; continue; }
      buf += ch;
    }
    items.push(buf);
    return items.map(s => s.trim()).filter(Boolean).map(s => {
      let name = '', addr = '';
      const m = s.match(/^([\s\S]*?)<([^>]*)>\s*$/);
      if (m) { name = m[1].trim().replace(/^"|"$/g, ''); addr = m[2].trim(); }
      else { addr = s.replace(/[<>]/g, '').trim(); }
      name = decodeRFC2047(name).trim();
      addr = addr.replace(/^mailto:/i, '');
      const at = addr.lastIndexOf('@');
      const domain = at >= 0 ? addr.slice(at + 1).toLowerCase().replace(/[>,;\s]+$/, '') : '';
      return { raw: s.trim(), name, address: addr, domain, orgDomain: orgDomain(domain) };
    });
  }

  // ---------------------------------------------------------------------------
  // Autenticación
  // ---------------------------------------------------------------------------

  function parseAuthResults(headers) {
    const res = {
      spf: null, dkim: null, dmarc: null, compauth: null, arc: null,
      spfDomain: null, dkimDomain: null, dmarcFrom: null, raw: [], dkimSignatures: [], arcChain: 0
    };
    const ar = headerAll(headers, 'authentication-results').concat(headerAll(headers, 'arc-authentication-results'));
    for (const line of ar) {
      res.raw.push(line);
      const low = line.toLowerCase();
      const grab = (k) => { const m = low.match(new RegExp('\\b' + k + '\\s*=\\s*([a-z]+)')); return m ? m[1] : null; };
      res.spf = res.spf || grab('spf');
      res.dkim = res.dkim || grab('dkim');
      res.dmarc = res.dmarc || grab('dmarc');
      res.compauth = res.compauth || grab('compauth');
      res.arc = res.arc || grab('arc');
      let m = low.match(/smtp\.mailfrom\s*=\s*([^\s;,()]+)/); if (m && !res.spfDomain) res.spfDomain = m[1].replace(/^.*@/, '');
      m = low.match(/header\.d\s*=\s*([^\s;,()]+)/); if (m && !res.dkimDomain) res.dkimDomain = m[1];
      m = low.match(/header\.from\s*=\s*([^\s;,()]+)/); if (m && !res.dmarcFrom) res.dmarcFrom = m[1].replace(/^.*@/, '');
    }
    // Received-SPF como respaldo
    if (!res.spf) {
      const rs = headerAll(headers, 'received-spf');
      for (const line of rs) {
        res.raw.push('Received-SPF: ' + line);
        const m = line.trim().match(/^([A-Za-z]+)/);
        if (m) res.spf = m[1].toLowerCase();
        const d = line.match(/(?:envelope-from|smtp\.mailfrom)\s*=\s*([^\s;,()]+)/i);
        if (d && !res.spfDomain) res.spfDomain = d[1].replace(/^.*@/, '').replace(/[<>]/g, '');
      }
    }
    for (const sig of headerAll(headers, 'dkim-signature')) {
      const g = (k) => { const m = sig.match(new RegExp('(?:^|;)\\s*' + k + '\\s*=\\s*([^;]+)')); return m ? m[1].trim().replace(/\s+/g, '') : null; };
      res.dkimSignatures.push({ d: g('d'), s: g('s'), a: g('a'), c: g('c'), bLen: (g('b') || '').length });
    }
    if (!res.dkimDomain && res.dkimSignatures.length) res.dkimDomain = res.dkimSignatures[0].d;
    // "none" no es un dominio
    for (const k of ['spfDomain', 'dkimDomain', 'dmarcFrom']) {
      if (res[k] && /^(none|unknown|-)$/i.test(res[k])) res[k] = null;
    }
    res.arcChain = headerAll(headers, 'arc-seal').length;
    return res;
  }

  // ---------------------------------------------------------------------------
  // Cadena Received
  // ---------------------------------------------------------------------------

  function parseReceived(headers) {
    const raw = headerAll(headers, 'received');
    const hops = raw.map((line, i) => {
      const dateM = line.match(/;\s*([^;]+)$/);
      const date = dateM ? dateM[1].trim().replace(/\s+/g, ' ') : null;
      const ts = date ? Date.parse(date.replace(/\s*\([^)]*\)\s*$/, '')) : NaN;
      const fromM = line.match(/\bfrom\s+([^\s;()]+)/i);
      const byM = line.match(/\bby\s+([^\s;()]+)/i);
      const withM = line.match(/\bwith\s+([A-Za-z0-9._+-]+)/i);
      const idM = line.match(/\bid\s+([^\s;()]+)/i);
      const forM = line.match(/\bfor\s+<?([^\s;<>()]+@[^\s;<>()]+)>?/i);
      const ips = [];
      const reAll = new RegExp(RE_IPV4.source, 'g');
      let m;
      while ((m = reAll.exec(line))) if (ips.indexOf(m[1]) < 0) ips.push(m[1]);
      const m6 = line.match(new RegExp(RE_IPV6.source, 'g'));
      if (m6) for (const x of m6) if (ips.indexOf(x) < 0 && x.indexOf(':') > 0) ips.push(x);
      return {
        index: raw.length - i, raw: line.replace(/\s+/g, ' ').trim(),
        from: fromM ? fromM[1] : null, by: byM ? byM[1] : null,
        with: withM ? withM[1].trim() : null, id: idM ? idM[1] : null,
        for: forM ? forM[1] : null, date, ts: isNaN(ts) ? null : ts,
        ips, publicIPs: ips.filter(ip => !isPrivateIP(ip))
      };
    });
    // Received se apila hacia arriba: el último del array es el primer salto real
    const chrono = hops.slice().reverse();
    for (let i = 0; i < chrono.length; i++) {
      const prev = chrono[i - 1];
      chrono[i].delaySeconds = (prev && prev.ts && chrono[i].ts) ? Math.round((chrono[i].ts - prev.ts) / 1000) : null;
      chrono[i].hop = i + 1;
    }
    return chrono;
  }

  // ---------------------------------------------------------------------------
  // URLs
  // ---------------------------------------------------------------------------

  const SHORTENERS = new Set(['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
    'cutt.ly', 'rb.gy', 'shorturl.at', 'rebrand.ly', 'tiny.cc', 'lnkd.in', 'bl.ink', 't.ly',
    'shorte.st', 'adf.ly', 'v.gd', 'trib.al', 'mcaf.ee', 'urlz.fr', 'x.gd', 'clck.ru']);

  const REDIRECT_HOSTS = [/^clicktime\./i, /safelinks\.protection\.outlook\.com$/i, /urldefense\./i,
    /\.proofpoint\.com$/i, /\.mimecastprotect\.com$/i, /^r\./i, /^click\./i, /^link\./i, /^email\./i, /\.sendgrid\.net$/i];

  const CRED_WORDS = /(login|log-in|signin|sign-in|verify|verification|secure|account|update|confirm|password|passwd|credential|billing|invoice|payment|unlock|suspend|recover|auth|sso|mfa|otp|token|wallet|seed|kyc)/i;

  const RISKY_TLD = new Set(['zip', 'mov', 'xyz', 'top', 'tk', 'ml', 'ga', 'cf', 'gq', 'work', 'click',
    'link', 'country', 'stream', 'download', 'loan', 'review', 'kim', 'men', 'date', 'racing', 'win',
    'bid', 'quest', 'cam', 'rest', 'buzz', 'monster', 'sbs', 'cfd', 'icu', 'shop', 'live', 'fit']);

  const BRANDS = ['microsoft', 'office365', 'outlook', 'onedrive', 'sharepoint', 'apple', 'icloud',
    'google', 'gmail', 'amazon', 'aws', 'paypal', 'netflix', 'facebook', 'instagram', 'whatsapp',
    'linkedin', 'dropbox', 'docusign', 'adobe', 'santander', 'bbva', 'caixabank', 'sabadell',
    'bankinter', 'unicaja', 'ing', 'correos', 'seur', 'dhl', 'fedex', 'ups', 'dgt', 'aeat',
    'agenciatributaria', 'seguridadsocial', 'endesa', 'iberdrola', 'movistar', 'vodafone',
    'binance', 'coinbase', 'metamask', 'revolut', 'wetransfer', 'zoom', 'teams', 'chase', 'hsbc'];

  // Correo gratuito: legítimo para una persona, sospechoso cuando quien escribe
  // dice ser el director financiero de una empresa.
  const FREEMAIL = new Set(['gmail.com', 'googlemail.com', 'hotmail.com', 'hotmail.es',
    'outlook.com', 'outlook.es', 'live.com', 'yahoo.com', 'yahoo.es', 'aol.com',
    'protonmail.com', 'proton.me', 'gmx.com', 'mail.com', 'yandex.com', 'icloud.com']);

  const CARGOS = /\b(ceo|cfo|coo|cto|director|directora|direccion|dirección|gerente|presidente|presidenta|administrador|administradora|jefe|jefa|responsable|manager|head of)\b/i;

  // Servicios de archivos: el phishing desde cuentas comprometidas casi siempre
  // apunta aquí, porque el dominio es legítimo y ningún filtro lo bloquea.
  const FILEHOSTS = new Set(['drive.google.com', 'docs.google.com', 'dropbox.com',
    'wetransfer.com', 'we.tl', 'onedrive.live.com', '1drv.ms', 'mega.nz', 'mediafire.com',
    'box.com', 'sharefile.com', 'sync.com', 'pcloud.com', 'terabox.com']);

  const IBAN_RE = /\b[A-Z]{2}\d{2}[ ]?(?:[A-Za-z0-9]{4}[ ]?){3,7}[A-Za-z0-9]{1,4}\b/;

  const URL_RE = /\b(?:https?|ftp|file):\/\/[^\s<>"'`)\]}]+|\bwww\.[a-z0-9-]+(?:\.[a-z0-9-]+)+[^\s<>"'`)\]}]*/gi;

  function parseUrl(u) {
    let s = String(u).trim().replace(/[)>\]}.,;:'"]+$/, '');
    if (/^www\./i.test(s)) s = 'http://' + s;
    let scheme = '', authority = '', rest = '';
    const m = s.match(/^([a-z][a-z0-9+.-]*):\/\/([^/?#]*)([\s\S]*)$/i);
    if (m) { scheme = m[1].toLowerCase(); authority = m[2]; rest = m[3] || ''; }
    else return { url: s, scheme: '', host: '', path: s, userinfo: '', port: '' };
    let userinfo = '';
    if (authority.indexOf('@') >= 0) { const i = authority.lastIndexOf('@'); userinfo = authority.slice(0, i); authority = authority.slice(i + 1); }
    let host = authority, port = '';
    const pm = authority.match(/^(\[[^\]]+\]|[^:]+)(?::(\d+))?$/);
    if (pm) { host = pm[1]; port = pm[2] || ''; }
    return { url: s, scheme, host: host.toLowerCase(), port, userinfo, path: rest };
  }

  // dominiosPropios: dominio del remitente y el que firma DKIM. Un enlace a la
  // propia casa del remitente no es un indicio de nada, y era la mayor fuente
  // de falsos positivos: cualquier boletín enlaza a su zona de cuenta.
  function extractLinks(htmlText, plainText, dominiosPropios) {
    const propios = new Set((dominiosPropios || []).filter(Boolean));
    const found = new Map(); // url -> {texts:Set, sources:Set}
    const add = (url, text, source) => {
      if (!url) return;
      const p = parseUrl(url);
      if (!p.scheme) return;
      const key = p.url;
      if (!found.has(key)) found.set(key, { parsed: p, texts: new Set(), sources: new Set() });
      if (text) found.get(key).texts.add(String(text).replace(/\s+/g, ' ').trim().slice(0, 200));
      found.get(key).sources.add(source);
    };

    if (htmlText) {
      let usedDom = false;
      if (typeof DOMParser === 'function') {
        try {
          const doc = new DOMParser().parseFromString(htmlText, 'text/html');
          doc.querySelectorAll('a[href]').forEach(a => add(a.getAttribute('href'), a.textContent, 'html:a'));
          doc.querySelectorAll('img[src]').forEach(i => add(i.getAttribute('src'), '[img]', 'html:img'));
          doc.querySelectorAll('form[action]').forEach(f => add(f.getAttribute('action'), '[form]', 'html:form'));
          doc.querySelectorAll('[background]').forEach(f => add(f.getAttribute('background'), '[bg]', 'html:bg'));
          usedDom = true;
        } catch (e) { usedDom = false; }
      }
      if (!usedDom) {
        const re = /<a\b[^>]*href\s*=\s*["']?([^"'\s>]+)["']?[^>]*>([\s\S]*?)<\/a>/gi;
        let m;
        while ((m = re.exec(htmlText))) add(decodeEntities(m[1]), decodeEntities(m[2].replace(/<[^>]+>/g, '')), 'html:a');
        const re2 = /<(?:img|form|[a-z]+)\b[^>]*(?:src|action|background)\s*=\s*["']?([^"'\s>]+)/gi;
        while ((m = re2.exec(htmlText))) add(decodeEntities(m[1]), '[asset]', 'html:asset');
      }
      // URLs sueltas en el HTML (dentro de scripts, meta refresh...)
      const bare = htmlText.replace(/<[^>]+>/g, ' ');
      let m2; const re3 = new RegExp(URL_RE.source, 'gi');
      while ((m2 = re3.exec(bare))) add(decodeEntities(m2[0]), null, 'html:text');
      const mr = htmlText.match(/http-equiv\s*=\s*["']?refresh["']?[^>]*url\s*=\s*([^"'>\s]+)/i);
      if (mr) add(decodeEntities(mr[1]), '[meta refresh]', 'html:refresh');
    }
    if (plainText) {
      let m; const re = new RegExp(URL_RE.source, 'gi');
      while ((m = re.exec(plainText))) add(m[0], null, 'text');
    }

    return Array.from(found.values()).map(entry => {
      const p = entry.parsed;
      const texts = Array.from(entry.texts);
      const flags = [];
      const host = p.host;
      const od = orgDomain(host);
      const tld = host.split('.').pop();

      if (isIP(host)) flags.push({ id: 'url-ip', sev: 'high', msg: 'URL apunta a una IP directa, sin dominio' });
      if (/(^|\.)xn--/i.test(host)) flags.push({ id: 'url-punycode', sev: 'high', msg: 'Dominio punycode (posible homoglifo IDN)' });
      if (/[\u202A-\u202E\u2066-\u2069]/.test(p.url)) flags.push({ id: 'url-rtlo', sev: 'high', msg: 'Caracteres de control bidireccional en la URL: la dirección se lee al revés de como es' });
      if (/[\u200B-\u200D\uFEFF\u2060]/.test(p.url)) flags.push({ id: 'url-zerowidth', sev: 'high', msg: 'Caracteres invisibles de ancho cero dentro de la URL' });
      if ((p.userinfo.match(/@/g) || []).length >= 1) flags.push({ id: 'url-multi-at', sev: 'high', msg: 'Varias "@" en la dirección: todo lo anterior a la última es decorado, el destino real es ' + host });
      if (!isIP(host) && host.indexOf('.') < 0) flags.push({ id: 'url-no-tld', sev: 'medium', msg: 'El destino no tiene dominio de primer nivel: ' + host });
      if (p.userinfo) flags.push({ id: 'url-userinfo', sev: 'high', msg: 'Autoridad con "@" (' + p.userinfo + '@): oculta el host real' });
      if (SHORTENERS.has(od)) flags.push({ id: 'url-shortener', sev: 'medium', msg: 'Acortador de URL: destino oculto' });
      if (REDIRECT_HOSTS.some(r => r.test(host))) flags.push({ id: 'url-redirector', sev: 'info', msg: 'Host de redirección/tracking' });
      if (p.port && p.port !== '80' && p.port !== '443') flags.push({ id: 'url-port', sev: 'medium', msg: 'Puerto no estándar: ' + p.port });
      if (RISKY_TLD.has(tld)) flags.push({ id: 'url-tld', sev: 'medium', msg: 'TLD de alto abuso: .' + tld });
      if (CRED_WORDS.test(p.path)) flags.push({ id: 'url-creds', sev: 'medium', msg: 'Ruta con palabras de robo de credenciales' });
      if (p.scheme === 'http' && CRED_WORDS.test(p.path)) flags.push({ id: 'url-http', sev: 'medium', msg: 'Formulario sensible sobre HTTP sin cifrar' });
      if ((host.match(/\./g) || []).length >= 4) flags.push({ id: 'url-subdomains', sev: 'low', msg: 'Exceso de subdominios (' + host + ')' });
      // Por tokens y no por subcadena: "steamstatic" contiene "teams" y
      // "purchase" contiene "chase". Así solo cuenta la marca como palabra.
      const tokens = host.split(/[.\-_]/).filter(Boolean);
      const brandHit = BRANDS.find(b => tokens.includes(b) && !od.split('.')[0].startsWith(b));
      if (brandHit) flags.push({ id: 'url-brand', sev: 'high', msg: 'Marca "' + brandHit + '" en subdominio de un dominio ajeno' });
      if (/^data:/i.test(p.url)) flags.push({ id: 'url-data', sev: 'high', msg: 'data: URI (HTML embebido)' });
      if (FILEHOSTS.has(host) || FILEHOSTS.has(od)) {
        flags.push({ id: 'url-filehost', sev: 'low', msg: 'Enlace a un servicio de archivos (' + host + '): comprueba que esperabas ese documento' });
      }

      for (const t of texts) {
        const tp = t.match(URL_RE);
        if (tp) {
          const shownHost = parseUrl(tp[0]).host;
          if (shownHost && orgDomain(shownHost) !== od) {
            flags.push({ id: 'url-mismatch', sev: 'high', msg: 'El texto muestra ' + shownHost + ' pero el enlace va a ' + host });
          }
        }
      }
      // En casa del remitente, los indicios débiles no cuentan
      const DEBILES = ['url-creds', 'url-brand', 'url-tld', 'url-subdomains', 'url-http',
        'url-port', 'url-redirector', 'url-filehost'];
      const enCasa = propios.has(od);
      const flagsFinales = enCasa ? flags.filter(f => DEBILES.indexOf(f.id) < 0) : flags;

      // Un enlace es donde el usuario puede pinchar. Una imagen o una fuente
      // que carga la plantilla no lo es, y mezclarlas hacía que un boletín
      // normal dijera "23 enlaces" cuando el usuario ve cuatro.
      const PINCHABLES = ['html:a', 'html:form', 'html:refresh', 'text'];
      const tipo = Array.from(entry.sources).some(x => PINCHABLES.indexOf(x) >= 0) ? 'enlace' : 'recurso';

      return {
        url: p.url, defanged: defang(p.url), scheme: p.scheme, host, orgDomain: od, propio: enCasa, tipo,
        port: p.port, path: p.path.slice(0, 300), anchorTexts: texts,
        sources: Array.from(entry.sources), flags: flagsFinales
      };
    });
  }

  // Un correo con &#x110000; tiraba el analisis entero por una excepcion de
  // String.fromCodePoint. Fuera de rango se deja la entidad tal cual.
  function puntoCodigo(n, original) {
    if (!isFinite(n) || n < 0 || n > 0x10FFFF || (n >= 0xD800 && n <= 0xDFFF)) return original;
    try { return String.fromCodePoint(n); } catch (e) { return original; }
  }

  function decodeEntities(s) {
    if (!s) return '';
    return String(s)
      .replace(/&#x([0-9a-f]+);/gi, (m, h) => puntoCodigo(parseInt(h, 16), m))
      .replace(/&#(\d+);/g, (m, d) => puntoCodigo(parseInt(d, 10), m))
      .replace(/&amp;/gi, '&').replace(/&lt;/gi, '<').replace(/&gt;/gi, '>')
      .replace(/&quot;/gi, '"').replace(/&#39;|&apos;/gi, "'").replace(/&nbsp;/gi, ' ');
  }

  // ---------------------------------------------------------------------------
  // Adjuntos
  // ---------------------------------------------------------------------------

  const EXEC_EXT = new Set(['exe', 'scr', 'com', 'pif', 'cpl', 'msi', 'msp', 'mst', 'dll', 'sys',
    'bat', 'cmd', 'ps1', 'psm1', 'vbs', 'vbe', 'js', 'jse', 'wsf', 'wsh', 'hta', 'jar', 'lnk',
    'inf', 'reg', 'scf', 'application', 'gadget', 'msc', 'apk', 'appx', 'chm', 'url', 'library-ms',
    'settingcontent-ms', 'diagcab', 'theme', 'iqy', 'slk', 'ade', 'adp', 'mde', 'accdb', 'py', 'sh']);
  const MACRO_EXT = new Set(['docm', 'dotm', 'xlsm', 'xltm', 'xlam', 'pptm', 'potm', 'ppam', 'sldm', 'xll', 'xlsb']);
  const CONTAINER_EXT = new Set(['zip', '7z', 'rar', 'iso', 'img', 'vhd', 'vhdx', 'cab', 'ace', 'arj', 'tar', 'gz', 'bz2', 'xz', 'z', 'lzh']);
  const HTML_EXT = new Set(['html', 'htm', 'shtml', 'xhtml', 'mht', 'mhtml', 'svg']);

  const MAGIC = [
    { sig: [0x4d, 0x5a], type: 'PE/DOS ejecutable (MZ)' },
    { sig: [0x7f, 0x45, 0x4c, 0x46], type: 'ELF' },
    { sig: [0x25, 0x50, 0x44, 0x46], type: 'PDF' },
    { sig: [0x50, 0x4b, 0x03, 0x04], type: 'ZIP/OOXML' },
    { sig: [0xd0, 0xcf, 0x11, 0xe0], type: 'OLE2 (Office 97-2003)' },
    { sig: [0x52, 0x61, 0x72, 0x21], type: 'RAR' },
    { sig: [0x37, 0x7a, 0xbc, 0xaf], type: '7-Zip' },
    { sig: [0x1f, 0x8b], type: 'GZIP' },
    { sig: [0xca, 0xfe, 0xba, 0xbe], type: 'Java class / Mach-O fat' },
    { sig: [0x23, 0x21], type: 'Script con shebang' },
    { sig: [0x7b, 0x5c, 0x72, 0x74], type: 'RTF' }
  ];

  // Mira dentro de un ZIP sin descomprimirlo: basta con leer las cabeceras
  // locales. El bit 0 del flag de proposito general dice si va cifrado, y los
  // nombres de fichero dicen si dentro hay otro comprimido.
  function inspeccionaZip(bytes) {
    const out = { cifrado: false, anidado: null };
    if (bytes.length < 30 || bytes[0] !== 0x50 || bytes[1] !== 0x4b) return out;
    for (let i = 0; i + 30 <= bytes.length && i < 5000000; i++) {
      if (bytes[i] !== 0x50 || bytes[i + 1] !== 0x4b || bytes[i + 2] !== 0x03 || bytes[i + 3] !== 0x04) continue;
      if ((bytes[i + 6] & 0x01) === 1) out.cifrado = true;
      const largo = bytes[i + 26] | (bytes[i + 27] << 8);
      if (largo > 0 && largo < 512 && i + 30 + largo <= bytes.length) {
        let nombre = '';
        for (let k = 0; k < largo; k++) nombre += String.fromCharCode(bytes[i + 30 + k]);
        const e = extOf(nombre);
        if (!out.anidado && (CONTAINER_EXT.has(e) || EXEC_EXT.has(e))) out.anidado = nombre;
      }
    }
    return out;
  }

  function magicOf(bytes) {
    for (const m of MAGIC) {
      if (bytes.length >= m.sig.length && m.sig.every((b, i) => bytes[i] === b)) return m.type;
    }
    return null;
  }

  function extOf(name) {
    const m = String(name || '').toLowerCase().match(/\.([a-z0-9_-]{1,20})$/);
    return m ? m[1] : '';
  }

  function humanSize(n) {
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1048576).toFixed(2) + ' MB';
  }

  async function collectAttachments(root) {
    const list = [];
    const stack = [root];
    while (stack.length) {
      const n = stack.shift();
      for (const c of n.children) stack.push(c);
      if (n.children.length && n.mime.startsWith('multipart/')) continue;
      const isAttach = n.disposition === 'attachment' ||
        (n.dispParams && n.dispParams.filename) || n.params.name ||
        (n.disposition === 'inline' && !n.mime.startsWith('text/')) ||
        (!n.mime.startsWith('text/') && !n.mime.startsWith('multipart/') && n.mime !== 'message/rfc822');
      if (!isAttach) continue;
      const name = decodeRFC2047((n.dispParams && n.dispParams.filename) || n.params.name || '(sin nombre)');
      const bytes = nodeBytes(n);
      const hashes = await hashBytes(bytes);
      const ext = extOf(name);
      const magic = magicOf(bytes);
      const flags = [];
      if (EXEC_EXT.has(ext)) flags.push({ id: 'att-exec', sev: 'high', msg: 'Extensión ejecutable/script: .' + ext });
      if (MACRO_EXT.has(ext)) flags.push({ id: 'att-macro', sev: 'high', msg: 'Office con macros habilitadas: .' + ext });
      if (CONTAINER_EXT.has(ext)) flags.push({ id: 'att-container', sev: 'medium', msg: 'Contenedor (.' + ext + '): puede ocultar el payload' });
      if (HTML_EXT.has(ext)) flags.push({ id: 'att-html', sev: 'high', msg: 'Adjunto HTML/SVG: tipico de phishing local (smuggling)' });
      if (/\.[a-z0-9]{2,4}\s*\.[a-z0-9]{2,4}$/i.test(name)) flags.push({ id: 'att-double', sev: 'high', msg: 'Doble extensión en el nombre' });
      if (/[‪-‮⁦-⁩]/.test(name)) flags.push({ id: 'att-rtlo', sev: 'high', msg: 'Caracteres de control bidireccional (RTLO) en el nombre' });
      if (magic === 'PE/DOS ejecutable (MZ)' && !EXEC_EXT.has(ext)) flags.push({ id: 'att-mismatch', sev: 'high', msg: 'Cabecera MZ pero extensión .' + ext + ': tipo declarado falso' });
      if (magic === 'RTF' && ['rtf'].indexOf(ext) < 0) flags.push({ id: 'att-mismatch', sev: 'high', msg: 'Es un RTF disfrazado de .' + ext + ': vector habitual de exploits de Office' });
      if (magic === 'OLE2 (Office 97-2003)' && ['doc', 'xls', 'ppt'].indexOf(ext) < 0) flags.push({ id: 'att-ole', sev: 'medium', msg: 'Contenedor OLE2 con extensión .' + ext });
      const zip = inspeccionaZip(bytes);
      if (zip.cifrado) flags.push({ id: 'att-encrypted', sev: 'high', msg: 'Archivo comprimido con contraseña: ningún antivirus puede mirar dentro' });
      if (zip.anidado) flags.push({ id: 'att-archive-nested', sev: 'high', msg: (CONTAINER_EXT.has(extOf(zip.anidado)) ? 'Comprimido dentro de otro comprimido' : 'Programa dentro del comprimido') + ' (' + zip.anidado + '): se hace para esquivar el antivirus' });
      if (bytes.length === 0) flags.push({ id: 'att-empty', sev: 'info', msg: 'Adjunto vacio' });
      list.push({
        filename: name, mime: n.mime, declaredEncoding: n.encoding, disposition: n.disposition,
        size: bytes.length, sizeHuman: humanSize(bytes.length), magic, ext,
        md5: hashes.md5, sha1: hashes.sha1, sha256: hashes.sha256, flags
      });
    }
    return list;
  }

  // ---------------------------------------------------------------------------
  // PONDERACION
  //
  // Los pesos salen de medir el motor contra correo real. Corpus usados:
  //
  //   P  = Phishing Pot, 8.613 correos de phishing reales de honeypot (2023-25)
  //   H1 = SpamAssassin hard_ham, 250 correos legitimos comerciales en HTML (2002)
  //   H2 = Listas publicas de Apache, 3.471 correos legitimos (2025-26)
  //
  // Ninguno de los dos corpus legitimos vale por si solo: H1 tiene el HTML
  // comercial pero es anterior a SPF/DKIM/DMARC, y H2 tiene la autenticacion
  // moderna pero es texto plano de listas tecnicas. Asi que para cada regla se
  // toma el PEOR caso legitimo de los dos, y de ahi la razon de verosimilitud:
  //
  //   LR = P(la regla dispara | phishing) / P(la regla dispara | legitimo)
  //   pts = redondeo( 3.5 x log2(LR) )
  //
  // Una LR de 1 significa que el indicio no distingue nada, por grave que
  // suene. Una de 30 significa que aparece treinta veces mas en el fraude.
  //
  // El campo `fuente` lleva los porcentajes medidos. Se regenera con:
  //   node tools/verosimilitud.mjs <phishing> <legitimo>
  //
  // TRES AVISOS sobre los datos, que hay que tener presentes al tocar esto:
  //
  //  1. El 98,5% del corpus de phishing lo recibio Microsoft, frente al 8,1%
  //     del legitimo. Todo lo que escriba el receptor esta contaminado:
  //     `compauth` sale en el 72% del phishing y en el 0% del ham, pero eso
  //     mide quien recibio el correo, no si es fraude. Su peso esta puesto a
  //     mano por lo que significa, no por la medida.
  //  2. H2 son listas de correo, que reescriben Reply-To y rompen el
  //     alineamiento por diseño. Por eso replyto-mismatch y align-* disparan
  //     tanto en legitimo. Es real para listas, no para correo normal.
  //  3. Las reglas con 0,0% en ambos corpus no estan validadas: no hay datos,
  //     ni a favor ni en contra. Se quedan con peso moderado porque son
  //     precisas por construccion (un RTLO en un nombre de fichero no aparece
  //     por accidente), pero nadie las ha comprobado contra nada.
  //
  // LO QUE LA MEDIDA CAMBIO RESPECTO DE LA VERSION ANTERIOR:
  //
  //  - La version anterior anclaba los pesos a SpamAssassin y Rspamd. Estaba
  //    mal: esos motores llegan a su umbral sumando cientos de reglas mas
  //    Bayes mas listas negras de red. Este tiene sesenta reglas y ninguna
  //    consulta de red, asi que importar sus pesos por regla garantizaba no
  //    llegar nunca. Detectaba el 2,1% del phishing real.
  //  - Los mitigantes negativos eran contraproducentes. El 24% del phishing
  //    real pasa DMARC -lo mandan desde tenants de Microsoft 365 robados- y el
  //    60% activaba algun mitigante. Se les baja a la minima expresion.
  //  - dn-brand valia 14 puntos y dispara MAS en correo legitimo (9,8% vs
  //    11,1%): las marcas se llaman por su nombre en su propio correo.
  //  - url-mismatch, el caso que encabeza el README, tiene LR 1,0. No
  //    distingue. Hoy casi todo se lee en el movil, donde no se ve la URL, y
  //    el atacante ya no se molesta.
  // ---------------------------------------------------------------------------
  const CATEGORIAS = {
    auth:       { techo: 30, nombre: 'Autenticación' },
    identidad:  { techo: 20, nombre: 'Identidad del remitente' },
    enlaces:    { techo: 20, nombre: 'Enlaces' },
    contenido:  { techo: 15, nombre: 'Contenido del mensaje' },
    adjuntos:   { techo: 10, nombre: 'Adjuntos' },
    transporte: { techo: 5, nombre: 'Transporte y cabeceras' }
  };

  const PESOS = {
    // --- Autenticación (techo 30) --------------------------------------------
    // Lo que mas informa de todo, y no por el fallo en si: por lo que dice del
    // dominio que envia. Un dominio que no publica DMARC aparece en el 44% del
    // phishing y en el 3% del correo bueno.
    'dkim-fail':       { cat: 'auth', pts: 19, sev: 'high',  fuente: 'LR 41.5 (P 9.5% / H 0.0%)' },
    'dmarc-fail':      { cat: 'auth', pts: 19, sev: 'high',  fuente: 'LR 39.0 (P 7.8% / H 0.0%)' },
    'spf-fail':        { cat: 'auth', pts: 18, sev: 'high',  fuente: 'LR 32.8 (P 9.4% / H 0.1%)' },
    'spf-softfail':    { cat: 'auth', pts: 16, sev: 'medium', fuente: 'LR 26.3 (P 5.2% / H 0.0%)' },
    'spf-neutral':     { cat: 'auth', pts: 15, sev: 'medium', fuente: 'LR 18.9 (P 28.8% / H 1.3%)' },
    'dmarc-none':      { cat: 'auth', pts: 13, sev: 'medium', fuente: 'LR 12.4 (P 43.9% / H 3.3%)' },
    // Puesto a mano: la medida esta contaminada por el receptor (aviso 1).
    // Cuando Microsoft dice que la autenticacion compuesta falla, lo dice con
    // mucha mas informacion de la que tenemos aqui.
    'compauth':        { cat: 'auth', pts: 12, sev: 'medium', fuente: 'a mano - veredicto de Microsoft, medida contaminada por el receptor' },
    // Dispara en el 0,1% del phishing y en el 11% del legitimo: las listas de
    // correo rompen el alineamiento por diseño. Era 8 puntos.
    'align-none':      { cat: 'auth', pts: 0, sev: 'info',  fuente: 'LR 0.0 (P 0.1% / H 11.1%) - no distingue' },
    'align-dkim':      { cat: 'auth', pts: 0, sev: 'info',  fuente: 'LR 0.1 (P 0.3% / H 3.4%) - no distingue' },
    'spf-absent':      { cat: 'auth', pts: 0, sev: 'info',  fuente: 'ausencia de datos, no indicio' },
    'dkim-absent':     { cat: 'auth', pts: 0, sev: 'info',  fuente: 'ausencia de datos, no indicio' },
    'dmarc-absent':    { cat: 'auth', pts: 0, sev: 'info',  fuente: 'ausencia de datos, no indicio' },
    'no-transport':    { cat: 'auth', pts: 0, sev: 'info',  fuente: 'informativo' },

    // Mitigantes. El 24% del phishing real pasa DMARC y el 60% activaba alguno
    // de estos, asi que restar de verdad era premiar al atacante que manda
    // desde una cuenta robada. Se quedan en un gesto: separan al que autentica
    // del que no, pero no rescatan a nadie.
    'ok-arc':          { cat: 'auth', pts: -1, sev: 'info', fuente: 'a mano - reenvio legitimo; el 60% del phishing tambien lo activaba' },
    'ok-dmarc':        { cat: 'auth', pts: -1, sev: 'info', fuente: 'a mano - el 24% del phishing real pasa DMARC' },
    'ok-dkim':         { cat: 'auth', pts: 0, sev: 'info',  fuente: 'a mano - no distingue por si solo' },
    'ok-spf':          { cat: 'auth', pts: 0, sev: 'info',  fuente: 'a mano - no distingue por si solo' },

    // --- Identidad del remitente (techo 20) ----------------------------------
    // From mal formado: coma sin comillas en el nombre visible, que parte la
    // cabecera en dos. El cliente enseña una cosa y el filtro lee otra.
    // Aparece en el 18,6% del phishing y en cero correos legitimos de 3.721.
    'from-malformed':  { cat: 'identidad', pts: 20, sev: 'high', fuente: 'LR 93.4 (P 18.6% / H 0.0%)' },
    'from-tld':        { cat: 'identidad', pts: 13, sev: 'high', fuente: 'LR 13.3 (P 3.0% / H 0.0%)' },
    'replyto-freemail':{ cat: 'identidad', pts: 6, sev: 'medium', fuente: 'LR 3.1 (P 0.6% / H 0.0%)' },
    'dn-mixed-script': { cat: 'identidad', pts: 5, sev: 'medium', fuente: 'LR 2.6 (P 0.5% / H 0.0%)' },
    'from-multi':      { cat: 'identidad', pts: 5, sev: 'medium', fuente: 'sin validar - varias direcciones reales en From' },
    'from-punycode':   { cat: 'identidad', pts: 12, sev: 'high', fuente: 'sin validar (0% en ambos corpus) - preciso por construccion' },
    'from-lookalike':  { cat: 'identidad', pts: 12, sev: 'high', fuente: 'sin validar - dominio que imita a una marca' },
    'from-freemail-cargo': { cat: 'identidad', pts: 8, sev: 'high', fuente: 'sin validar - patron BEC (FBI IC3)' },
    'dn-email':        { cat: 'identidad', pts: 0, sev: 'info', fuente: 'LR 0.4 (P 0.4% / H 0.8%) - no distingue' },
    // Valia 14 puntos. Dispara mas en correo legitimo: las marcas se llaman
    // por su nombre en su propio correo.
    'dn-brand':        { cat: 'identidad', pts: 0, sev: 'info', fuente: 'LR 0.9 (P 9.8% / H 11.1%) - no distingue' },
    'replyto-mismatch':{ cat: 'identidad', pts: 0, sev: 'info', fuente: 'LR 0.3 (P 15.2% / H 46.1%) - no distingue' },
    'rp-mismatch':     { cat: 'identidad', pts: 0, sev: 'info', fuente: 'LR 0.8 (P 13.8% / H 17.6%) - no distingue' },
    'mid-mismatch':    { cat: 'identidad', pts: 0, sev: 'info', fuente: 'LR 0.4 (P 28.1% / H 64.0%) - no distingue' },
    'mid-missing':     { cat: 'identidad', pts: 0, sev: 'info', fuente: 'LR 0.4 (P 0.1% / H 0.0%) - no distingue' },
    'from-missing':    { cat: 'identidad', pts: 0, sev: 'info', fuente: 'LR 0.3 (P 0.1% / H 0.0%) - no distingue' },

    // --- Enlaces (techo 20) ---------------------------------------------------
    'url-tld':         { cat: 'enlaces', pts: 17, sev: 'high', fuente: 'LR 30.6 (P 6.1% / H 0.0%)' },
    'url-userinfo':    { cat: 'enlaces', pts: 10, sev: 'high', fuente: 'LR 7.9 (P 1.6% / H 0.0%)' },
    'url-shortener':   { cat: 'enlaces', pts: 10, sev: 'medium', fuente: 'LR 7.4 (P 13.3% / H 1.6%)' },
    'url-ip':          { cat: 'enlaces', pts: 6, sev: 'medium', fuente: 'LR 3.3 (P 5.9% / H 1.6%)' },
    'url-subdomains':  { cat: 'enlaces', pts: 5, sev: 'low', fuente: 'LR 2.7 (P 4.9% / H 1.6%)' },
    // Sin validar: cero apariciones en los tres corpus. Se quedan porque no
    // aparecen por accidente, pero nadie las ha comprobado.
    'url-rtlo':        { cat: 'enlaces', pts: 15, sev: 'high', fuente: 'sin validar (0% en ambos) - preciso por construccion' },
    'url-zerowidth':   { cat: 'enlaces', pts: 15, sev: 'high', fuente: 'sin validar (0% en ambos) - preciso por construccion' },
    'url-punycode':    { cat: 'enlaces', pts: 14, sev: 'high', fuente: 'sin validar (0% en ambos) - preciso por construccion' },
    'url-multi-at':    { cat: 'enlaces', pts: 12, sev: 'high', fuente: 'sin validar - preciso por construccion' },
    'url-data':        { cat: 'enlaces', pts: 10, sev: 'high', fuente: 'sin validar - preciso por construccion' },
    // El caso que encabeza el README. LR 1,0: no distingue.
    'url-mismatch':    { cat: 'enlaces', pts: 3, sev: 'low', fuente: 'LR 1.0 (P 3.5% / H 3.2%) - apenas distingue' },
    'url-no-tld':      { cat: 'enlaces', pts: 0, sev: 'info', fuente: 'LR 1.0 (P 1.6% / H 1.3%) - no distingue' },
    'url-brand':       { cat: 'enlaces', pts: 0, sev: 'info', fuente: 'LR 0.1 (P 0.8% / H 12.0%) - no distingue' },
    'url-creds':       { cat: 'enlaces', pts: 0, sev: 'info', fuente: 'LR 0.1 (P 6.7% / H 53.2%) - no distingue' },
    'url-http':        { cat: 'enlaces', pts: 0, sev: 'info', fuente: 'LR 0.0 (P 0.7% / H 43.6%) - no distingue' },
    'url-port':        { cat: 'enlaces', pts: 0, sev: 'info', fuente: 'LR 0.0 (P 0.0% / H 1.2%) - no distingue' },
    'url-filehost':    { cat: 'enlaces', pts: 0, sev: 'info', fuente: 'LR 0.6 (P 0.4% / H 0.5%) - no distingue' },
    'url-redirector':  { cat: 'enlaces', pts: 0, sev: 'info', fuente: 'informativo' },

    // --- Contenido del mensaje (techo 15) -------------------------------------
    'body-image':      { cat: 'contenido', pts: 15, sev: 'high', fuente: 'LR 29.3 (P 5.8% / H 0.0%), recortado al techo' },
    'subj-urgency':    { cat: 'contenido', pts: 14, sev: 'medium', fuente: 'LR 15.5 (P 5.7% / H 0.2%)' },
    'body-crypto':     { cat: 'contenido', pts: 10, sev: 'medium', fuente: 'LR 7.7 (P 13.9% / H 1.6%)' },
    'body-bec':        { cat: 'contenido', pts: 4, sev: 'medium', fuente: 'LR 2.2 (P 3.9% / H 1.6%)' },
    'body-hidden':     { cat: 'contenido', pts: 5, sev: 'low', fuente: 'LR 2.5 (P 37.5% / H 14.8%)' },
    'body-password':   { cat: 'contenido', pts: 12, sev: 'high', fuente: 'sin validar - preciso por construccion' },
    'body-iban':       { cat: 'contenido', pts: 8, sev: 'medium', fuente: 'sin validar - patron BEC' },
    'body-nocontacto': { cat: 'contenido', pts: 8, sev: 'medium', fuente: 'sin validar - patron BEC' },
    'body-refresh':    { cat: 'contenido', pts: 6, sev: 'medium', fuente: 'sin validar' },
    'body-empty':      { cat: 'contenido', pts: 0, sev: 'info', fuente: 'LR 0.4 - no distingue' },
    'subj-nothread':   { cat: 'contenido', pts: 0, sev: 'info', fuente: 'LR 1.0 (P 1.9% / H 1.6%) - no distingue' },
    // El HTML de 2002 llevaba scripts, iframes y formularios de serie, y el
    // phishing de hoy casi no los usa. Los cuatro disparan mas en correo bueno.
    'body-form':       { cat: 'contenido', pts: 0, sev: 'info', fuente: 'LR 0.0 (P 0.6% / H 34.0%) - no distingue' },
    'body-script':     { cat: 'contenido', pts: 0, sev: 'info', fuente: 'LR 0.1 (P 1.6% / H 25.2%) - no distingue' },
    'body-iframe':     { cat: 'contenido', pts: 0, sev: 'info', fuente: 'LR 0.0 (P 0.7% / H 24.0%) - no distingue' },
    'body-entities':   { cat: 'contenido', pts: 0, sev: 'info', fuente: 'LR 0.0 (P 0.4% / H 8.4%) - no distingue' },

    // --- Adjuntos (techo 10) --------------------------------------------------
    // Cero adjuntos peligrosos en 8.613 correos de phishing: hoy el fraude va
    // por enlace, no por fichero. Se quedan por si acaso, sin validar.
    'att-exec':        { cat: 'adjuntos', pts: 10, sev: 'high', fuente: 'sin validar (0% en el corpus)' },
    'att-archive-nested': { cat: 'adjuntos', pts: 10, sev: 'high', fuente: 'sin validar (0% en el corpus)' },
    'att-macro':       { cat: 'adjuntos', pts: 10, sev: 'high', fuente: 'sin validar (0% en el corpus)' },
    'att-encrypted':   { cat: 'adjuntos', pts: 9, sev: 'high', fuente: 'sin validar (0% en el corpus)' },
    'att-rtlo':        { cat: 'adjuntos', pts: 9, sev: 'high', fuente: 'sin validar (0% en el corpus)' },
    'att-double':      { cat: 'adjuntos', pts: 8, sev: 'high', fuente: 'sin validar (0% en el corpus)' },
    'att-mismatch':    { cat: 'adjuntos', pts: 8, sev: 'high', fuente: 'sin validar (0% en el corpus)' },
    'att-html':        { cat: 'adjuntos', pts: 6, sev: 'medium', fuente: 'LR 0.6 (P 0.1% / H 0.0%) - pocos datos' },
    'att-ole':         { cat: 'adjuntos', pts: 4, sev: 'medium', fuente: 'sin validar' },
    'att-container':   { cat: 'adjuntos', pts: 0, sev: 'info', fuente: 'LR 0.1 - no distingue' },
    'att-empty':       { cat: 'adjuntos', pts: 0, sev: 'info', fuente: 'informativo' },

    // --- Transporte y cabeceras (techo 5) -------------------------------------
    'xmailer':         { cat: 'transporte', pts: 5, sev: 'medium', fuente: 'LR 17.4 (P 3.5% / H 0.0%), recortado por el techo' },
    'date-skew':       { cat: 'transporte', pts: 3, sev: 'low', fuente: 'LR 1.9 (P 1.2% / H 0.4%)' },
    'rcv-none':        { cat: 'transporte', pts: 3, sev: 'low', fuente: 'sin validar' },
    'date-missing':    { cat: 'transporte', pts: 2, sev: 'low', fuente: 'sin validar' },
    'rcv-delay':       { cat: 'transporte', pts: 0, sev: 'info', fuente: 'LR 0.1 (P 3.4% / H 22.8%) - no distingue' },
    'rcv-one':         { cat: 'transporte', pts: 0, sev: 'info', fuente: 'LR ~1 - no distingue' },
    'x-orig-ip':       { cat: 'transporte', pts: 0, sev: 'info', fuente: 'informativo' }
  };

  // Correlaciones. La de credenciales estaba montada sobre dos indicios
  // debiles y disparaba catorce veces mas en correo legitimo que en fraude
  // (1,1% vs 15,2%): pedia (formulario O ruta con palabra de login) Y (marca
  // en subdominio O texto que no cuadra), y todo eso es un boletin comercial
  // normal. Ahora exige la contraseña pedida en el propio correo, que es el
  // hecho que de verdad define el robo de credenciales.
  const COMBOS = [
    { id: 'combo-bec', pts: 22, sev: 'high',
      msg: 'Encaja con el fraude del jefe: alguien que dice ser de la empresa, desde una cuenta que no es la suya, pidiendo un pago',
      si: ids => (ids.has('from-freemail-cargo') || ids.has('replyto-freemail'))
        && (ids.has('body-bec') || ids.has('body-iban') || ids.has('body-nocontacto')) },
    { id: 'combo-credenciales', pts: 18, sev: 'high',
      msg: 'Encaja con el robo de contraseñas: te lleva a una página falsa y te pide que te identifiques',
      si: ids => ids.has('body-password')
        && (ids.has('url-mismatch') || ids.has('url-punycode') || ids.has('url-ip') || ids.has('url-tld')) },
    { id: 'combo-malware', pts: 18, sev: 'high',
      msg: 'Encaja con el envío de malware: adjunto peligroso y una excusa para que lo abras deprisa',
      si: ids => (ids.has('att-exec') || ids.has('att-macro') || ids.has('att-encrypted') || ids.has('att-archive-nested'))
        && (ids.has('body-empty') || ids.has('subj-urgency') || ids.has('dmarc-fail') || ids.has('spf-fail')) },
    { id: 'combo-extorsion', pts: 15, sev: 'high',
      msg: 'Encaja con la extorsión: amenaza y una cartera de criptomonedas para pagar',
      si: ids => ids.has('body-crypto')
        && (ids.has('from-tld') || ids.has('spf-neutral') || ids.has('dmarc-none') || ids.has('subj-urgency')) }
  ];

  const TECHO_COMBOS = 22;

  // Umbrales del veredicto
  const UMBRALES = [[80, 'CRITICO'], [50, 'ALTO'], [20, 'MEDIO'], [0, 'BAJO']];

  // ---------------------------------------------------------------------------
  // Análisis principal
  // ---------------------------------------------------------------------------

  const URGENCY = /(urgente|inmediat|caduca|expira|vence|suspend|bloquea|bloqueo|último aviso|último aviso|accion requerida|acción requerida|24 horas|48 horas|impag|multa|sanción|sanción|premio|herencia|urgent|immediate|expires?|suspended|action required|final notice|overdue|last warning)/i;

  async function analyze(rawLatin1, meta) {
    meta = meta || {};
    const root = parseNode(rawLatin1, 0);
    const H = root.headers;
    const findings = [];
    const push = (id, msg) => {
      const p = PESOS[id] || { cat: 'contenido', pts: 0, sev: 'info' };
      findings.push({ id, msg, cat: p.cat, sev: p.sev, points: p.pts, fuente: p.fuente || null });
    };

    // --- Identidades
    const from = parseAddressList(headerGet(H, 'from'));
    const replyTo = parseAddressList(headerGet(H, 'reply-to'));
    const returnPath = parseAddressList(headerGet(H, 'return-path'));
    const to = parseAddressList(headerGet(H, 'to'));
    const cc = parseAddressList(headerGet(H, 'cc'));
    const sender = parseAddressList(headerGet(H, 'sender'));
    const subject = decodeRFC2047(headerGet(H, 'subject') || '');
    const messageId = (headerGet(H, 'message-id') || '').trim();
    const dateHdr = (headerGet(H, 'date') || '').trim();
    const fromOrg = from[0] ? from[0].orgDomain : '';

    const auth = parseAuthResults(H);
    const hops = parseReceived(H);

    // --- Cuerpos
    const textParts = [], htmlParts = [];
    (function walk(n) {
      if (n.mime === 'text/plain' && n.disposition !== 'attachment') textParts.push(nodeText(n));
      else if (n.mime === 'text/html' && n.disposition !== 'attachment') htmlParts.push(nodeText(n));
      n.children.forEach(walk);
    })(root);
    const plain = textParts.join('\n\n');
    const html = htmlParts.join('\n\n');

    const urls = extractLinks(html, plain, [fromOrg, orgDomain(auth.dkimDomain || '')]);
    // Muchos correos solo traen HTML: si solo se mira el texto plano, la mitad
    // de las reglas de contenido no se enteran de nada.
    const textoVisible = (plain + ' ' + decodeEntities(html.replace(/<[^>]+>/g, ' ')))
      .replace(/\s+/g, ' ').trim();
    const attachments = await collectAttachments(root);

    // Un .eml reconstruido o exportado a mano no conserva cabeceras de transporte:
    // en ese caso su ausencia no es un indicio, solo una limitacion del análisis.
    const noTransport = auth.raw.length === 0 && hops.length === 0;
    if (noTransport) {
      push('no-transport', 'El fichero no conserva cabeceras de transporte (Received/Authentication-Results): análisis limitado al contenido');
    }

    // --- Reglas de autenticación
    //
    // Orden importado del RFC 7489: DMARC no es un tercer voto que se suma a
    // SPF y DKIM, es SU CONCLUSION. "SPF o DKIM pasa Y alinea con el From".
    // Antes se sumaban los tres y un unico hecho puntuaba tres veces: una
    // lista de correo reenviada sacaba 75 puntos brutos por un solo fallo.
    // Ahora SPF y DKIM apenas puntuan por su cuenta, que es exactamente lo
    // que dicen los corpus: SpamAssassin puntua SPF_FAIL con 0.001 sobre 5.
    const S = (v) => (v || '').toLowerCase();

    // ARC (RFC 8617) primero: si la cadena valida, los fallos de SPF y DKIM
    // son del reenvio, no del autor, y no cuentan. Medido: solo el 2,8% del
    // phishing real trae ARC valido y fallo de autenticacion a la vez, asi que
    // esto cuesta poca deteccion y arregla del todo el correo de listas.
    const arcOk = auth.arcChain > 0 && ['pass', 'none', null, ''].indexOf(S(auth.arc)) >= 0;
    // DMARC es la conclusion de SPF y DKIM (RFC 7489). Si hay veredicto DMARC,
    // el fallo ya esta contado ahi y sumar los insumos es contarlo tres veces.
    const hayDmarc = ['pass', 'fail', 'none'].indexOf(S(auth.dmarc)) >= 0;
    const sueltos = !hayDmarc && !arcOk;

    if (S(auth.spf) === 'fail') { if (sueltos) push('spf-fail', 'SPF fail: el servidor emisor no está autorizado por el dominio del sobre'); }
    else if (S(auth.spf) === 'softfail') { if (sueltos) push('spf-softfail', 'SPF softfail'); }
    else if (S(auth.spf) === 'none' || S(auth.spf) === 'neutral') { if (!arcOk) push('spf-neutral', 'SPF ' + auth.spf + ': el dominio no publica política utilizable'); }
    else if (S(auth.spf) === 'pass') push('ok-spf', 'SPF pass: el servidor emisor está autorizado');
    else if (!noTransport) push('spf-absent', 'Sin resultado SPF en las cabeceras');

    if (S(auth.dkim) === 'fail') { if (sueltos) push('dkim-fail', 'DKIM fail: la firma no valida (contenido alterado o firma falsa)'); }
    else if (S(auth.dkim) === 'pass') push('ok-dkim', 'DKIM pass: la firma del dominio valida');
    else if (!noTransport) push('dkim-absent', 'El mensaje no viene firmado con DKIM');

    if (S(auth.dmarc) === 'fail') { if (!arcOk) push('dmarc-fail', 'DMARC fail: no hay alineamiento con el dominio del From'); }
    else if (S(auth.dmarc) === 'none') push('dmarc-none', 'DMARC none: el dominio no publica política DMARC');
    else if (S(auth.dmarc) === 'pass') push('ok-dmarc', 'DMARC pass: el correo viene de donde dice venir');
    else if (!noTransport) push('dmarc-absent', 'Sin resultado DMARC en las cabeceras');

    if (auth.compauth && ['fail', 'softpass', 'none'].indexOf(S(auth.compauth)) >= 0) {
      push('compauth', 'compauth=' + auth.compauth + ' (Microsoft marca autenticación compuesta débil)');
    }

    // ARC (RFC 8617): la cadena de confianza que dejan los reenviadores. Un
    // DMARC fail con ARC valido es la firma del REENVIO LEGITIMO -causa numero
    // uno de que el correo bueno falle DMARC-, no la de un fraude. Se parseaba
    // desde el principio y no se usaba para nada.
    if (arcOk) push('ok-arc', 'Cadena ARC presente (' + auth.arcChain + ' sello(s)): el correo ha pasado por un reenviador que da fe de que autenticaba en origen');

    // Alineamiento manual. Solo cuenta si NO hubo veredicto DMARC: si lo hubo,
    // esto ya esta contado ahi y sumarlo seria contar dos veces lo mismo.
    const alignment = { spf: null, dkim: null };
    if (fromOrg && auth.spfDomain) alignment.spf = orgDomain(auth.spfDomain) === fromOrg;
    if (fromOrg && auth.dkimDomain) alignment.dkim = orgDomain(auth.dkimDomain) === fromOrg;
    if (!auth.dmarc) {
      if (alignment.spf === false && alignment.dkim !== true) {
        push('align-none', 'Ningún identificador alinea con el From (' + fromOrg + '): SPF=' +
          (auth.spfDomain || 'n/d') + ', DKIM=' + (auth.dkimDomain || 'sin firma'));
      } else if (alignment.dkim === false && auth.dkimDomain) {
        push('align-dkim', 'DKIM firma como ' + auth.dkimDomain + ', no como ' + fromOrg);
      }
    }

    // Un correo que autentica de punta a punta. Se usa mas abajo para callar
    // los indicios debiles que disparan en practicamente todo correo masivo
    // legitimo (Return-Path del proveedor de envio, texto oculto de plantilla).
    const autentica = S(auth.dmarc) === 'pass' || alignment.dkim === true || arcOk;

    // --- Reglas de identidad
    if (returnPath[0] && fromOrg && returnPath[0].orgDomain && returnPath[0].orgDomain !== fromOrg && !autentica) {
      push('rp-mismatch', 'Return-Path (' + returnPath[0].orgDomain + ') distinto del From (' + fromOrg + ')');
    }
    if (replyTo[0] && fromOrg && replyTo[0].orgDomain && replyTo[0].orgDomain !== fromOrg) {
      push('replyto-mismatch', 'Reply-To apunta a ' + replyTo[0].address + ', dominio ajeno al remitente');
    } else if (replyTo[0] && from[0] && replyTo[0].address.toLowerCase() !== from[0].address.toLowerCase()
               && FREEMAIL.has(fromOrg)) {
      push('replyto-freemail', 'La respuesta iría a ' + replyTo[0].address + ', otra cuenta distinta de la que envía');
    }
    if (from[0]) {
      const dn = from[0].name || '';
      const emailInName = dn.match(/[\w.+-]+@[\w.-]+\.\w+/);
      if (emailInName && orgDomain(emailInName[0].split('@')[1]) !== fromOrg) {
        push('dn-email', 'El nombre visible contiene otra dirección (' + emailInName[0] + ') distinta de la real');
      }
      const dnNorm = dn.toLowerCase().replace(/[^a-z0-9]/g, '');
      const brand = BRANDS.find(b => dnNorm.includes(b));
      if (brand && fromOrg && !fromOrg.replace(/[^a-z0-9]/g, '').includes(brand)) {
        push('dn-brand', 'Nombre visible suplanta a "' + brand + '" desde el dominio ' + fromOrg);
      }
      const mezcla = scriptMixto(dn) || scriptMixto(from[0].address || '');
      if (mezcla) {
        push('dn-mixed-script', 'Mezcla de alfabetos dentro de una misma palabra ("' + mezcla + '"): letras de otro alfabeto que se ven igual que las latinas');
      }
      if (/(^|\.)xn--/i.test(from[0].domain || '')) push('from-punycode', 'Dominio del remitente en punycode: ' + from[0].domain);
      if (RISKY_TLD.has((from[0].domain || '').split('.').pop())) {
        push('from-tld', 'TLD de alto abuso en el remitente: .' + from[0].domain.split('.').pop());
      }
      if (FREEMAIL.has(fromOrg) && CARGOS.test(dn)) {
        push('from-freemail-cargo', 'Se presenta como "' + dn.trim() + '" pero escribe desde una cuenta de correo gratuita');
      }
      if (from.length > 1) {
        const conDireccion = from.filter(a => a.address && a.address.indexOf('@') > 0);
        if (conDireccion.length > 1) {
          push('from-multi', 'Múltiples direcciones en From (' + conDireccion.length + '): técnica de evasión');
        } else {
          push('from-malformed', 'El From lleva una coma sin comillas ("' + (from[0].raw || '').slice(0, 40) +
            '"): parte la cabecera en dos y tu programa de correo enseña una cosa distinta de la que lee el filtro');
        }
      }
      const parecido = dominioParecido(fromOrg);
      if (parecido) {
        push('from-lookalike', 'El dominio ' + fromOrg + ' imita a "' + parecido + '" cambiando o quitando letras');
      }
    } else {
      push('from-missing', 'Sin cabecera From');
    }

    if (!messageId) { if (!noTransport) push('mid-missing', 'Sin Message-ID: generado por herramienta de envio masivo o script'); }
    else {
      const mdom = (messageId.match(/@([^>\s]+)>?\s*$/) || [])[1];
      if (mdom && fromOrg && orgDomain(mdom) !== fromOrg && !autentica) {
        push('mid-mismatch', 'Dominio del Message-ID (' + orgDomain(mdom) + ') distinto del From');
      }
    }

    const xMailer = headerGet(H, 'x-mailer') || headerGet(H, 'user-agent') || '';
    if (/phpmailer|sendmail|python|swiftmailer|mass|bulk|axigen|smtplib|mailer\s*script/i.test(xMailer)) {
      push('xmailer', 'X-Mailer sospechoso: ' + xMailer.trim());
    }
    if (headerGet(H, 'x-originating-ip')) {
      push('x-orig-ip', 'X-Originating-IP: ' + headerGet(H, 'x-originating-ip').replace(/[\[\]]/g, ''));
    }

    // --- Received
    if (hops.length === 0) { if (!noTransport) push('rcv-none', 'Sin cabeceras Received: mensaje inyectado localmente o cabeceras eliminadas'); }
    else if (hops.length === 1) push('rcv-one', 'Un único salto Received: entrega directa al MX');
    const bigDelay = hops.find(h => h.delaySeconds !== null && h.delaySeconds > 3600);
    if (bigDelay) push('rcv-delay', 'Salto con ' + Math.round(bigDelay.delaySeconds / 60) + ' min de retardo (hop ' + bigDelay.hop + ')');
    if (!dateHdr && !noTransport) push('date-missing', 'Sin cabecera Date');
    if (dateHdr && hops.length) {
      const first = hops.find(h => h.ts);
      const dts = Date.parse(dateHdr.replace(/\s*\([^)]*\)\s*$/, ''));
      if (first && !isNaN(dts) && Math.abs(first.ts - dts) > 48 * 3600 * 1000) {
        push('date-skew', 'Date difiere más de 48 h del primer Received: cabecera falsificada');
      }
    }
    const originIP = (() => {
      for (const h of hops) { if (h.publicIPs.length) return h.publicIPs[0]; }
      return null;
    })();

    // --- Asunto / cuerpo
    if (URGENCY.test(subject)) push('subj-urgency', 'Asunto con lenguaje de urgencia/presión');
    // Ojo: un reenvío (Fwd:/RV:) sí puede no tener In-Reply-To de forma legítima.
    // Solo cuenta cuando dice ser una respuesta.
    if (/^\s*re\s*:/i.test(subject) && !headerGet(H, 'in-reply-to') && !headerGet(H, 'references')) {
      push('subj-nothread', 'Simula responder a un hilo que nunca existió: no hay In-Reply-To ni References');
    }
    if (html) {
      if (/<form\b/i.test(html)) push('body-form', 'Formulario HTML embebido en el correo (captura de credenciales)');
      if (/type\s*=\s*["']?password/i.test(html)) push('body-password', 'Campo de contraseña en el HTML del correo');
      if (/<script\b/i.test(html)) push('body-script', 'Etiqueta <script> en el cuerpo');
      if (/<iframe\b/i.test(html)) push('body-iframe', 'iframe embebido');
      if (/http-equiv\s*=\s*["']?refresh/i.test(html)) push('body-refresh', 'meta refresh: redirección automatica');
      const invisible = html.match(/(font-size\s*:\s*0|display\s*:\s*none|visibility\s*:\s*hidden|color\s*:\s*#?f{3,6}\b)/gi);
      if (invisible && invisible.length >= 2 && !autentica) push('body-hidden', 'Texto oculto/invisible (' + invisible.length + ' ocurrencias): evasión de filtros');
      const textLen = html.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim().length;
      const imgs = (html.match(/<img\b/gi) || []).length;
      if (imgs > 0 && textLen < 120) push('body-image', 'Correo casi solo imagen (' + imgs + ' img, ' + textLen + ' chars): evasión de análisis textual');
      if (/&#x?[0-9a-f]{2,};/i.test(html) && (html.match(/&#x?[0-9a-f]{2,};/gi) || []).length > 40) {
        push('body-entities', 'Uso masivo de entidades HTML: ofuscacion');
      }
    }
    if (!html && !plain && attachments.length) push('body-empty', 'Cuerpo vacio con adjunto: patron de malware/spear-phishing');
    if (/(bitcoin|btc|usdt|ethereum|monero|wallet|seed phrase|frase semilla|criptomoneda)/i.test(textoVisible + ' ' + subject)) {
      push('body-crypto', 'Referencias a criptomonedas (extorsión o fraude de inversión)');
    }
    const pinta_bec = /(transferencia|wire transfer|iban|swift|cambio de cuenta|bank details|datos bancarios|nomina|payroll|pago urgente|urgent payment)/i.test(textoVisible + ' ' + subject);
    if (pinta_bec && (replyTo.length || alignment.dkim === false || FREEMAIL.has(fromOrg))) {
      push('body-bec', 'Patrón BEC: pide un pago o un cambio de datos bancarios y el remitente no es de fiar');
    }
    if (IBAN_RE.test(textoVisible) && pinta_bec) {
      push('body-iban', 'Da un número de cuenta (IBAN) dentro del correo para que hagas el ingreso ahí');
    }
    if (/(no me llames|no llames|no puedo hablar|estoy en una reunion|estoy en una reunión|no digas nada|es confidencial)/i.test(textoVisible)) {
      push('body-nocontacto', 'Pide que no le llames ni lo comentes: sirve para que nadie verifique la petición');
    }

    // --- Puntos de URLs y adjuntos
    const seenUrlFlags = new Set();
    for (const u of urls) {
      for (const f of u.flags) {
        const key = f.id + '|' + u.host;
        if (seenUrlFlags.has(key)) continue;
        seenUrlFlags.add(key);
        push(f.id, f.msg + ' -> ' + defang(u.url).slice(0, 160));
      }
    }
    for (const a of attachments) {
      for (const f of a.flags) push(f.id, f.msg + ' [' + a.filename + ']');
    }

    // --- Combinaciones: correlaciones que valen más que la suma de sus partes
    const disparadas = new Set(findings.map(f => f.id));
    for (const c of COMBOS) {
      if (c.si(disparadas)) findings.push({ id: c.id, msg: c.msg, cat: 'combinacion', sev: c.sev, points: c.pts });
    }

    // --- Score: suma dentro de cada categoría, cada categoría con su techo
    const desglose = Object.keys(CATEGORIAS).map(cat => {
      const dela = findings.filter(f => f.cat === cat);
      const bruto = dela.reduce((s, f) => s + (f.points || 0), 0);
      const techo = CATEGORIAS[cat].techo;
      return { cat, nombre: CATEGORIAS[cat].nombre, bruto, techo,
               puntos: Math.min(bruto, techo), reglas: dela.length };
    });
    const brutoCombos = findings.filter(f => f.cat === 'combinacion').reduce((s, f) => s + f.points, 0);
    if (brutoCombos) {
      desglose.push({ cat: 'combinacion', nombre: 'Combinaciones que encajan con un fraude conocido',
        bruto: brutoCombos, techo: TECHO_COMBOS, puntos: Math.min(brutoCombos, TECHO_COMBOS),
        reglas: findings.filter(f => f.cat === 'combinacion').length });
    }
    const score = Math.max(0, Math.min(100, desglose.reduce((s, d) => s + d.puntos, 0)));
    const verdict = UMBRALES.find(([min]) => score >= min)[1];

    // --- IOCs
    const iocDomains = new Set();
    const iocUrls = new Set();
    const iocIPs = new Set();
    const iocHashes = new Set();
    const iocEmails = new Set();
    for (const u of urls) { iocUrls.add(u.url); if (u.host && !isIP(u.host)) iocDomains.add(u.host); else if (u.host) iocIPs.add(u.host); }
    for (const h of hops) for (const ip of h.publicIPs) iocIPs.add(ip);
    for (const a of attachments) { if (a.sha256) iocHashes.add(a.sha256); else if (a.md5) iocHashes.add(a.md5); }
    for (const g of [from, replyTo, returnPath, sender]) for (const a of g) if (a.address) iocEmails.add(a.address);

    const iocs = {
      urls: Array.from(iocUrls), urlsDefanged: Array.from(iocUrls).map(defang),
      domains: Array.from(iocDomains), domainsDefanged: Array.from(iocDomains).map(defang),
      ips: Array.from(iocIPs), hashes: Array.from(iocHashes), emails: Array.from(iocEmails)
    };

    const interesting = ['from', 'reply-to', 'return-path', 'to', 'cc', 'bcc', 'subject', 'date',
      'message-id', 'in-reply-to', 'references', 'x-mailer', 'user-agent', 'x-originating-ip',
      'authentication-results', 'received-spf', 'dkim-signature', 'arc-authentication-results',
      'x-forefront-antispam-report', 'x-microsoft-antispam', 'x-spam-status', 'x-spam-score',
      'list-unsubscribe', 'content-type', 'mime-versión', 'x-priority', 'importance', 'sender',
      'x-sender', 'x-original-from', 'x-authenticated-sender', 'x-php-originating-script'];

    return {
      meta: {
        filename: meta.filename || null, sizeBytes: rawLatin1.length,
        analyzedAt: new Date().toISOString(), engine: 'PhishTriage 1.0'
      },
      score, verdict, scoreBreakdown: desglose,
      summary: {
        from: from[0] ? from[0].address : null,
        fromDisplay: from[0] ? from[0].name : null,
        fromOrgDomain: fromOrg || null,
        replyTo: replyTo.map(a => a.address),
        returnPath: returnPath[0] ? returnPath[0].address : null,
        to: to.map(a => a.address), cc: cc.map(a => a.address),
        subject, date: dateHdr, messageId,
        originIP, hops: hops.length,
        urlCount: urls.filter(u => u.tipo === 'enlace').length,
        resourceCount: urls.filter(u => u.tipo === 'recurso').length,
        attachmentCount: attachments.length
      },
      auth: {
        spf: auth.spf, dkim: auth.dkim, dmarc: auth.dmarc, compauth: auth.compauth,
        spfDomain: auth.spfDomain, dkimDomain: auth.dkimDomain, dmarcFrom: auth.dmarcFrom,
        alignment, dkimSignatures: auth.dkimSignatures, arcSeals: auth.arcChain, raw: auth.raw
      },
      headers: H.map(([k, v]) => ({ name: k, value: v, decoded: decodeRFC2047(v), interesting: interesting.indexOf(k.toLowerCase()) >= 0 })),
      received: hops,
      urls, attachments, findings, iocs,
      bodies: { plain: plain.slice(0, 200000), htmlLength: html.length, htmlSource: html.slice(0, 400000) },
      structure: describeStructure(root)
    };
  }

  function describeStructure(node, prefix) {
    const label = node.mime + (node.params.charset ? '; charset=' + node.params.charset : '') +
      (node.encoding && node.encoding !== '7bit' ? ' [' + node.encoding + ']' : '') +
      ((node.dispParams && node.dispParams.filename) ? ' -> ' + decodeRFC2047(node.dispParams.filename) : '');
    return { label, children: node.children.map(c => describeStructure(c)) };
  }

  // Solo lo que usan de verdad la interfaz y los tests. Todo lo demas es
  // interno: exportarlo era prometer una API que nadie llamaba.
  return { analyze, bytesToLatin1, defang, orgDomain, isPrivateIP, md5 };
});

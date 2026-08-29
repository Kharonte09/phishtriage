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

  function decodeRFC2047(input) {
    if (!input) return '';
    let s = String(input);
    s = s.replace(/(=\?[^?]+\?[BbQq]\?[^?]*\?=)\s+(?==\?)/g, '$1');
    return s.replace(/=\?([^?]+)\?([BbQq])\?([^?]*)\?=/g, (m, cs, enc, txt) => {
      try {
        const bytes = enc.toUpperCase() === 'B' ? b64ToBytes(txt) : latin1ToBytes(decodeQP(txt, true));
        return decodeBytes(bytes, cs);
      } catch (e) { return m; }
    });
  }

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


  const MULTI_SUFFIX = new Set('co.uk org.uk me.uk gov.uk ac.uk net.uk sch.uk com.es org.es gob.es edu.es nom.es com.ar com.br com.mx com.co com.pe com.cl com.ve com.uy com.au net.au org.au gov.au edu.au co.jp or.jp ne.jp ac.jp go.jp co.kr or.kr co.in net.in org.in gov.in co.za org.za com.tr gov.tr com.cn net.cn org.cn gov.cn com.tw com.hk com.sg com.my co.nz com.pt com.pl com.ua com.ru org.ru net.ru co.il com.sa com.eg com.ng'.split(' '));

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

  const SCRIPTS = [
    ['cirílico', /[\u0400-\u04FF\u0500-\u052F]/],
    ['griego',   /[\u0370-\u03FF\u1F00-\u1FFF]/],
    ['armenio',  /[\u0530-\u058F]/],
    ['latino',   /[A-Za-z\u00C0-\u024F]/]
  ];

  function normalizaLeet(s) {
    return String(s || '').toLowerCase()
      .replace(/rn/g, 'm').replace(/vv/g, 'w')
      .replace(/0/g, 'o').replace(/1/g, 'l').replace(/3/g, 'e')
      .replace(/4/g, 'a').replace(/5/g, 's').replace(/7/g, 't')
      .replace(/[^a-z]/g, '');
  }

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

  function dominioParecido(orgDomain) {
    if (!orgDomain) return null;
    const etiqueta = String(orgDomain).split('.')[0];
    if (!etiqueta || etiqueta.length < 4) return null;
    const norm = normalizaLeet(etiqueta);
    const crudo = String(etiqueta).toLowerCase().replace(/[^a-z]/g, );
    if (!norm) return null;
    for (const marca of BRANDS) {
      if (marca.length < 4) continue;
      if (crudo === marca) return null;
      if (norm === marca) return marca;
      if (norm.length > marca.length && norm.indexOf(marca) >= 0) return marca;
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
    if (depth > 30) {
      if (node.mime.startsWith('multipart/') || node.mime === 'message/rfc822') node.truncado = true;
      return node;
    }
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
    for (const k of ['spfDomain', 'dkimDomain', 'dmarcFrom']) {
      if (res[k] && /^(none|unknown|-)$/i.test(res[k])) res[k] = null;
    }
    res.arcChain = headerAll(headers, 'arc-seal').length;
    return res;
  }


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
    const chrono = hops.slice().reverse();
    for (let i = 0; i < chrono.length; i++) {
      const prev = chrono[i - 1];
      chrono[i].delaySeconds = (prev && prev.ts && chrono[i].ts) ? Math.round((chrono[i].ts - prev.ts) / 1000) : null;
      chrono[i].hop = i + 1;
    }
    return chrono;
  }


  const SHORTENERS = new Set('bit.ly tinyurl.com t.co goo.gl ow.ly is.gd buff.ly cutt.ly rb.gy shorturl.at rebrand.ly tiny.cc lnkd.in bl.ink t.ly shorte.st adf.ly v.gd trib.al mcaf.ee urlz.fr x.gd clck.ru'.split(' '));

  const REDIRECT_HOSTS = [/^clicktime\./i, /safelinks\.protection\.outlook\.com$/i, /urldefense\./i,
    /\.proofpoint\.com$/i, /\.mimecastprotect\.com$/i, /^r\./i, /^click\./i, /^link\./i, /^email\./i, /\.sendgrid\.net$/i];

  const CRED_WORDS = /(login|log-in|signin|sign-in|verify|verification|secure|account|update|confirm|password|passwd|credential|billing|invoice|payment|unlock|suspend|recover|auth|sso|mfa|otp|token|wallet|seed|kyc)/i;

  const RISKY_TLD = new Set('zip mov xyz top tk ml ga cf gq work click link country stream download loan review kim men date racing win bid quest cam rest buzz monster sbs cfd icu shop live fit'.split(' '));

  const BRANDS = 'microsoft office365 outlook onedrive sharepoint apple icloud google gmail amazon aws paypal netflix facebook instagram whatsapp linkedin dropbox docusign adobe santander bbva caixabank sabadell bankinter unicaja ing correos seur dhl fedex ups dgt aeat agenciatributaria seguridadsocial endesa iberdrola movistar vodafone binance coinbase metamask revolut wetransfer zoom teams chase hsbc'.split(' ');

  const FREEMAIL = new Set('gmail.com googlemail.com hotmail.com hotmail.es outlook.com outlook.es live.com yahoo.com yahoo.es aol.com protonmail.com proton.me gmx.com mail.com yandex.com icloud.com'.split(' '));

  const CARGOS = /\b(ceo|cfo|coo|cto|director|directora|direccion|dirección|gerente|presidente|presidenta|administrador|administradora|jefe|jefa|responsable|manager|head of)\b/i;

  const FILEHOSTS = new Set('drive.google.com docs.google.com dropbox.com wetransfer.com we.tl onedrive.live.com 1drv.ms mega.nz mediafire.com box.com sharefile.com sync.com pcloud.com terabox.com'.split(' '));

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

  function extractLinks(htmlText, plainText, dominiosPropios) {
    const propios = new Set((dominiosPropios || []).filter(Boolean));
    const found = new Map();
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
      if (p.userinfo) flags.push({ id: 'url-userinfo', sev: 'high', msg: 'Autoridad con "@" (' + p.userinfo + '@): oculta el host real' });
      if (SHORTENERS.has(od)) flags.push({ id: 'url-shortener', sev: 'medium', msg: 'Acortador de URL: destino oculto' });
      if (RISKY_TLD.has(tld)) flags.push({ id: 'url-tld', sev: 'medium', msg: 'TLD de alto abuso: .' + tld });
      if ((host.match(/\./g) || []).length >= 4) flags.push({ id: 'url-subdomains', sev: 'low', msg: 'Exceso de subdominios (' + host + ')' });
      const tokens = host.split(/[.\-_]/).filter(Boolean);
      const brandHit = BRANDS.find(b => tokens.includes(b) && !od.split('.')[0].startsWith(b));
      if (/^data:/i.test(p.url)) flags.push({ id: 'url-data', sev: 'high', msg: 'data: URI (HTML embebido)' });
      if (FILEHOSTS.has(host) || FILEHOSTS.has(od)) {
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
      const DEBILES = 'url-tld url-subdomains url-hosting-gratis'.split(' ');
      const enCasa = propios.has(od);
      const flagsFinales = enCasa ? flags.filter(f => DEBILES.indexOf(f.id) < 0) : flags;

      const PINCHABLES = 'html:a html:form html:refresh text'.split(' ');
      const tipo = Array.from(entry.sources).some(x => PINCHABLES.indexOf(x) >= 0) ? 'enlace' : 'recurso';

      return {
        url: p.url, defanged: defang(p.url), scheme: p.scheme, host, orgDomain: od, propio: enCasa, tipo,
        port: p.port, path: p.path.slice(0, 300), anchorTexts: texts,
        sources: Array.from(entry.sources), flags: flagsFinales
      };
    });
  }

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


  const EXEC_EXT = new Set('exe scr com pif cpl msi msp mst dll sys bat cmd ps1 psm1 vbs vbe js jse wsf wsh hta jar lnk inf reg scf application gadget msc apk appx chm url library-ms settingcontent-ms diagcab theme iqy slk ade adp mde accdb py sh'.split(' '));
  const MACRO_EXT = new Set('docm dotm xlsm xltm xlam pptm potm ppam sldm xll xlsb'.split(' '));
  const CONTAINER_EXT = new Set('zip 7z rar iso img vhd vhdx cab ace arj tar gz bz2 xz z lzh'.split(' '));
  const HTML_EXT = new Set('html htm shtml xhtml mht mhtml svg'.split(' '));

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
      if (HTML_EXT.has(ext)) flags.push({ id: 'att-html', sev: 'high', msg: 'Adjunto HTML/SVG: tipico de phishing local (smuggling)' });
      if (/\.[a-z0-9]{2,4}\s*\.[a-z0-9]{2,4}$/i.test(name)) flags.push({ id: 'att-double', sev: 'high', msg: 'Doble extensión en el nombre' });
      if (/[‪-‮⁦-⁩]/.test(name)) flags.push({ id: 'att-rtlo', sev: 'high', msg: 'Caracteres de control bidireccional (RTLO) en el nombre' });
      if (magic === 'PE/DOS ejecutable (MZ)' && !EXEC_EXT.has(ext)) flags.push({ id: 'att-mismatch', sev: 'high', msg: 'Cabecera MZ pero extensión .' + ext + ': tipo declarado falso' });
      if (magic === 'RTF' && ['rtf'].indexOf(ext) < 0) flags.push({ id: 'att-mismatch', sev: 'high', msg: 'Es un RTF disfrazado de .' + ext + ': vector habitual de exploits de Office' });
      if (magic === 'OLE2 (Office 97-2003)' && ['doc', 'xls', 'ppt'].indexOf(ext) < 0) flags.push({ id: 'att-ole', sev: 'medium', msg: 'Contenedor OLE2 con extensión .' + ext });
      const zip = inspeccionaZip(bytes);
      if (zip.cifrado) flags.push({ id: 'att-encrypted', sev: 'high', msg: 'Archivo comprimido con contraseña: ningún antivirus puede mirar dentro' });
      if (zip.anidado) flags.push({ id: 'att-archive-nested', sev: 'high', msg: (CONTAINER_EXT.has(extOf(zip.anidado)) ? 'Comprimido dentro de otro comprimido' : 'Programa dentro del comprimido') + ' (' + zip.anidado + '): se hace para esquivar el antivirus' });
      list.push({
        filename: name, mime: n.mime, declaredEncoding: n.encoding, disposition: n.disposition,
        size: bytes.length, sizeHuman: humanSize(bytes.length), magic, ext,
        md5: hashes.md5, sha1: hashes.sha1, sha256: hashes.sha256, flags
      });
    }
    return list;
  }

  const CATEGORIAS = {
    auth:       { techo: 30, nombre: 'Autenticación' },
    identidad:  { techo: 20, nombre: 'Identidad del remitente' },
    enlaces:    { techo: 20, nombre: 'Enlaces' },
    contenido:  { techo: 15, nombre: 'Contenido del mensaje' },
    adjuntos:   { techo: 10, nombre: 'Adjuntos' },
    transporte: { techo: 5, nombre: 'Transporte y cabeceras' }
  };

  const PESOS = {
    'dkim-fail':       { cat: 'auth', pts: 19, sev: 'high',  fuente: 'LR 41.5 (P 9.5% / H 0.0%)' },
    'dmarc-fail':      { cat: 'auth', pts: 19, sev: 'high',  fuente: 'LR 39.0 (P 7.8% / H 0.0%)' },
    'spf-fail':        { cat: 'auth', pts: 18, sev: 'high',  fuente: 'LR 32.8 (P 9.4% / H 0.1%)' },
    'spf-softfail':    { cat: 'auth', pts: 16, sev: 'medium', fuente: 'LR 26.3 (P 5.2% / H 0.0%)' },
    'spf-neutral':     { cat: 'auth', pts: 15, sev: 'medium', fuente: 'LR 18.9 (P 28.8% / H 1.3%)' },
    'dmarc-none':      { cat: 'auth', pts: 13, sev: 'medium', fuente: 'LR 12.4 (P 43.9% / H 3.3%)' },
    'compauth':        { cat: 'auth', pts: 12, sev: 'medium', fuente: 'a mano - veredicto de Microsoft, medida contaminada por el receptor' },

    'ok-arc':          { cat: 'auth', pts: -1, sev: 'info', fuente: 'a mano - reenvio legitimo; el 60% del phishing tambien lo activaba' },
    'ok-dmarc':        { cat: 'auth', pts: -1, sev: 'info', fuente: 'a mano - el 24% del phishing real pasa DMARC' },

    'dn-suplanta-propio': { cat: 'identidad', pts: 20, sev: 'high', fuente: 'LR 99.2 (P 5.9% / H 0.00%), recortado al techo' },
    'from-basura':     { cat: 'identidad', pts: 20, sev: 'high', fuente: 'LR 155.8 (P 6.1% / H 0.04%), recortado al techo' },
    'from-malformed':  { cat: 'identidad', pts: 20, sev: 'high', fuente: 'LR 93.4 (P 18.6% / H 0.0%)' },
    'from-tld':        { cat: 'identidad', pts: 13, sev: 'high', fuente: 'LR 13.3 (P 3.0% / H 0.0%)' },
    'dn-oficial-freemail': { cat: 'identidad', pts: 8, sev: 'high', fuente: 'LR 5.0 (P 0.4% / H <0.1%, regla de tres)' },
    'replyto-freemail':{ cat: 'identidad', pts: 6, sev: 'medium', fuente: 'LR 3.1 (P 0.6% / H 0.0%)' },
    'dn-mixed-script': { cat: 'identidad', pts: 5, sev: 'medium', fuente: 'LR 2.6 (P 0.5% / H 0.0%)' },
    'from-multi':      { cat: 'identidad', pts: 5, sev: 'medium', fuente: 'sin validar - varias direcciones reales en From' },
    'from-punycode':   { cat: 'identidad', pts: 12, sev: 'high', fuente: 'sin validar (0% en ambos corpus) - preciso por construccion' },
    'from-lookalike':  { cat: 'identidad', pts: 12, sev: 'high', fuente: 'sin validar - dominio que imita a una marca' },
    'from-freemail-cargo': { cat: 'identidad', pts: 8, sev: 'high', fuente: 'sin validar - patron BEC (FBI IC3)' },

    'url-tld':         { cat: 'enlaces', pts: 17, sev: 'high', fuente: 'LR 30.6 (P 6.1% / H 0.0%)' },
    'url-hosting-gratis': { cat: 'enlaces', pts: 7, sev: 'medium', fuente: 'LR 4.2 (P 8.4% / H 2.03%)' },
    'url-userinfo':    { cat: 'enlaces', pts: 10, sev: 'high', fuente: 'LR 7.9 (P 1.6% / H 0.0%)' },
    'url-shortener':   { cat: 'enlaces', pts: 10, sev: 'medium', fuente: 'LR 7.4 (P 13.3% / H 1.6%)' },
    'url-ip':          { cat: 'enlaces', pts: 6, sev: 'medium', fuente: 'LR 3.3 (P 5.9% / H 1.6%)' },
    'url-subdomains':  { cat: 'enlaces', pts: 5, sev: 'low', fuente: 'LR 2.7 (P 4.9% / H 1.6%)' },
    'url-rtlo':        { cat: 'enlaces', pts: 15, sev: 'high', fuente: 'sin validar (0% en ambos) - preciso por construccion' },
    'url-zerowidth':   { cat: 'enlaces', pts: 15, sev: 'high', fuente: 'sin validar (0% en ambos) - preciso por construccion' },
    'url-punycode':    { cat: 'enlaces', pts: 14, sev: 'high', fuente: 'sin validar (0% en ambos) - preciso por construccion' },
    'url-multi-at':    { cat: 'enlaces', pts: 12, sev: 'high', fuente: 'sin validar - preciso por construccion' },
    'url-data':        { cat: 'enlaces', pts: 10, sev: 'high', fuente: 'sin validar - preciso por construccion' },
    'url-mismatch':    { cat: 'enlaces', pts: 3, sev: 'low', fuente: 'LR 1.0 (P 3.5% / H 3.2%) - apenas distingue' },

    'body-image':      { cat: 'contenido', pts: 15, sev: 'high', fuente: 'LR 29.3 (P 5.8% / H 0.0%), recortado al techo' },
    'subj-urgency':    { cat: 'contenido', pts: 14, sev: 'medium', fuente: 'LR 15.5 (P 5.7% / H 0.2%)' },
    'body-buzon':      { cat: 'contenido', pts: 15, sev: 'high', fuente: 'LR 81.9 (P 5.4% / H 0.07%), recortado al techo' },
    'subj-premio':     { cat: 'contenido', pts: 12, sev: 'medium', fuente: 'LR 11.2 (P 4.4% / H 0.4%) - medido solo en ingles' },
    'body-crypto':     { cat: 'contenido', pts: 10, sev: 'medium', fuente: 'LR 7.7 (P 13.9% / H 1.6%)' },
    'body-callback':   { cat: 'contenido', pts: 6, sev: 'medium', fuente: 'LR 3.1 (P 0.6% / H 0.0%)' },
    'body-bec':        { cat: 'contenido', pts: 4, sev: 'medium', fuente: 'LR 2.2 (P 3.9% / H 1.6%)' },
    'body-hidden':     { cat: 'contenido', pts: 5, sev: 'low', fuente: 'LR 2.5 (P 37.5% / H 14.8%)' },
    'body-password':   { cat: 'contenido', pts: 12, sev: 'high', fuente: 'sin validar - preciso por construccion' },
    'body-iban':       { cat: 'contenido', pts: 8, sev: 'medium', fuente: 'sin validar - patron BEC' },
    'body-nocontacto': { cat: 'contenido', pts: 8, sev: 'medium', fuente: 'sin validar - patron BEC' },
    'body-refresh':    { cat: 'contenido', pts: 6, sev: 'medium', fuente: 'sin validar' },
    'body-empty':      { cat: 'contenido', pts: 0, sev: 'info', fuente: 'LR 0.4 - no distingue' },

    'att-exec':        { cat: 'adjuntos', pts: 10, sev: 'high', fuente: 'sin validar (0% en el corpus)' },
    'att-archive-nested': { cat: 'adjuntos', pts: 10, sev: 'high', fuente: 'sin validar (0% en el corpus)' },
    'att-macro':       { cat: 'adjuntos', pts: 10, sev: 'high', fuente: 'sin validar (0% en el corpus)' },
    'att-encrypted':   { cat: 'adjuntos', pts: 9, sev: 'high', fuente: 'sin validar (0% en el corpus)' },
    'att-rtlo':        { cat: 'adjuntos', pts: 9, sev: 'high', fuente: 'sin validar (0% en el corpus)' },
    'att-double':      { cat: 'adjuntos', pts: 8, sev: 'high', fuente: 'sin validar (0% en el corpus)' },
    'att-mismatch':    { cat: 'adjuntos', pts: 8, sev: 'high', fuente: 'sin validar (0% en el corpus)' },
    'att-senuelo':     { cat: 'adjuntos', pts: 10, sev: 'high', fuente: 'LR 17.4 (P 1.4% / H <0.1%, regla de tres), recortado al techo' },
    'att-html':        { cat: 'adjuntos', pts: 6, sev: 'medium', fuente: 'LR 0.6 (P 0.1% / H 0.0%) - pocos datos' },
    'att-ole':         { cat: 'adjuntos', pts: 4, sev: 'medium', fuente: 'sin validar' },

    'xmailer':         { cat: 'transporte', pts: 5, sev: 'medium', fuente: 'LR 17.4 (P 3.5% / H 0.0%), recortado por el techo' },
    'date-skew':       { cat: 'transporte', pts: 3, sev: 'low', fuente: 'LR 1.9 (P 1.2% / H 0.4%)' },
    'mime-profundo':   { cat: 'adjuntos', pts: 8, sev: 'high', fuente: 'sin validar (0% en los tres corpus) - evasion por construccion' },
    'rcv-none':        { cat: 'transporte', pts: 3, sev: 'low', fuente: 'sin validar' },
    'date-missing':    { cat: 'transporte', pts: 2, sev: 'low', fuente: 'sin validar' },
  };

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

  const UMBRALES = [[80, 'CRITICO'], [50, 'ALTO'], [18, 'MEDIO'], [0, 'BAJO']];


  const TELEFONO = /(?:\+\d{1,3}[\s.\-]?)?(?:\(?\d{3}\)?[\s.\-]?){2}\d{3,4}/;
  const LLAMADA = /(llam[ae]|ll[áa]menos|call us|call now|contact us at|para cancelar|to cancel|customer (care|service|support)|atenci[óo]n al cliente|soporte t[ée]cnico|help ?desk)/i;
  const COBRO = /(subscription|suscripci[óo]n|renewal|renovaci[óo]n|invoice|factura|order|pedido|charge|cargo|payment|pago|purchase|compra|receipt|recibo)/i;

  const URGENCY = /(urgente|inmediat|caduca|expira|vence|suspend|bloquea|bloqueo|último aviso|último aviso|accion requerida|acción requerida|24 horas|48 horas|impag|multa|sanción|sanción|premio|herencia|urgent|immediate|expires?|suspended|action required|final notice|overdue|last warning)/i;

  const PREMIO = /(has? ganado|ha sido premiad|premio|loter[ií]a|sorteo|has? sido seleccionad|you (have )?won|you'?re a winner|winner|jackpot|free spins?|freispiele|cashback|airdrop|gewonnen|gewinn|vinto|vincita|claim your (prize|bonus|reward)|reclama tu|congratulations[!,. ]|felicidades|prize|lottery|sweepstakes?|bonus (von|sichern))/i;

  const OFICIAL = /(notifica|aviso|atendimento|comunicado|no-?reply|nao-?responda|helpdesk|suporte|soporte|departamento|ouvidoria|cobran[cç]a|seguran[cç]a|protocolo|setor|central de|fatura|boleto|intima[cç])/i;

  const HOSTING_GRATIS = /(^|\.)(pages\.dev|workers\.dev|netlify\.app|vercel\.app|web\.app|firebaseapp\.com|glitch\.me|repl\.co|replit\.app|b-cdn\.net|ipfs\.io|ipfs\.dweb\.link|weebly\.com|wixsite\.com|github\.io|gitbook\.io|surge\.sh|000webhostapp\.com|r2\.dev|onrender\.com|codesandbox\.io|typedream\.app|framer\.app|softr\.app|carrd\.co)$|(^|\.)s3[.-][a-z0-9-]*\.amazonaws\.com$|(^|\.)blob\.core\.windows\.net$|(^|\.)storage\.googleapis\.com$/i;

  const BUZON = /(storage (is )?full|almost used up|used up your|mailbox (is )?(full|quota)|quota (exceeded|full)|password (will )?expire|expire[sd]? today|expiring password|reactivate your (account|mailbox)|verify your (account|mailbox|email)|validate your (account|mailbox)|held messages|messages? (are )?(on hold|pending release)|release (all )?messages|account (will be )?(suspend|deactivat|clos|terminat)|confirm your (account|identity|email)|update your (mailbox|account details)|revalidate|re-?activate|sign in to (keep|continue|avoid)|buz[oó]n (lleno|est[aá] lleno)|contrase[nñ]a (caduca|expira)|verifica tu cuenta|reactivar? tu cuenta)/i;

  function dominioBasura(dom) {
    const s = String(dom || '').split('.')[0];
    if (s.length < 8) return false;
    const digitos = (s.match(/\d/g) || []).length;
    const vocales = (s.match(/[aeiou]/gi) || []).length;
    return (digitos >= 3 && /[a-z]/i.test(s)) || vocales / s.length < 0.2;
  }

  async function analyze(rawLatin1, meta) {
    meta = meta || {};
    if (/^\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1/.test(rawLatin1)) {
      const e = new Error('Esto es un .msg de Outlook, no un correo que pueda leer. ' +
        'En Outlook: abre el correo, Archivo → Guardar como, y elige formato .eml. ' +
        'O más fácil: busca "ver origen del mensaje", copia todo y pégalo aquí con Ctrl+V.');
      e.formatoNoSoportado = 'msg';
      throw e;
    }
    const OTROS_FORMATOS = [
      [/^%PDF-/, 'un PDF'], [/^PK\x03\x04/, 'un ZIP (o un .docx/.xlsx, que son ZIP por dentro)'],
      [/^\x89PNG\r\n/, 'una imagen PNG'], [/^\xff\xd8\xff/, 'una imagen JPEG'],
      [/^GIF8[79]a/, 'una imagen GIF'], [/^\{\\rtf/, 'un documento RTF'],
      [/^MZ/, 'un ejecutable de Windows'], [/^\x1f\x8b/, 'un fichero comprimido gzip']
    ];
    for (const [magia, queEs] of OTROS_FORMATOS) {
      if (magia.test(rawLatin1)) {
        const e = new Error('Esto es ' + queEs + ', no un correo. Necesito el correo entero, ' +
          'con sus cabeceras: guárdalo como .eml, o abre "ver origen del mensaje", ' +
          'copia todo y pégalo aquí con Ctrl+V.');
        e.formatoNoSoportado = 'otro';
        throw e;
      }
    }

    const root = parseNode(rawLatin1, 0);
    const H = root.headers;
    if (!['from', 'received', 'subject', 'to', 'date', 'message-id'].some(h => headerGet(H, h))) {
      const e = new Error(rawLatin1.trim()
        ? 'Esto no parece un correo: no tiene ninguna cabecera (From, Subject, Received...). ' +
          'Si has pegado solo el texto del mensaje, necesito además la parte de arriba: ' +
          'busca "ver original" o "ver origen del mensaje" y copia todo.'
        : 'El fichero está vacío.');
      e.formatoNoSoportado = 'sin-cabeceras';
      throw e;
    }
    const findings = [];
    const push = (id, msg) => {
      const p = PESOS[id] || { cat: 'contenido', pts: 0, sev: 'info' };
      findings.push({ id, msg, cat: p.cat, sev: p.sev, points: p.pts, fuente: p.fuente || null });
    };

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

    const textParts = [], htmlParts = [];
    (function walk(n) {
      if (n.mime === 'text/plain' && n.disposition !== 'attachment') textParts.push(nodeText(n));
      else if (n.mime === 'text/html' && n.disposition !== 'attachment') htmlParts.push(nodeText(n));
      n.children.forEach(walk);
    })(root);
    const plain = textParts.join('\n\n');
    const html = htmlParts.join('\n\n');

    const urls = extractLinks(html, plain, [fromOrg, orgDomain(auth.dkimDomain || '')]);
    const textoVisible = (plain + ' ' + decodeEntities(html.replace(/<[^>]+>/g, ' ')))
      .replace(/\s+/g, ' ').trim();
    const attachments = await collectAttachments(root);

    const noTransport = auth.raw.length === 0 && hops.length === 0;


    // --- 1. ¿Autentica? ------------------------------------------------------
    const S = (v) => (v || '').toLowerCase();

    const arcOk = auth.arcChain > 0 && ['pass', 'none', null, ''].indexOf(S(auth.arc)) >= 0;
    const hayDmarc = ['pass', 'fail', 'none'].indexOf(S(auth.dmarc)) >= 0;
    const sueltos = !hayDmarc && !arcOk;

    if (S(auth.spf) === 'fail') { if (sueltos) push('spf-fail', 'SPF fail: el servidor emisor no está autorizado por el dominio del sobre'); }
    else if (S(auth.spf) === 'softfail') { if (sueltos) push('spf-softfail', 'SPF softfail'); }
    else if (S(auth.spf) === 'none' || S(auth.spf) === 'neutral') { if (!arcOk) push('spf-neutral', 'SPF ' + auth.spf + ': el dominio no publica política utilizable'); }

    if (S(auth.dkim) === 'fail' && sueltos) push('dkim-fail', 'DKIM fail: la firma no valida (contenido alterado o firma falsa)');

    if (S(auth.dmarc) === 'fail') { if (!arcOk) push('dmarc-fail', 'DMARC fail: no hay alineamiento con el dominio del From'); }
    else if (S(auth.dmarc) === 'none') push('dmarc-none', 'DMARC none: el dominio no publica política DMARC');
    else if (S(auth.dmarc) === 'pass') push('ok-dmarc', 'DMARC pass: el correo viene de donde dice venir');

    if (auth.compauth && ['fail', 'softpass', 'none'].indexOf(S(auth.compauth)) >= 0) {
      push('compauth', 'compauth=' + auth.compauth + ' (Microsoft marca autenticación compuesta débil)');
    }

    if (arcOk) push('ok-arc', 'Cadena ARC presente (' + auth.arcChain + ' sello(s)): el correo ha pasado por un reenviador que da fe de que autenticaba en origen');

    const alignment = { spf: null, dkim: null };
    if (fromOrg && auth.spfDomain) alignment.spf = orgDomain(auth.spfDomain) === fromOrg;
    if (fromOrg && auth.dkimDomain) alignment.dkim = orgDomain(auth.dkimDomain) === fromOrg;

    const autentica = S(auth.dmarc) === 'pass' || alignment.dkim === true || arcOk;

    // --- 2. ¿Quien escribe de verdad? ----------------------------------------
    if (replyTo[0] && from[0] && FREEMAIL.has(fromOrg) &&
        replyTo[0].address.toLowerCase() !== from[0].address.toLowerCase() &&
        (!replyTo[0].orgDomain || replyTo[0].orgDomain === fromOrg)) {
      push('replyto-freemail', 'La respuesta iría a ' + replyTo[0].address + ', otra cuenta distinta de la que envía');
    }
    if (from[0]) {
      const dn = from[0].name || '';
      const dnNorm = dn.toLowerCase().replace(/[^a-z0-9]/g, '');
      const brand = BRANDS.find(b => dnNorm.includes(b));
      const miDominio = to[0] && to[0].domain ? orgDomain(to[0].domain) : null;
      if (dn && miDominio && fromOrg !== miDominio &&
          dn.toLowerCase().includes(miDominio)) {
        push('dn-suplanta-propio', 'Se hace pasar por tu propio dominio (' + miDominio +
          ') pero escribe desde ' + fromOrg);
      }
      if (dominioBasura(from[0].domain)) {
        push('from-basura', 'El dominio del remitente parece generado a máquina: ' + from[0].domain);
      }
      if (dn && FREEMAIL.has(fromOrg) && (brand || OFICIAL.test(dn))) {
        push('dn-oficial-freemail', 'Firma como un departamento o una marca ("' + dn.slice(0, 40) +
          '") pero escribe desde un buzón gratuito: ' + fromOrg);
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
    }


    const xMailer = headerGet(H, 'x-mailer') || headerGet(H, 'user-agent') || '';
    if (/phpmailer|sendmail|python|swiftmailer|mass|bulk|axigen|smtplib|mailer\s*script/i.test(xMailer)) {
      push('xmailer', 'X-Mailer sospechoso: ' + xMailer.trim());
    }

    // --- Por donde ha pasado -------------------------------------------------
    if (hops.length === 0) { if (!noTransport) push('rcv-none', 'Sin cabeceras Received: mensaje inyectado localmente o cabeceras eliminadas'); }
    const bigDelay = hops.find(h => h.delaySeconds !== null && h.delaySeconds > 3600);
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

    // --- 4. ¿Que te pide? ---------------------------------------------------
    if (URGENCY.test(subject)) push('subj-urgency', 'Asunto con lenguaje de urgencia/presión');
    if (html) {
      if (/type\s*=\s*["']?password/i.test(html)) push('body-password', 'Campo de contraseña en el HTML del correo');
      if (/http-equiv\s*=\s*["']?refresh/i.test(html)) push('body-refresh', 'meta refresh: redirección automatica');
      const invisible = html.match(/(font-size\s*:\s*0|display\s*:\s*none|visibility\s*:\s*hidden|color\s*:\s*#?f{3,6}\b)/gi);
      if (invisible && invisible.length >= 2 && !autentica) push('body-hidden', 'Texto oculto/invisible (' + invisible.length + ' ocurrencias): evasión de filtros');
      const textLen = html.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim().length;
      const imgs = (html.match(/<img\b/gi) || []).length;
      if (imgs > 0 && textLen < 120) push('body-image', 'Correo casi solo imagen (' + imgs + ' img, ' + textLen + ' chars): evasión de análisis textual');
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
    if (urls.filter(u => u.tipo === 'enlace').length === 0 && TELEFONO.test(textoVisible) &&
        LLAMADA.test(textoVisible) && COBRO.test(textoVisible + ' ' + subject)) {
      push('body-callback', 'Te da un teléfono para cancelar un cobro que no has hecho, y ningún enlace: la estafa consiste en que llames');
    }
    if (/(no me llames|no llames|no puedo hablar|estoy en una reunion|estoy en una reunión|no digas nada|es confidencial)/i.test(textoVisible)) {
      push('body-nocontacto', 'Pide que no le llames ni lo comentes: sirve para que nadie verifique la petición');
    }
    if (PREMIO.test(subject)) {
      push('subj-premio', 'El asunto anuncia un premio, un sorteo o un bono que no has pedido');
    }
    if (BUZON.test(subject) || BUZON.test(textoVisible.slice(0, 2500))) {
      push('body-buzon', 'Dice que tu buzón se llena, que tu contraseña caduca o que tienes correo retenido: es la excusa más usada para que metas la contraseña');
    }
    for (const u of urls) {
      if (u.tipo === 'enlace' && HOSTING_GRATIS.test(u.host || '')) {
        push('url-hosting-gratis', 'El enlace lleva a una página alojada gratis (' + defang(u.host) +
          '), no a la web de la empresa que dice ser');
        break;
      }
    }
    if (urls.filter(u => u.tipo === 'enlace').length === 0 && attachments.length && textoVisible.length < 400) {
      push('att-senuelo', 'Cuatro líneas y un adjunto, sin un solo enlace: todo el mensaje está en el fichero para que lo abras');
    }
    const truncado = (function hay(n) { return !!n.truncado || n.children.some(hay); })(root);
    if (truncado) {
      push('mime-profundo', 'El mensaje anida partes tan hondo que he dejado de abrirlas: puede haber algo escondido ahí debajo');
    }

    // --- 3 y 5. ¿A donde te lleva? ¿Que trae? --------------------------------
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

    const disparadas = new Set(findings.map(f => f.id));
    for (const c of COMBOS) {
      if (c.si(disparadas)) findings.push({ id: c.id, msg: c.msg, cat: 'combinacion', sev: c.sev, points: c.pts });
    }

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

  return { analyze, bytesToLatin1, defang, orgDomain, isPrivateIP, md5 };
});

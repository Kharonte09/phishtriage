/*!
 * PhishTriage - enriquecimiento contra VirusTotal y AbuseIPDB.
 *
 * NUNCA hay claves escritas en el codigo. La configuracion se resuelve en este orden:
 *   1. window.PHISHTRIAGE_CONFIG  -> assets/config.local.js (ignorado por git, solo 127.0.0.1)
 *   2. localStorage               -> lo que el usuario escriba en el panel de ajustes
 *   3. nada                       -> el enriquecimiento queda desactivado
 *
 * Si se define proxyBase, las claves NO salen del navegador: las pone el proxy
 * (cli/proxy.py) desde variables de entorno. Es el modo recomendado y el unico
 * que funciona sin pelearse con CORS.
 */
(function (root) {
  'use strict';

  const LS_KEY = 'phishtriage.settings.v1';

  function loadSettings() {
    const fromFile = root.PHISHTRIAGE_CONFIG || {};
    let fromLS = {};
    try { fromLS = JSON.parse(localStorage.getItem(LS_KEY) || '{}'); } catch (e) {}
    return Object.assign({
      proxyBase: '', vtKey: '', abuseKey: '',
      vtBase: 'https://www.virustotal.com/api/v3',
      abuseBase: 'https://api.abuseipdb.com/api/v2',
      enabled: false, maxItems: 12, delayMs: 1000
    }, fromFile, fromLS);
  }

  function saveSettings(s) {
    const clean = {
      proxyBase: s.proxyBase || '', vtKey: s.vtKey || '', abuseKey: s.abuseKey || '',
      enabled: !!s.enabled, maxItems: s.maxItems || 12, delayMs: s.delayMs || 1000
    };
    localStorage.setItem(LS_KEY, JSON.stringify(clean));
    return clean;
  }

  function clearSettings() { localStorage.removeItem(LS_KEY); }

  const sleep = ms => new Promise(r => setTimeout(r, ms));

  function b64url(s) {
    const b = btoa(unescape(encodeURIComponent(s)));
    return b.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  async function req(url, headers) {
    let res;
    try {
      res = await fetch(url, { headers: headers || {}, mode: 'cors' });
    } catch (e) {
      const err = new Error('Peticion bloqueada (CORS o red). Usa el proxy local o el CLI.');
      err.kind = 'cors';
      throw err;
    }
    if (res.status === 401 || res.status === 403) { const e = new Error('Clave rechazada (' + res.status + ')'); e.kind = 'auth'; throw e; }
    if (res.status === 404) { const e = new Error('Sin datos en el servicio (404)'); e.kind = 'notfound'; throw e; }
    if (res.status === 429) { const e = new Error('Limite de peticiones alcanzado (429)'); e.kind = 'quota'; throw e; }
    if (!res.ok) { const e = new Error('HTTP ' + res.status); e.kind = 'http'; throw e; }
    return res.json();
  }

  function vtUrl(s, kind, value) {
    if (s.proxyBase) return s.proxyBase.replace(/\/$/, '') + '/vt/' + kind + '/' + encodeURIComponent(value);
    return s.vtBase.replace(/\/$/, '') + '/' + kind + '/' + encodeURIComponent(value);
  }

  function vtHeaders(s) { return s.proxyBase ? {} : { 'x-apikey': s.vtKey }; }

  function summarizeVT(json) {
    const a = (json && json.data && json.data.attributes) || {};
    const st = a.last_analysis_stats || {};
    return {
      malicious: st.malicious || 0, suspicious: st.suspicious || 0,
      harmless: st.harmless || 0, undetected: st.undetected || 0,
      reputation: a.reputation, tags: a.tags || [],
      names: a.names ? a.names.slice(0, 5) : undefined,
      typeDescription: a.type_description,
      categories: a.categories ? Object.values(a.categories).slice(0, 6) : undefined,
      creationDate: a.creation_date ? new Date(a.creation_date * 1000).toISOString().slice(0, 10) : undefined,
      registrar: a.registrar,
      lastAnalysis: a.last_analysis_date ? new Date(a.last_analysis_date * 1000).toISOString().slice(0, 16).replace('T', ' ') : undefined,
      asOwner: a.as_owner, country: a.country,
      link: json && json.data && json.data.id ? null : null
    };
  }

  async function vtLookup(s, kind, value) {
    const id = kind === 'urls' ? b64url(value) : value;
    const json = await req(vtUrl(s, kind, id), vtHeaders(s));
    const sum = summarizeVT(json);
    sum.permalink = kind === 'urls' ? 'https://www.virustotal.com/gui/url/' + b64url(value)
      : kind === 'files' ? 'https://www.virustotal.com/gui/file/' + value
        : kind === 'ip_addresses' ? 'https://www.virustotal.com/gui/ip-address/' + value
          : 'https://www.virustotal.com/gui/domain/' + value;
    return sum;
  }

  async function abuseLookup(s, ip) {
    const base = s.proxyBase
      ? s.proxyBase.replace(/\/$/, '') + '/abuseipdb/check?ipAddress=' + encodeURIComponent(ip) + '&maxAgeInDays=90'
      : s.abuseBase.replace(/\/$/, '') + '/check?ipAddress=' + encodeURIComponent(ip) + '&maxAgeInDays=90';
    const headers = s.proxyBase ? { Accept: 'application/json' } : { Accept: 'application/json', Key: s.abuseKey };
    const json = await req(base, headers);
    const d = (json && json.data) || {};
    return {
      abuseScore: d.abuseConfidenceScore, totalReports: d.totalReports,
      countryCode: d.countryCode, isp: d.isp, domain: d.domain,
      usageType: d.usageType, isTor: d.isTor, isWhitelisted: d.isWhitelisted,
      lastReportedAt: d.lastReportedAt,
      permalink: 'https://www.abuseipdb.com/check/' + ip
    };
  }

  /**
   * Enriquece un informe de PhishTriage. Devuelve un objeto con la misma forma
   * tanto si hay exito como si falla, para que el informe siga siendo util.
   * onProgress(hechas, total, etiqueta)
   */
  async function enrichReport(report, settings, onProgress) {
    const s = settings || loadSettings();
    const out = {
      provider: { virustotal: !!(s.proxyBase || s.vtKey), abuseipdb: !!(s.proxyBase || s.abuseKey) },
      via: s.proxyBase ? 'proxy: ' + s.proxyBase : 'directo desde el navegador',
      files: {}, urls: {}, domains: {}, ips: {}, errors: []
    };
    const max = s.maxItems || 12;
    const hashes = report.iocs.hashes.slice(0, max);
    const domains = report.iocs.domains.slice(0, max);
    const urls = report.urls.map(u => u.url).slice(0, max);
    const ips = report.iocs.ips.slice(0, max);

    const jobs = [];
    if (out.provider.virustotal) {
      for (const h of hashes) jobs.push(['files', h, () => vtLookup(s, 'files', h)]);
      for (const d of domains) jobs.push(['domains', d, () => vtLookup(s, 'domains', d)]);
      for (const u of urls) jobs.push(['urls', u, () => vtLookup(s, 'urls', u)]);
      for (const i of ips) jobs.push(['ips', i, () => vtLookup(s, 'ip_addresses', i)]);
    }
    const abuseJobs = out.provider.abuseipdb ? ips.map(i => ['abuse', i, () => abuseLookup(s, i)]) : [];

    let done = 0;
    const total = jobs.length + abuseJobs.length;
    for (const [bucket, key, fn] of jobs.concat(abuseJobs)) {
      try {
        const data = await fn();
        if (bucket === 'abuse') {
          out.ips[key] = Object.assign(out.ips[key] || {}, { abuseipdb: data });
        } else if (bucket === 'ips') {
          out.ips[key] = Object.assign(out.ips[key] || {}, { virustotal: data });
        } else {
          out[bucket][key] = { virustotal: data };
        }
      } catch (e) {
        out.errors.push({ target: key, bucket, kind: e.kind || 'error', message: e.message });
        if (e.kind === 'cors' || e.kind === 'auth') { done = total; break; }
      }
      done++;
      if (onProgress) onProgress(done, total, key);
      if (done < total) await sleep(s.delayMs || 1000);
    }
    out.completedAt = new Date().toISOString();
    return out;
  }

  root.PhishEnrich = { loadSettings, saveSettings, clearSettings, enrichReport, vtLookup, abuseLookup, b64url };
})(typeof globalThis !== 'undefined' ? globalThis : this);

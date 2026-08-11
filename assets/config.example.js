/*
 * Configuracion LOCAL de PhishTriage.
 *
 *   cp assets/config.example.js assets/config.local.js
 *
 * config.local.js esta en .gitignore: nunca se sube al repositorio.
 * Usalo solo para pruebas en 127.0.0.1. En produccion (GitHub Pages) deja que
 * cada usuario meta lo suyo en el panel de Ajustes, o apunta a un proxy.
 */
window.PHISHTRIAGE_CONFIG = {
  // Opcion A (recomendada): proxy local; las claves viven en el entorno del proxy.
  //   export VT_API_KEY=...  ABUSEIPDB_API_KEY=...  && python3 cli/proxy.py
  proxyBase: 'http://127.0.0.1:8787',

  // Opcion B: claves directas en el navegador. Solo para pruebas en local,
  // y aun asi te comeras el CORS de AbuseIPDB. Dejalo vacio si usas proxy.
  vtKey: '',
  abuseKey: '',

  // Cuantos IOCs de cada tipo consultar y cuanto esperar entre peticiones.
  // La API publica de VirusTotal permite 4 peticiones/minuto -> delayMs: 15000.
  maxItems: 12,
  delayMs: 1000
};

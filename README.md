# PhishTriage

Analizador de correos `.eml`. Traga un fichero y escupe el informe que normalmente
haces a mano: cabeceras parseadas, resultados de SPF/DKIM/DMARC con su alineamiento,
cadena de `Received` salto a salto, URLs extraídas y defanged, adjuntos con sus hashes,
y enriquecimiento opcional contra VirusTotal y AbuseIPDB.

Dos frontales sobre la misma lógica:

- **Web** (`index.html`): 100 % client-side. El `.eml` no se sube a ningún servidor,
  se parsea en la pestaña. Se hospeda gratis en GitHub Pages.
- **CLI** (`cli/phishtriage.py`): Python sin dependencias, salida de terminal, JSON o
  Markdown, y código de salida según el riesgo para encadenarlo en scripts.

**Demo: https://kharonte09.github.io/phishtriage/**

![tests](https://github.com/Kharonte09/phishtriage/actions/workflows/ci.yml/badge.svg)
![pages](https://github.com/Kharonte09/phishtriage/actions/workflows/pages.yml/badge.svg)

---

## Qué extrae

| Bloque | Detalle |
|---|---|
| Cabeceras | Todas, en orden de aparición, con RFC 2047 decodificado y las relevantes resaltadas |
| Autenticación | `spf` / `dkim` / `dmarc` / `compauth` de `Authentication-Results`, respaldo en `Received-SPF`, firmas `DKIM-Signature` (`d=`, `s=`, `a=`), sellos ARC |
| Alineamiento | Compara el dominio organizativo del `From` con `smtp.mailfrom` y `header.d` (PSL reducida para `co.uk`, `com.es`, etc.) |
| Cadena Received | Orden cronológico invertido, `from` → `by`, protocolo, IPs (marcando privadas), retardo entre saltos, primera IP pública como origen |
| Identidades | `From` / `Reply-To` / `Return-Path` / `Sender`, spoofing del nombre visible, marcas suplantadas, punycode, TLD de alto abuso |
| URLs | De HTML (`a`, `img`, `form`, `background`, `meta refresh`) y de texto plano; desajuste texto/href, IP directa, `@` en la autoridad, acortadores, puertos raros, palabras de robo de credenciales |
| Adjuntos | Nombre, MIME, tamaño, MD5 / SHA-1 / SHA-256, *magic bytes*, extensión ejecutable, doble extensión, macros de Office, RTLO, discordancia tipo/extensión |
| Cuerpo | `<form>`, campos `password`, `<script>`, `iframe`, `meta refresh`, texto invisible, correo solo-imagen |
| Score | Suma ponderada de indicios, tope 100: BAJO &lt;20, MEDIO 20-49, ALTO 50-79, CRÍTICO &ge;80 |
| Salidas | JSON completo, informe Markdown, lista de IOCs defanged, CSV de IOCs |

Los indicios no son un veredicto. El score sirve para priorizar la cola, no para
bloquear un dominio sin mirarlo.

---

## Web

Abrirla en local:

```bash
git clone https://github.com/Kharonte09/phishtriage.git
cd phishtriage
python3 -m http.server 8000
# http://127.0.0.1:8000
```

Sírvela por HTTP, no con `file://`: los hashes SHA usan WebCrypto, que solo existe en
contexto seguro (HTTPS o `localhost`). MD5 va en JS puro y funciona siempre.

Arrastra el `.eml`, suelta varios a la vez para trabajar en lote, o pega el correo en
bruto con `Ctrl+V`. El HTML del correo se muestra como código, **nunca se renderiza**:
así no se cargan las imágenes remotas ni se avisa al atacante de que has abierto el correo.

## CLI

```bash
python3 cli/phishtriage.py correo.eml                  # informe en terminal
python3 cli/phishtriage.py *.eml --json informes/      # lote a JSON
python3 cli/phishtriage.py correo.eml --md informe.md  # Markdown para el ticket
python3 cli/phishtriage.py correo.eml --headers        # + volcado de cabeceras
cat correo.eml | python3 cli/phishtriage.py -          # por stdin
```

Códigos de salida: `0` bajo, `1` medio, `2` alto, `3` crítico, `10` error. Útil en un hook:

```bash
python3 cli/phishtriage.py "$1" --quiet --json out/ || echo "revisar a mano"
```

---

## Enriquecimiento (VirusTotal + AbuseIPDB)

Consulta hashes de adjuntos, dominios, URLs e IPs. **En el repositorio no hay ninguna
clave**, y no debe haberla nunca.

### CLI

```bash
export VT_API_KEY=...
export ABUSEIPDB_API_KEY=...
python3 cli/phishtriage.py correo.eml --enrich --delay 15
```

O copia `cli/.env.example` a `cli/.env` (ignorado por git). `--delay 15` respeta el
límite de 4 peticiones/minuto de la API pública de VirusTotal; con clave de pago bájalo.

### Web

El navegador no puede llamar a AbuseIPDB directamente (no manda cabeceras CORS) y
VirusTotal tampoco es de fiar en ese sentido. Además, meter una clave en una página
pública es regalarla. Solución: un proxy en tu propia máquina.

```bash
export VT_API_KEY=... ABUSEIPDB_API_KEY=...
python3 cli/proxy.py                     # http://127.0.0.1:8787
```

Y en la web, **Ajustes → Proxy** → `http://127.0.0.1:8787`. Las claves se quedan en el
entorno del proxy; el navegador nunca las ve. El proxy escucha solo en loopback y acepta
peticiones de `localhost`; para usarlo desde tu GitHub Pages, arráncalo con
`--allow-origin https://kharonte09.github.io`.

Para trastear en local sin tocar el panel cada vez:

```bash
cp assets/config.example.js assets/config.local.js
# edítalo: proxyBase, o claves si estás en 127.0.0.1
```

`assets/config.local.js` está en `.gitignore`. Es el fichero de *pre*: nunca se sube.
Si aun así prefieres pegar tu clave en el panel de Ajustes, se guarda solo en el
`localStorage` de ese navegador — asume que es una clave quemable, personal y de solo
lectura, jamás la corporativa.

Y ojo con el enriquecimiento en un incidente real: consultar una URL en VirusTotal la
hace visible a terceros y puede avisar al atacante de que le has detectado.

---

## Despliegue

El workflow `.github/workflows/pages.yml` publica la web en cada push a `main` y activa
Pages solo la primera vez (`actions/configure-pages` con `enablement: true`), así que no
hay que tocar nada en *Settings*. No hay build ni dependencias: Pages sirve el HTML tal
cual, y `.nojekyll` evita que Jekyll se meta por medio.

Para desplegar a mano: pestaña **Actions → pages → Run workflow**.

Requisito: el repositorio debe ser público (Pages en repos privados es de plan de pago).

---

## Estructura

```
phishtriage/
├── index.html                 interfaz
├── assets/
│   ├── eml.js                 motor: MIME, cabeceras, auth, URLs, hashes, scoring
│   ├── enrich.js              cliente VT/AbuseIPDB y resolución de configuración
│   ├── app.js                 render y eventos
│   ├── styles.css
│   └── config.example.js      plantilla -> config.local.js (gitignored)
├── cli/
│   ├── phishtriage.py         CLI, misma lógica, sin dependencias
│   ├── proxy.py               proxy local para no exponer las claves
│   └── .env.example
├── samples/
│   ├── sample-phishing.eml    correo de phishing sintético (inofensivo)
│   └── make_sample.py         lo regenera
├── tests/run-tests.mjs        40 comprobaciones + paridad JS vs Python
└── .github/workflows/ci.yml
```

## Tests

```bash
node tests/run-tests.mjs
```

Comprueba las utilidades (dominio organizativo, defang, MD5, RFC 2047), los indicios que
debe detectar en el correo de ejemplo, que un correo inocuo sale BAJO, y que el CLI de
Python y el motor JS dan el **mismo score, los mismos hashes y el mismo número de
hallazgos**. Si tocas una heurística, tócala en los dos sitios o el test te lo dirá.

## Límites conocidos

- No valida criptográficamente DKIM: lee el resultado que puso el MTA receptor. Si el
  `.eml` viene sin `Authentication-Results`, no hay veredicto de autenticación que leer.
- La lista de sufijos públicos es reducida, no la PSL completa de Mozilla.
- No abre archivos comprimidos ni desofusca macros: para eso, sandbox.
- No sigue redirecciones ni resuelve acortadores. Es deliberado: seguir el enlace desde
  tu IP es avisar al atacante.
- `.msg` de Outlook no está soportado; expórtalo a `.eml` antes.

## Licencia

MIT.

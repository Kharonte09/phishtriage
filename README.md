# PhishTriage

Analizador de correos `.eml`. Traga un fichero y escupe el informe que normalmente
haces a mano: cabeceras parseadas, resultados de SPF/DKIM/DMARC con su alineamiento,
cadena de `Received` salto a salto, URLs extraídas y defanged, adjuntos con sus hashes,
y enriquecimiento opcional contra VirusTotal y AbuseIPDB desde el CLI.

Dos frontales sobre la misma lógica:

- **Web** (`index.html`): 100 % client-side. El `.eml` no se sube a ningún servidor,
  se parsea en la pestaña. Se hospeda gratis en GitHub Pages.
- **CLI** (`cli/phishtriage.py`): Python sin dependencias, salida de terminal, JSON o
  Markdown, y código de salida según el riesgo para encadenarlo en scripts.

**Demo: https://kharonte09.github.io/phishtriage/**

![tests](https://github.com/Kharonte09/phishtriage/actions/workflows/ci.yml/badge.svg)

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
| Score | Ponderación por categorías con techo (ver abajo): BAJO &lt;20, MEDIO 20-49, ALTO 50-79, CRÍTICO &ge;80 |
| Salidas | JSON completo, informe Markdown, lista de IOCs defanged, CSV de IOCs |

Los indicios no son un veredicto. El score sirve para priorizar la cola, no para
bloquear un dominio sin mirarlo.

### Cómo se pondera

Toda la ponderación vive en dos tablas al principio de `assets/eml.js` (`CATEGORIAS` y
`PESOS`), espejadas en `cli/phishtriage.py`. Para cambiar cuánto pesa algo, cambias un
número de la tabla y ya: no hay puntos sueltos por el código.

| Categoría | Techo |
|---|---|
| Autenticación (SPF/DKIM/DMARC y alineamiento) | 30 |
| Identidad del remitente | 20 |
| Enlaces | 20 |
| Adjuntos | 15 |
| Contenido del mensaje | 10 |
| Transporte y cabeceras | 5 |

Cada regla suma dentro de su categoría y **cada categoría tiene un techo**. Los techos
suman 100, así que la nota es una composición real: un correo solo se acerca a 100 si
falla en varios frentes a la vez, no por acumular quince pegas del mismo tipo. Antes se
sumaba todo a un único cubo y el 79 % de los puntos del correo de ejemplo no cambiaban
nada, porque ya estaba saturado con cinco reglas.

El informe incluye el desglose (`scoreBreakdown`): la pestaña **Hallazgos** lo pinta y el
CLI lo imprime en barras, con los puntos brutos al lado para que se vea cuánto ha
recortado el techo.

Los tests comprueban que las dos tablas no diverjan, que los techos sigan sumando 100 y
que las dos implementaciones disparen exactamente las mismas reglas sobre el mismo correo.

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

Solo en el CLI, y a propósito. Ni VirusTotal ni AbuseIPDB envían cabeceras CORS, así que
desde el navegador la petición muere antes de salir; y meter una clave de API en una
página pública es regalarla. La web resuelve esto por otro camino: la pestaña
**¿Qué hago?** enlaza a la ficha pública de cada hash, dominio e IP, que no necesita clave
ni registro.

```bash
export VT_API_KEY=...
export ABUSEIPDB_API_KEY=...
python3 cli/phishtriage.py correo.eml --enrich --delay 15
```

O copia `cli/.env.example` a `cli/.env` (ignorado por git). `--delay 15` respeta el límite
de 4 peticiones/minuto de la API pública de VirusTotal; con clave de pago bájalo.

En el repositorio no hay ninguna clave, y no debe haberla nunca: el CI falla si aparece
algo que lo parezca.

Y ojo con el enriquecimiento en un incidente real: consultar una URL en VirusTotal la hace
visible a terceros y puede avisar al atacante de que le has detectado.

---

## Despliegue

Pages está configurado como **Deploy from a branch** (`main`, carpeta `/ (root)`): cada push
a `main` se publica solo. No hay build ni dependencias, GitHub sirve el HTML tal cual y
`.nojekyll` evita que Jekyll se meta por medio.

Es a propósito que **no** haya un workflow de despliegue. La alternativa
(`actions/deploy-pages`) obliga a dar *Read and write permissions* al `GITHUB_TOKEN` de
Actions, y no compensa ampliar el radio de acción de un workflow para servir HTML estático.
Así el único workflow del repo es `tests`, declarado con `permissions: contents: read`:
no puede escribir nada aunque una dependencia comprometida lo intentara.

Requisito: el repositorio debe ser público (Pages en repos privados es de plan de pago).

---

## Estructura

```
phishtriage/
├── index.html                 interfaz
├── assets/
│   ├── eml.js                 motor: MIME, cabeceras, auth, URLs, hashes, ponderación
│   ├── app.js                 render y eventos
│   └── styles.css
├── cli/
│   ├── phishtriage.py         CLI, misma lógica, sin dependencias
│   └── .env.example
├── samples/
│   ├── sample-phishing.eml    correo de phishing sintético (inofensivo)
│   └── make_sample.py         lo regenera
├── tests/
│   ├── run-tests.mjs          46 comprobaciones + paridad JS vs Python
│   └── ui-test.mjs            30 comprobaciones de interfaz con jsdom
└── .github/workflows/ci.yml
```

## Tests

```bash
node tests/run-tests.mjs
```

Comprueba las utilidades (dominio organizativo, defang, MD5, RFC 2047), los indicios que
debe detectar en el correo de ejemplo, que un correo inocuo sale BAJO, y que el CLI de
Python y el motor JS **disparan exactamente las mismas reglas, con el mismo desglose por
categoría y los mismos hashes**. Además compara las dos tablas de ponderación y falla si
divergen. Si tocas una heurística, tócala en los dos sitios o el test te lo dirá.

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

## Modo "para no técnicos"

La primera pestaña del informe, **¿Qué hago?**, es la vista por defecto y no habla de
SPF, DKIM ni cadenas Received. Traduce los hallazgos a frases normales ("un enlace enseña
una dirección y lleva a otra"), da una lista de pasos concretos según el riesgo, y ofrece
botones que abren la ficha pública de cada dominio, IP y hash en VirusTotal y AbuseIPDB
**sin necesidad de clave ni de registrarse**.

Ese es el camino para alguien que solo quiere saber si puede fiarse de un correo. El
enriquecimiento por API (que sí necesita clave y proxy) es para el otro perfil: el que
está haciendo triaje de una cola de incidentes.

También hay, bajo el área de subida, una chuleta de cómo exportar el `.eml` desde Gmail,
Outlook, Apple Mail o Thunderbird, y la alternativa de pegar el correo en bruto.

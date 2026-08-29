# PhishTriage

Análisis de correos sospechosos en el navegador. Le sueltas un correo y te dice
si es un fraude, por qué, y qué hacer con él.

**→ https://kharonte09.github.io/phishtriage/**

![tests](https://github.com/Kharonte09/phishtriage/actions/workflows/ci.yml/badge.svg)

## Para quién es

Para cualquiera que haya recibido un correo raro y no sepa si fiarse. No hace
falta saber nada de informática: la primera pestaña se llama **¿Qué hago?** y
responde a eso, en castellano y sin siglas. Si eres del oficio, las demás traen
el detalle: cabeceras, SPF/DKIM/DMARC con alineamiento, cadena Received, URLs
defanged, hashes de adjuntos e IOCs.

## Tu correo no sale de tu ordenador

No es una web que "sube" tu correo a ningún sitio: es un programa que se descarga
tu navegador y se ejecuta en tu pestaña. No hay servidor ni base de datos ni nada
que registre lo que analizas. El código está aquí; no hace falta que te fíes de
mi palabra.

Tampoco se abre el correo: el HTML se muestra como texto, nunca se ejecuta. Así
no se cargan imágenes remotas ni se avisa al atacante de que lo has abierto.

## Cómo se usa

Consigue el fichero del correo, suéltalo en la página (o pégalo con `Ctrl+V`) y
lee la pestaña **¿Qué hago?**.

Para descargarlo: en **Gmail**, menú `⋮` → Descargar mensaje. En **Outlook web**,
abrir en ventana nueva → `⋮` → Guardar como. En **Thunderbird**, clic derecho →
Guardar como. En **Apple Mail** y **Outlook de escritorio**, arrastrarlo a una
carpeta. Si no te aclaras: abre el "mensaje original", copia todo y pégalo.

> Un `.msg` de Outlook no vale: es un contenedor OLE2, no un correo. La
> herramienta lo dice en vez de analizarlo mal.

## Qué mira

Quién lo envía de verdad (nombre visible contra dirección real, Reply-To y quién
lo entregó), a dónde llevan los enlaces, qué traen los adjuntos —tipo real,
hashes, ejecutables disfrazados, macros—, y qué dice el mensaje: prisa, amenazas,
premios, formularios de contraseña, peticiones de pago.

Y las combinaciones, que valen más que la suma de sus partes: un correo no es
sospechoso por venir de Gmail, ni por pedir una transferencia, ni por traer un
IBAN, sino por hacer las tres cosas a la vez.

## La nota

Cada indicio suma dentro de su categoría, y cada categoría tiene un techo. Los
techos suman 100, así que un correo solo se acerca al máximo si falla en varios
frentes, no por acumular quince pegas del mismo tipo.

| Categoría | Techo |  | Categoría | Techo |
|---|---|---|---|---|
| Autenticación (SPF/DKIM/DMARC) | 30 | | Contenido del mensaje | 15 |
| Identidad del remitente | 20 | | Adjuntos | 10 |
| Enlaces | 20 | | Transporte y cabeceras | 5 |
| | | | Combinaciones de fraude conocido | +22 |

BAJO menos de 20 · MEDIO 20-49 · ALTO 50-79 · CRÍTICO 80 o más.

## De dónde salen los números

No están puestos a ojo ni copiados de nadie: **salen de medir el motor contra
correo real**. Para cada regla se cuenta cuántas veces dispara en phishing y
cuántas en correo legítimo, y el cociente decide su peso:

```
LR  = P(dispara | phishing) / P(dispara | legítimo)
pts = redondeo( 3,5 × log2(LR) )
```

Una LR de 1 significa que el indicio no distingue nada, por grave que suene.
12.334 correos medidos: 8.613 de [Phishing Pot](https://github.com/rf-peixoto/phishing_pot)
(2023-25), 250 del `hard_ham` de [SpamAssassin](https://spamassassin.apache.org/old/publiccorpus/)
(2002, HTML comercial legítimo) y 3.471 de las [listas de Apache](https://lists.apache.org/)
(2025-26, con autenticación moderna). Ninguno de los dos legítimos vale solo: el
de 2002 es anterior a SPF/DKIM/DMARC y el moderno es texto plano. Para cada regla
se toma **el peor caso legítimo de los dos**.

Cada regla lleva en el código un campo `fuente` con sus porcentajes, y sale en la
pestaña de Hallazgos. Hay un test que falla si alguien añade una regla sin
declarar de dónde sale su peso.

### Qué dijo la medida

**Detección 58,4% con 0,1-0,4% de falsos positivos** — porcentaje de phishing que
llega a MEDIO o más; a ALTO o más llega el 19,5%. La primera versión anclaba los
pesos a SpamAssassin y Rspamd y detectaba el 2,1%: esos motores llegan a su
umbral sumando cientos de reglas más Bayes más listas negras de red, así que
importar sus pesos por regla sin importar su *cantidad* de reglas garantizaba no
llegar nunca.

**El 24% del phishing real pasa DMARC**, enviado desde tenants de Microsoft 365
comprometidos: autentica de verdad, y lo falso es quien escribe, no el sobre. Por
eso los pesos negativos que premiaban al correo autenticado están en su mínima
expresión, y por eso hay tres reglas que solo miran el texto (`subj-premio`,
`att-senuelo`, `dn-oficial-freemail`): son las únicas que le llegan al fraude
cuyo sobre es auténtico.

**Tres reglas de las que uno estaba orgulloso no distinguen nada:** que el texto
enseñe una dirección y el enlace vaya a otra (LR 1,0), que el nombre visible
suplante una marca (0,9) y que el enlace lleve a una página de identificarse
(0,1). La primera duele, porque es el caso de manual, pero tiene sentido: hoy
casi todo el correo se lee en el móvil, donde no se ve la URL de destino, y el
atacante ya no se molesta en disfrazarla.

**Lo que sí distingue** es que el dominio no publique DMARC (44% vs 3%) ni SPF
utilizable (29% vs 1%), los TLD baratos, los acortadores, las criptomonedas, la
urgencia y los premios en el asunto, el correo que es casi solo una imagen, y
sobre todo el `From` mal formado: una coma sin comillas en el nombre visible que
parte la cabecera en dos, en el 18,6% del phishing y en cero de 3.721 legítimos.

**Tres trampas en los datos**, por si alguien repite la medida. `compauth` daba
una LR enorme, pero solo la escribe Microsoft y el 98,5% del corpus de phishing
lo recibió Microsoft frente al 8,1% del legítimo: medía el buzón de destino, no
el fraude. El corpus legítimo moderno son listas de correo, que reescriben
`Reply-To` y rompen el alineamiento por diseño. Y **los dos corpus legítimos
están en inglés**, así que cualquier regla con palabras en español o portugués da
0% de falsos positivos por eso y no por ser buena: la regla de premios se pesó
midiendo *solo* sus términos ingleses (LR 11,2), y los demás idiomas amplían la
cobertura pero no el peso.

## Qué NO hace

- **No detecta cuentas comprometidas por el sobre.** Si un atacante entra en el
  correo real de tu proveedor y escribe desde ahí, todo autentica porque el
  correo *es* auténtico. Contra eso solo queda leer lo que dice el mensaje, que
  es lo que hacen las tres reglas de texto, y eso no llega a todo.
- **No abre los adjuntos ni sigue los enlaces.** Seguir el enlace desde tu
  conexión es avisar al atacante de que has picado.
- **No consulta VirusTotal automáticamente.** Te da botones para abrir la ficha
  pública de cada dominio, IP y hash, sin claves ni registro, y tú decides.
- **Es orientativo.** Ni detecta todo ni acierta siempre. Ante la duda, entra tú
  a la web oficial escribiendo la dirección a mano y llama al teléfono de siempre.

## Si te ha llegado uno de verdad

No pulses enlaces ni abras adjuntos. No respondas. Si ya metiste tu contraseña,
cámbiala desde otra pestaña entrando tú a la web oficial y activa la verificación
en dos pasos. En España, INCIBE atiende dudas en el **017**, gratis y
confidencial. Si hubo pérdida de dinero, se denuncia ante Policía Nacional o
Guardia Civil.

## Cómo está hecho

Cuatro ficheros y ninguna dependencia: `index.html` es la página,
`assets/parser.js` el motor (MIME, cabeceras, autenticación, URLs, hashes,
ponderación), `assets/ui.js` la interfaz y `assets/styles.css` los estilos.

```bash
git clone https://github.com/Kharonte09/phishtriage.git
cd phishtriage
python3 -m http.server 8000     # http://127.0.0.1:8000
```

Sírvelo por HTTP y no con `file://`: los hashes SHA usan WebCrypto, que solo
funciona en contexto seguro.

## Pruebas

```bash
node tests/test.mjs        # 63 pruebas del motor
npm install jsdom          # opcional: añade las de la interfaz
```

Comprueban que un phishing de manual salga CRÍTICO, que un boletín legítimo se
quede en BAJO, que el fraude del jefe —sin enlaces ni adjuntos— llegue a ALTO, y
que el HTML del correo nunca se ejecute. Se ejecutan solas en cada push.

Pero esos correos son sintéticos: sirven para que no se rompa nada, no para saber
si acierta. Para eso hace falta correo real:

```bash
node tools/corpus.mjs <carpeta>
node tools/corpus.mjs <carpeta> --esperado phishing|legitimo [--csv notas.csv]
node tools/corpus.mjs <carpeta-phishing> <carpeta-legitimo>
```

Lee `.eml` sueltos y buzones mbox. Con una carpeta saca el reparto de notas, en
qué se equivoca y cuánto dispara cada regla; con dos, la razón de verosimilitud
de cada indicio, que es lo que decide su peso.

Además de los corpus de arriba, lo más útil es tu propia carpeta de spam: actual,
en español y dirigida a ti. Un corpus de phishing lleva malware de verdad dentro:
el motor solo lee bytes, pero el antivirus va a protestar al descomprimirlo.
Descomprímelo aparte y no toques nada a mano.

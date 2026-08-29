# PhishTriage

Análisis de correos sospechosos en el navegador. Le sueltas un correo y te dice
si es un fraude, por qué, y qué hacer con él.

**→ https://kharonte09.github.io/phishtriage/**

![tests](https://github.com/Kharonte09/phishtriage/actions/workflows/ci.yml/badge.svg)

## Para quién es

Para cualquiera que haya recibido un correo raro y no sepa si fiarse. No hace
falta saber nada de informática: la primera pestaña se llama **¿Qué hago?** y
responde exactamente a eso, en castellano y sin siglas.

Si además eres del oficio, las otras pestañas traen el detalle completo:
cabeceras, SPF/DKIM/DMARC con alineamiento, cadena Received, URLs defanged,
hashes de adjuntos e IOCs.

## Tu correo no sale de tu ordenador

Esto no es una web que "sube" tu correo a ningún sitio. Es un programa que se
descarga tu navegador y se ejecuta dentro de tu pestaña. No hay servidor, no hay
base de datos, no hay nada que registre lo que analizas. El código está aquí:
puedes comprobarlo tú mismo, no hace falta que te fíes de mi palabra.

Tampoco se abre el correo: el HTML se muestra como texto, nunca se ejecuta. Así
no se cargan imágenes remotas ni se le avisa al atacante de que lo has abierto.

## Cómo se usa

1. Consigue el fichero del correo (abajo te explico cómo) o copia su texto.
2. Suéltalo en la página, o pégalo con `Ctrl+V`.
3. Lee la pestaña **¿Qué hago?**.

### Cómo descargo el correo

| Programa | Cómo |
|---|---|
| Gmail (web) | Abre el correo → menú `⋮` → **Descargar mensaje** |
| Outlook escritorio | Arrastra el correo al escritorio, o **Archivo → Guardar como** |
| Outlook web | Abre el correo en ventana nueva → `⋮` → **Guardar como** |
| Apple Mail | Arrastra el correo a una carpeta |
| Thunderbird | Clic derecho → **Guardar como → Archivo** |

Si no te aclaras: abre el "mensaje original" o "código fuente", selecciona todo,
cópialo y pégalo en la web con `Ctrl+V`. Funciona igual.

## Qué mira

- **Quién lo envía de verdad.** Compara el nombre que ves con la dirección real,
  con quién responde si contestas y con quién lo entregó al servidor. Detecta
  marcas suplantadas, dominios que imitan a otros y letras cambiadas.
- **A dónde llevan los enlaces.** El caso clásico: el texto pone una dirección y
  el enlace va a otra. También acortadores, dominios en punycode, enlaces a IPs
  y páginas que piden identificarse.
- **Qué traen los adjuntos.** Tipo real del fichero, hashes MD5/SHA-1/SHA-256,
  ejecutables disfrazados, doble extensión y documentos con macros.
- **Cómo está escrito.** Prisa, amenazas, formularios de contraseña dentro del
  correo, peticiones de pago con número de cuenta.
- **Combinaciones.** Hay patrones que valen más que la suma de sus partes: un
  correo no es sospechoso por venir de Gmail, ni por pedir una transferencia, ni
  por traer un IBAN, sino por hacer las tres cosas a la vez.

## La nota

Cada indicio suma dentro de su categoría, y cada categoría tiene un techo. Los
techos suman 100, así que un correo solo se acerca al máximo si falla en varios
frentes, no por acumular quince pegas del mismo tipo.

| Categoría | Techo |
|---|---|
| Autenticación (SPF/DKIM/DMARC) | 30 |
| Identidad del remitente | 20 |
| Enlaces | 20 |
| Contenido del mensaje | 15 |
| Adjuntos | 10 |
| Transporte y cabeceras | 5 |
| Combinaciones de fraude conocido | +22 |

BAJO menos de 20 · MEDIO 20-49 · ALTO 50-79 · CRÍTICO 80 o más.

### De dónde salen los números

No están puestos a ojo, ni copiados de nadie: **salen de medir el motor contra correo
real**. Para cada regla se cuenta cuántas veces dispara en phishing y cuántas en
correo legítimo, y el cociente decide su peso:

```
LR  = P(la regla dispara | phishing) / P(la regla dispara | legítimo)
pts = redondeo( 3,5 × log2(LR) )
```

Una LR de 1 significa que el indicio no distingue nada, por grave que suene. Una de
30 significa que aparece treinta veces más en el fraude que en el correo bueno.

Corpus usados, 12.334 correos en total:

| Corpus | n | Época | Qué aporta |
|---|---|---|---|
| [Phishing Pot](https://github.com/rf-peixoto/phishing_pot) | 8.613 | 2023-25 | phishing real de honeypot |
| [SpamAssassin `hard_ham`](https://spamassassin.apache.org/old/publiccorpus/) | 250 | 2002 | HTML comercial legítimo |
| [Listas de Apache](https://lists.apache.org/) | 3.471 | 2025-26 | legítimo con autenticación moderna |

Ninguno de los dos corpus legítimos vale por sí solo: el de 2002 tiene el HTML
comercial pero es anterior a SPF/DKIM/DMARC, y el moderno autentica pero es texto
plano. Para cada regla se toma **el peor caso legítimo de los dos**, para no
acreditar a una regla que solo parece buena porque a un corpus le falta ese género
de correo.

Cada regla lleva en el código un campo `fuente` con los porcentajes medidos, y sale
también en la pestaña de Hallazgos. Las que dicen `sin validar` son las que el
corpus no cubre; las que dicen `a mano` son las dos que hubo que poner a criterio
porque la medida estaba contaminada. Hay un test que falla si alguien añade una
regla sin declarar de dónde sale su peso.

Se regenera con:

```bash
node tools/verosimilitud.mjs <carpeta-phishing> <carpeta-legitimo>
```

### Qué dijo la medida

**Detección: del 2,1% al 56,3%, con un 0,1% de falsos positivos.** La versión
anterior anclaba los pesos a SpamAssassin y Rspamd, y eso estaba mal: esos motores
llegan a su umbral sumando cientos de reglas más Bayes más listas negras de red.
Este tiene sesenta reglas y ninguna consulta de red, así que importar sus pesos por
regla sin importar su *cantidad* de reglas garantizaba no llegar nunca.

**El 24% del phishing real pasa DMARC.** Se envía desde tenants de Microsoft 365
comprometidos, así que autentica de verdad: lo falso es quien escribe, no el sobre.
Los pesos negativos que premiaban al correo autenticado se activaban en el 60% del
phishing, así que están en la mínima expresión.

**Tres reglas de las que uno estaba orgulloso no distinguen nada:**

| Regla | Phishing | Legítimo | LR |
|---|---|---|---|
| `url-mismatch` — el texto enseña una dirección y el enlace va a otra | 3,5% | 3,2% | 1,0 |
| `dn-brand` — el nombre visible suplanta una marca | 9,8% | 11,1% | 0,9 |
| `url-creds` — enlace a una página de identificarse | 6,7% | 53,2% | 0,1 |

La primera duele, porque es el caso que encabeza este README. Tiene sentido: hoy
casi todo el correo se lee en el móvil, donde no se ve la URL de destino, y el
atacante ya no se molesta en disfrazarla.

**Lo que sí distingue** es que el dominio no publique DMARC (44% vs 3%), que no
publique SPF utilizable (29% vs 1%), los TLD baratos, los acortadores, las
criptomonedas, la urgencia en el asunto, el correo que es casi solo una imagen, y
sobre todo el `From` mal formado: una coma sin comillas en el nombre visible que
parte la cabecera en dos, presente en el 18,6% del phishing y en cero de los 3.721
correos legítimos.

**Dos trampas en los datos**, por si alguien repite la medida. `compauth` daba una
LR enorme, pero es una cabecera que solo escribe Microsoft, y el 98,5% del corpus de
phishing lo recibió Microsoft frente al 8,1% del legítimo: medía el buzón de
destino, no el fraude. Y el corpus legítimo moderno son listas de correo, que
reescriben `Reply-To` y rompen el alineamiento por diseño.


## Qué NO hace

Conviene decirlo claro:

- **No detecta cuentas comprometidas.** Si un atacante entra en el correo real de
  tu proveedor y te escribe desde ahí, todo autentica correctamente porque el
  correo *es* auténtico. Ninguna herramienta que mire cabeceras resuelve eso.
- **No abre los adjuntos ni sigue los enlaces.** Es deliberado: seguir el enlace
  desde tu conexión es avisar al atacante de que has picado el anzuelo.
- **No consulta VirusTotal automáticamente.** Te da botones para abrir la ficha
  pública de cada dominio, IP y hash, sin claves ni registro, y tú decides.
- **Es un análisis automático y orientativo.** Acierta con los fraudes de manual.
  Ni detecta todo ni acierta siempre. Ante la duda, entra tú a la web oficial
  escribiendo la dirección a mano y llama al teléfono de siempre.

## Si te ha llegado uno de verdad

No pulses enlaces ni abras adjuntos. No respondas. Si ya metiste tu contraseña,
cámbiala desde otra pestaña entrando tú a la web oficial y activa la verificación
en dos pasos. En España, INCIBE atiende dudas en el **017**, gratis y
confidencial. Si hubo pérdida de dinero, se denuncia ante Policía Nacional o
Guardia Civil.

## Cómo está hecho

Cuatro ficheros y ninguna dependencia:

| Fichero | Qué hace |
|---|---|
| `index.html` | la página |
| `assets/parser.js` | el motor: MIME, cabeceras, autenticación, URLs, hashes, ponderación |
| `assets/ui.js` | la interfaz: convierte el análisis en algo legible |
| `assets/styles.css` | los estilos, en claro y oscuro según el sistema |
| `tests/test.mjs` | las pruebas |



Para abrirlo en local:

```bash
git clone https://github.com/Kharonte09/phishtriage.git
cd phishtriage
python3 -m http.server 8000
# http://127.0.0.1:8000
```

Sírvelo por HTTP y no con `file://`: los hashes SHA usan WebCrypto, que solo
funciona en contexto seguro (HTTPS o localhost).

## Probarlo contra un corpus de verdad

Los correos de `tests/test.mjs` son sinteticos: sirven para que no se rompa
nada, no para saber si acierta. Para eso hace falta correo real.

```bash
node tools/corpus.mjs <carpeta>
node tools/corpus.mjs <carpeta> --esperado phishing
node tools/corpus.mjs <carpeta> --esperado legitimo --csv notas.csv
```

Lee `.eml` sueltos y buzones mbox, saca el reparto de notas y, si le dices que
esperabas, los correos en los que se equivoca y que reglas mandan en ellos.
Tambien cuenta cuanto dispara cada regla sobre todo el corpus: con eso y un
corpus de cada clase sale la razon de verosimilitud de cada indicio, que es lo
que de verdad deberia decidir su peso.

De donde sacar correos:

| Fuente | Qué trae |
|---|---|
| [SpamAssassin public corpus](https://spamassassin.apache.org/old/publiccorpus/) | ham y spam en crudo, con cabeceras. El `hard_ham` es correo legítimo con pinta de spam: justo donde salen los falsos positivos |
| [Phishing Pot](https://github.com/rf-peixoto/phishing_pot) | ~4.000 `.eml` de phishing recogidos en honeypots, ya anonimizados |
| [Nazario phishing corpus](https://monkey.org/~jose/phishing/) | el clásico, mbox de phishing, viejo pero con cabeceras completas |
| [Enron](https://www.cs.cmu.edu/~enron/) | medio millón de correos internos legítimos |
| Tu carpeta de spam | lo más útil de todo: actual, en español y dirigido a ti |

Un corpus de phishing lleva malware de verdad dentro. El motor no abre adjuntos
ni sigue enlaces -solo lee bytes-, pero el antivirus va a protestar al
descomprimirlo. Descomprimelo en una carpeta aparte y no toques nada a mano.

## Pruebas

```bash
node tests/test.mjs                  # el motor
npm install jsdom                    # opcional
node tests/test.mjs                  # motor + interfaz
```

Comprueba que un phishing de manual salga CRÍTICO, que un boletín legítimo se
quede en BAJO, que el fraude del jefe —sin enlaces ni adjuntos— llegue a ALTO, y
que el HTML del correo nunca se ejecute. Se ejecutan solas en cada push.

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

### Cómo sacar el fichero del correo

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
| Adjuntos | 15 |
| Contenido del mensaje | 10 |
| Transporte y cabeceras | 5 |
| Combinaciones de fraude conocido | +20 |

BAJO menos de 20 · MEDIO 20-49 · ALTO 50-79 · CRÍTICO 80 o más.

La ponderación está en dos tablas al principio de `assets/parser.js`. Si algo
debería pesar más o menos, se cambia un número y ya.

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

index.html la página
assets/parser.js el motor: MIME, cabeceras, autenticación, URLs, hashes, ponderación
assets/ui.js la interfaz: convierte el análisis en algo legible
assets/styles.css los estilos
tests/test.mjs las pruebas



Para abrirlo en local:

```bash
git clone https://github.com/Kharonte09/phishtriage.git
cd phishtriage
python3 -m http.server 8000
# http://127.0.0.1:8000
```

Sírvelo por HTTP y no con `file://`: los hashes SHA usan WebCrypto, que solo
funciona en contexto seguro (HTTPS o localhost).

## Pruebas

```bash
node tests/test.mjs                  # el motor
npm install jsdom                    # opcional
node tests/test.mjs                  # motor + interfaz
```

Comprueba que un phishing de manual salga CRÍTICO, que un boletín legítimo se
quede en BAJO, que el fraude del jefe —sin enlaces ni adjuntos— llegue a ALTO, y
que el HTML del correo nunca se ejecute. Se ejecutan solas en cada push.

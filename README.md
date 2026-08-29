# PhishTriage

Le sueltas un correo sospechoso y te dice si es un fraude, por qué, y qué hacer.

**→ https://kharonte09.github.io/phishtriage/**

![tests](https://github.com/Kharonte09/phishtriage/actions/workflows/ci.yml/badge.svg)

## Tu correo no sale de tu ordenador

No es una web que "sube" tu correo a ningún sitio: es un programa que se descarga
tu navegador y se ejecuta en tu pestaña. No hay servidor ni base de datos ni nada
que registre lo que analizas.

Tampoco se abre el correo: el HTML se muestra como texto, nunca se ejecuta. Así
no se cargan imágenes remotas ni se avisa al atacante de que lo has abierto.

## Cómo se usa

Consigue el fichero del correo, suéltalo en la página (o pégalo con `Ctrl+V`) y
lee la pestaña **¿Qué hago?**. No hace falta saber nada de informática; el resto
de pestañas traen el detalle técnico para quien lo quiera.

Para descargarlo: en **Gmail**, menú `⋮` → Descargar mensaje. En **Outlook web**,
abrir en ventana nueva → `⋮` → Guardar como. En **Thunderbird**, clic derecho →
Guardar como. Si no te aclaras, abre el "mensaje original", copia todo y pégalo.

> Un `.msg` de Outlook no vale: es un contenedor, no un correo. La herramienta te
> lo dice en vez de analizarlo mal.

## Qué mira

Las mismas cinco preguntas que se hace un analista, en el mismo orden. Cada
respuesta sospechosa suma puntos, y cada bloque tiene un techo para que ningún
tipo de pega dispare la nota por sí solo.

| | Techo |
|---|---|
| ¿Autentica? — SPF, DKIM, DMARC | 30 |
| ¿Quién escribe de verdad? — From, Reply-To, el dominio | 20 |
| ¿A dónde te lleva? — los enlaces | 20 |
| ¿Qué te pide? — el texto del mensaje | 15 |
| ¿Qué trae? — los adjuntos | 10 |
| ¿Por dónde ha pasado? — cabeceras de transporte | 5 |
| Combinaciones de fraude conocido | +22 |

BAJO menos de 18 · MEDIO 18-49 · ALTO 50-79 · CRÍTICO 80 o más.

Hay además combinaciones que valen más que la suma de sus partes: un correo no es
sospechoso por venir de Gmail, ni por pedir una transferencia, ni por traer un
IBAN, sino por hacer las tres cosas a la vez.

## De dónde salen los números

Los pesos no están puestos a ojo: **salen de medir el motor contra correo real**.
Para cada regla se cuenta cuántas veces dispara en phishing y cuántas en correo
legítimo, y el cociente decide su peso.

```
LR  = P(dispara | phishing) / P(dispara | legítimo)
pts = redondeo( 3,5 × log2(LR) )
```

Regla de la casa: **si un indicio no suma puntos, no está en el código.** Había
32 que sonaban graves y no distinguían nada —"el enlace lleva a una página de
identificarse" disparaba en el 53% del correo legítimo— y se fueron.

| Corpus de phishing | n | Detección |
|---|---|---|
| [Phishing Pot](https://github.com/rf-peixoto/phishing_pot) 2023-25 | 8.613 | 68,2% |
| [Nazario](https://monkey.org/~jose/phishing/) 2023-25 | 1.303 | 51,6% |

| Corpus legítimo | n | Falsos positivos |
|---|---|---|
| [SpamAssassin](https://spamassassin.apache.org/old/publiccorpus/) `easy_ham` + `hard_ham` | 4.150 | 0,1% |
| [Listas de Apache](https://lists.apache.org/) 2025-26 | 3.471 | 0,3% |

Detección = llega a MEDIO o más. Los dos corpus de phishing son de fuentes
independientes y la diferencia entre ellos importa: buena parte de lo que detecta
en el primero depende de cabeceras que escribe **el buzón que recibe**, no el
atacante. Phishing Pot lo recibió Microsoft; Nazario, un servidor Debian. La
cifra honesta está entre las dos.

Cada regla lleva en el código un campo `fuente` con sus porcentajes medidos, y
hay un test que falla si alguien añade una sin declararlo.

## Qué NO hace

- **No detecta cuentas comprometidas por el sobre.** Si un atacante entra en el
  correo real de tu proveedor, todo autentica porque el correo *es* auténtico.
  Contra eso solo queda leer lo que dice el mensaje, y eso no llega a todo.
- **No abre los adjuntos ni sigue los enlaces.** Seguirlos desde tu conexión es
  avisar al atacante de que has picado.
- **Es orientativo.** Ni detecta todo ni acierta siempre. Ante la duda, entra tú
  a la web oficial escribiendo la dirección a mano y llama al teléfono de siempre.

## Si te ha llegado uno de verdad

No pulses enlaces ni abras adjuntos. No respondas. Si ya metiste tu contraseña,
cámbiala desde otra pestaña entrando tú a la web oficial y activa la verificación
en dos pasos. En España, INCIBE atiende en el **017**, gratis y confidencial. Si
hubo pérdida de dinero, se denuncia ante Policía Nacional o Guardia Civil.

## Cómo está hecho

Cuatro ficheros y ninguna dependencia: `index.html` es la página,
`assets/parser.js` el motor, `assets/ui.js` la interfaz y `assets/styles.css` los
estilos.

```bash
git clone https://github.com/Kharonte09/phishtriage.git
cd phishtriage
python3 -m http.server 8000     # http://127.0.0.1:8000
```

Sírvelo por HTTP y no con `file://`: los hashes SHA usan WebCrypto, que solo
funciona en contexto seguro.

## Pruebas

```bash
node tests/test.mjs        # 71 pruebas
npm install jsdom          # opcional: añade las de la interfaz
```

Los correos de prueba son sintéticos: sirven para que no se rompa nada, no para
saber si acierta. Para eso hace falta correo real:

```bash
node tools/corpus.mjs <carpeta> --esperado phishing|legitimo
node tools/corpus.mjs <carpeta-phishing> <carpeta-legitimo>
```

Con una carpeta saca el reparto de notas y en qué se equivoca; con dos, la razón
de verosimilitud de cada indicio, que es lo que decide su peso. Lee `.eml`
sueltos y buzones mbox.

Un corpus de phishing lleva malware de verdad dentro: el motor solo lee bytes,
pero el antivirus va a protestar al descomprimirlo. Descomprímelo aparte.

## Licencia

[MIT](LICENSE). Úsalo, cópialo y modifícalo, también en proyectos comerciales;
solo se pide mantener el aviso de autoría. Va sin garantías.

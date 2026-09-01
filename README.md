# PhishTriage

Analiza un correo sospechoso e indica si se trata de un fraude, por qué motivos
y qué hacer.

**→ https://kharonte09.github.io/phishtriage/**

![tests](https://github.com/Kharonte09/phishtriage/actions/workflows/ci.yml/badge.svg)

## Uso

Arrastra el fichero del correo a la página, o pega el mensaje completo con
`Ctrl+V`, y consulta la pestaña **¿Qué hago?**. El resto de pestañas contienen
el detalle técnico.

Para obtener el fichero: en Gmail, `⋮` → *Descargar mensaje*; en Thunderbird,
clic derecho → *Guardar como*; en Outlook de escritorio, arrastrando el correo
al escritorio. Un `.msg` de Outlook no sirve: es un contenedor, no un correo, y
la herramienta lo detecta y lo advierte en lugar de analizarlo mal.

No hay servidor ni base de datos. El análisis se ejecuta en el navegador, y el
HTML del correo se muestra como código y nunca se ejecuta: no se cargan imágenes
remotas ni se informa al remitente de que el mensaje se ha abierto.

## Qué analiza

Seis bloques de comprobaciones, cada uno con un techo de puntos para que ningún
tipo de indicio determine por sí solo la puntuación: autenticación (SPF, DKIM,
DMARC, ARC), identidad del remitente, enlaces, contenido, adjuntos y transporte.
A ellos se suma un bloque de combinaciones que encajan con fraudes conocidos.

La puntuación resultante se traduce en cuatro niveles: BAJO, MEDIO, ALTO y
CRÍTICO. Los indicios se suman: un correo no resulta sospechoso por venir de
Gmail, ni por solicitar una transferencia, ni por incluir un IBAN, sino por las
tres cosas a la vez.

## De dónde salen los pesos

Cada regla lleva en el código un campo `fuente` que declara el origen de su
peso. Los pesos medidos salen de la razón de verosimilitud entre la frecuencia
con que la regla dispara sobre un corpus de phishing y sobre uno de correo
legítimo; el resto se marca como *sin validar* o *pocos casos* y su peso está
fijado por criterio. Una regla que no distingue tiene peso cero: aparece en el
informe como observación, pero no puntúa.

Los corpus no se incluyen en el repositorio. `tools/corpus.mjs` realiza la
medición sobre los que tenga cada cual:

```bash
node tools/corpus.mjs <carpeta> --esperado phishing|legitimo   # reparto de notas y fallos
node tools/corpus.mjs <carpeta-phishing> <carpeta-legitimo>    # razón de verosimilitud por regla
```

## Limitaciones

No detecta cuentas comprometidas: si un atacante accede al buzón real, el correo
autentica correctamente porque *es* auténtico. Tampoco abre los adjuntos ni
visita los enlaces, así que no sabe qué hay al otro lado.

El resultado es orientativo. Ante la duda, accede a la web oficial escribiendo
la dirección y llama al teléfono habitual. Si ya has introducido la contraseña,
cámbiala, activa la verificación en dos pasos y llama al **017**, el teléfono
gratuito de INCIBE.

## Desarrollo

Cuatro ficheros y ninguna dependencia: `index.html`, `assets/parser.js` (el
motor), `assets/ui.js` (la interfaz) y `assets/styles.css`. Sírvelo por HTTP y
no con `file://`: los hashes SHA se calculan con WebCrypto, que requiere un
contexto seguro.

```bash
python3 -m http.server 8000          # http://127.0.0.1:8000
node tests/test.mjs                  # pruebas del motor
npm i jsdom && node tests/test.mjs   # pruebas del motor y de la interfaz
```

Los correos de las pruebas son sintéticos: comprueban que el motor hace lo que
dice, no cuánto acierta. Eso último requiere correo real y lo mide
`tools/corpus.mjs`.

## Licencia

[MIT](LICENSE): uso, copia y modificación libres, también en proyectos
comerciales, manteniendo el aviso de autoría. Sin garantías.

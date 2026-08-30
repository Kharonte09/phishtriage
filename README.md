# PhishTriage

Le sueltas un correo sospechoso y te dice si parece un fraude, por qué, y qué
hacer.

**→ https://kharonte09.github.io/phishtriage/**

![tests](https://github.com/Kharonte09/phishtriage/actions/workflows/ci.yml/badge.svg)

## Cómo se usa

Suelta el fichero del correo en la página, o pega el mensaje entero con
`Ctrl+V`, y lee la pestaña **¿Qué hago?**. El resto de pestañas traen el detalle
técnico.

Para conseguir el fichero: en Gmail, `⋮` → *Descargar mensaje*; en Thunderbird,
clic derecho → *Guardar como*; en Outlook de escritorio, arrastrando el correo
al escritorio. Un `.msg` de Outlook no sirve, porque es un contenedor y no un
correo: la herramienta lo detecta y lo dice en vez de analizarlo mal.

No hay servidor ni base de datos. El análisis ocurre en la pestaña del
navegador, y el HTML del correo se muestra como código y nunca se ejecuta, así
que no se cargan imágenes remotas ni se avisa al remitente de que lo has abierto.

## Qué mira

Seis bloques de comprobaciones, cada uno con un techo de puntos para que ningún
tipo de indicio dispare la nota por sí solo:

| Bloque | Techo |
|---|---|
| Autenticación (SPF, DKIM, DMARC, ARC) | 30 |
| Identidad del remitente | 20 |
| Enlaces | 20 |
| Contenido del mensaje | 15 |
| Adjuntos | 10 |
| Transporte y cabeceras | 5 |
| Combinaciones que encajan con un fraude conocido | +22 |

La nota resultante se traduce en cuatro niveles: BAJO por debajo de 18, MEDIO
de 18 a 49, ALTO de 50 a 79 y CRÍTICO a partir de 80.

Los indicios se suman, no se disparan por separado. Un correo no es sospechoso
por venir de Gmail, ni por pedir una transferencia, ni por traer un IBAN, sino
por las tres cosas a la vez.

## De dónde salen los pesos

Cada regla lleva en el código un campo `fuente` que dice de dónde viene su peso.
Hay dos casos:

- **Medido.** Se cuenta cuántas veces dispara la regla sobre un corpus de
  phishing y cuántas sobre uno de correo legítimo, y se usa la razón entre
  ambas frecuencias (*likelihood ratio*) para fijar los puntos. Una regla que
  aparece con la misma frecuencia en los dos lados no distingue nada, por muy
  grave que suene.
- **Sin validar.** Reglas que no llegan a dispararse en los corpus disponibles,
  o que no tienen suficientes casos para medirlas. Sus puntos están puestos por
  criterio y el campo `fuente` lo dice explícitamente.

Hay una tercera etiqueta, **pocos casos**, para las reglas que sí aparecen en
los corpus pero en un puñado de correos: ahí la razón entre frecuencias es ruido,
así que se anota el recuento crudo y el peso queda puesto por criterio.

Una regla anotada como *no distingue* tiene el peso a cero: sigue apareciendo en
el informe como observación, pero no suma. Hay una prueba que lo comprueba.

El resultado depende del corpus que uses, y no todas las reglas se pueden medir
igual de bien. Las de autenticación son el caso claro: contra un corpus de correo
legítimo anterior a DMARC o a ARC, la comparación no dice nada útil, porque esas
cabeceras todavía no existían. Lo mismo pasa con `compauth`, que solo lo emite
Microsoft y por tanto depende de quién recibiera el correo. Esas anotaciones lo
avisan en el propio campo `fuente`.

Los corpus no están en el repositorio. `tools/corpus.mjs` es la herramienta que
hace la medición sobre los corpus que tengas tú:

```bash
node tools/corpus.mjs <carpeta> --esperado phishing|legitimo   # reparto de notas y fallos
node tools/corpus.mjs <carpeta-phishing> <carpeta-legitimo>    # razón de verosimilitud por regla
```

Acepta ficheros `.eml` sueltos y buzones `mbox`. No abre ningún adjunto ni sigue
ningún enlace: el motor solo lee bytes.

## Qué no hace

No detecta cuentas comprometidas: si un atacante entra en el buzón real de tu
proveedor, el correo autentica correctamente porque *es* auténtico.

No abre los adjuntos ni visita los enlaces, así que no sabe qué hay al otro
lado. Y es orientativo, no un veredicto: ante la duda, entra tú a la web oficial
escribiendo la dirección a mano y llama al teléfono de siempre.

Si ya has escrito la contraseña, cámbiala desde otra pestaña, activa la
verificación en dos pasos y llama al **017**, que es el teléfono de INCIBE y es
gratuito.

## Cómo está montado

Cuatro ficheros y ninguna dependencia: `index.html`, `assets/parser.js` (el
motor), `assets/ui.js` (la interfaz) y `assets/styles.css`.

Sírvelo por HTTP y no con `file://`: los hashes SHA se calculan con WebCrypto,
que solo funciona en contexto seguro.

```bash
python3 -m http.server 8000     # http://127.0.0.1:8000
node tests/test.mjs             # pruebas del motor
npm i jsdom && node tests/test.mjs   # pruebas del motor y de la interfaz
```

Los correos de las pruebas son sintéticos: sirven para comprobar que el motor
hace lo que dice, no para estimar cuánto acierta. Eso último requiere correo
real y lo mide `tools/corpus.mjs`.

## Licencia

[MIT](LICENSE): úsalo, cópialo y modifícalo, también en proyectos comerciales;
solo se pide mantener el aviso de autoría. Va sin garantías.

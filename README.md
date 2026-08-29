# PhishTriage

**v1.0** · cifras medidas el 29 de agosto de 2026 contra esta misma etiqueta. ![tests](https://github.com/Kharonte09/phishtriage/actions/workflows/ci.yml/badge.svg)

Le sueltas un correo sospechoso y te dice si es un fraude, por qué, y qué hacer.
**→ https://kharonte09.github.io/phishtriage/**

## Cómo se usa

Suelta el correo en la página (o pégalo con `Ctrl+V`) y lee la pestaña **¿Qué
hago?**. Lo descargas en Gmail con `⋮` → Descargar mensaje y en Thunderbird con
clic derecho → Guardar como; un `.msg` de Outlook no vale. No hay servidor ni
base de datos: el programa se ejecuta en tu pestaña, y el HTML del correo se
muestra como texto y nunca se ejecuta, así que no avisa al atacante.

## Qué mira

Las cinco preguntas de un analista, cada una con su techo de puntos para que
ninguna pega dispare la nota sola: autenticación SPF/DKIM/DMARC (30), quién
escribe de verdad (20), enlaces (20), texto (15), adjuntos (10), transporte (5)
y combinaciones de fraude conocido (+22). BAJO menos de 18 · MEDIO 18-49 · ALTO
50-79 · CRÍTICO 80 o más. Un correo no es sospechoso por venir de Gmail, ni por
pedir una transferencia, ni por traer un IBAN, sino por las tres cosas a la vez.

## De dónde salen los números

Los pesos no están puestos a ojo: salen de medir cuántas veces dispara cada
indicio en phishing real y cuántas en correo legítimo, y el que no distingue no
está en el código — así se cayeron 32. Medido sobre 9.916 correos de phishing
([Phishing Pot](https://github.com/rf-peixoto/phishing_pot) y
[Nazario](https://monkey.org/~jose/phishing/), 2023-25) y 7.621 legítimos:
detecta entre el 51,6% y el 68,2% del phishing masivo según el buzón que lo
recibió, con menos del 0,5% de falsos positivos. Dos límites:

- El correo legítimo medido es de 2002-2003 ([corpus de
  SpamAssassin](https://spamassassin.apache.org/old/publiccorpus/)) y de [listas
  técnicas](https://lists.apache.org/). **No incluye correo comercial moderno**,
  que es donde están casi todos los falsos positivos reales.
- Los dos corpus de phishing son de honeypot, así que miden **phishing masivo**.
  El dirigido —spear-phishing, BEC, cuentas comprometidas— no llega a una trampa.

## Qué NO hace

No detecta cuentas comprometidas: si el atacante entra en el correo real de tu
proveedor, todo autentica porque el correo *es* auténtico. No abre los adjuntos
ni sigue los enlaces, y es orientativo: ante la duda entra tú a la web oficial
escribiendo la dirección a mano y llama al teléfono de siempre. Si ya metiste la
contraseña, cámbiala desde otra pestaña, activa la verificación en dos pasos y
llama al **017**, que es INCIBE y es gratis.

## Cómo está hecho

Cuatro ficheros y ninguna dependencia: `index.html`, `assets/parser.js` (motor),
`assets/ui.js` y `assets/styles.css`. Sírvelo por HTTP y no con `file://`: los
hashes SHA usan WebCrypto, que solo funciona en contexto seguro.

```bash
python3 -m http.server 8000                                 # http://127.0.0.1:8000
node tests/test.mjs                                         # 71 pruebas
node tools/corpus.mjs <carpeta> --esperado phishing|legitimo
```

Los correos de prueba son sintéticos; para saber si acierta hace falta correo
real, y eso lo mide `tools/corpus.mjs`. Cada regla lleva un campo `fuente` con
sus porcentajes medidos, y un test falla si alguien añade una sin declararlo.

[MIT](LICENSE): úsalo, cópialo y modifícalo, también en proyectos comerciales;
solo se pide mantener el aviso de autoría. Va sin garantías.

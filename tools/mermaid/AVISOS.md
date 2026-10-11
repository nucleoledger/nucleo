# Avisos de dependencias del validador Mermaid

Este directorio es una herramienta de desarrollo: valida los bloques Mermaid de
`docs/ARQUITECTURA.md` en el CI (job `mermaid`) y no forma parte de ningún artefacto que se
publique. Aquí queda por qué se descarta un aviso en vez de subir la dependencia.

## Dependabot #5 — KaTeX, GHSA-238p-pmpm-9mq7 (severidad baja) — descartado el 2026-10-11

**El aviso.** KaTeX < 0.18.2 puede leer opciones heredadas de un `Object.prototype` ya
contaminado; con una opción `trust` heredada y expresiones matemáticas del atacante, su HTML
puede llevar enlaces con XSS si la aplicación lo inserta en una página sin sanear. KaTeX no
provoca la contaminación: hace falta otra vulnerabilidad que la provoque.

**Por qué no se sube.** KaTeX entra como dependencia de `mermaid`, y ninguna versión de mermaid
la admite corregida: la 11.17.2 que fija el lockfile y la 12.1.0, la última publicada al
escribir esto, piden `katex ^0.16.47`, que en 0.x no alcanza la 0.18.2. Forzarla con
`overrides` instalaría una versión que mermaid no declara, para corregir algo que aquí no
ocurre.

**Por qué no es alcanzable aquí**, condición a condición:

- **No se dibuja nada.** `valida.mjs` solo llama a `mermaid.parse`; no genera HTML, y nada de
  lo que produce se inserta en una página. El aviso exige insertar la salida de KaTeX en un
  documento.
- **La entrada no es de nadie de fuera.** Lo único que se valida es `docs/ARQUITECTURA.md` del
  propio repositorio y los bloques fijos de la autoprueba; quien puede cambiarlos puede cambiar
  el CI entero.
- **No hay contaminación del prototipo que aprovechar.** El proceso es un `node` de una sola
  ejecución en el CI, sin red ni entrada de usuarios, con `jsdom` y `mermaid` como únicas
  dependencias directas.
- **No se publica.** No llega a ningún binario, ni al paquete de npm, ni a `web/verify/`.

**Cuándo revisarlo.** Cuando una versión de mermaid admita `katex >= 0.18.2`, se sube con el
lockfile y este apartado se borra.

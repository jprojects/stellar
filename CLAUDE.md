# Stellar

Analizador de seguridad interno (webs y código) que genera informes para que Claude resuelva las vulnerabilidades.
Es una **instalación de Quasar** (`~/Projects/quasar`): el núcleo viene de una versión publicada de Quasar y lo propio
de Stellar va aparte. `STELLAR.md` es la referencia de lo propio; `README.md` es el de Quasar (referencia del núcleo):
léelos antes de cambiar algo.

## El núcleo de Quasar no se toca aquí

Los ficheros que lista `core.json` son de Quasar: una actualización los sustituye. Lo propio de Stellar: `modules/`
(salvo los de Quasar), `src/Scanner/`, `src/Hooks/TargetsHooks.php` y `FindingsHooks.php`,
`src/Pages/ScanReportPage.php`, `templates/default/pages/scan_report.php`, `templates/stellar/`,
`lang/*/{scanner,targets,scans,findings,scan_report,app}.json`, `database/stellar.sql`, `tools/`, `STELLAR.md`.

- Si hace falta cambiar el núcleo: en `~/Projects/quasar`, genérico, con README y CHANGELOG, y se publica una versión;
  luego `php tools/update-core.php X.Y.Z` aquí.
- `.claude/hooks/guard-core.php` bloquea editar el núcleo; antes de cada commit, `php tools/check-core.php` tiene que
  decir «Núcleo intacto».

## Convenciones (las de Quasar)

- Sin dependencias (ni Composer ni npm). Comentarios y documentación en castellano.
- Textos de la interfaz en `lang/{ca,es,en}/*.json` (catalán por defecto); los de cada control en `scanner.json`, en
  los tres idiomas. Iconos Lucide, nunca emojis. CSS con variables del tema; los estilos de la página, en su plantilla.
- Permisos en el servidor. El permiso propio `scan` (módulo `targets`) controla quién lanza análisis.

## Seguridad del propio Stellar

- Nunca analizar un objetivo sin `authorized = 1` (lo comprueba `ScanRunner`, no solo el botón).
- `TargetGuard`: webs sin IP privadas (salvo `allow_private`) y carpetas de código solo dentro de `code_roots`.
- `HttpClient` fija la IP y no sale del host; el análisis web no envía formularios ni cargas de ataque. No añadir
  controles destructivos ni intrusivos (fuerza bruta, inyecciones activas, DoS).
- Las pruebas pasan siempre por `Redactor` antes de guardarse (no guardar secretos enteros).

## Probar

- `php -l` en cada PHP cambiado; `php tools/check-core.php`.
- El motor se puede probar sin BD (clases de `src/Scanner/` con un autoloader); para la web, contra un servidor local
  con ficheros expuestos a propósito y `allow_private`. No lanzar análisis contra webs de terceros.
- Local: `config/config.local.php`, `php bin/install.php --no-demo`, `php tools/stellar-migrate.php`,
  `php -S 127.0.0.1:8000 -t public`. Probar en el navegador, también con un usuario que no sea administrador.

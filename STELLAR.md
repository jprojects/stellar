# Stellar

Analizador de seguridad interno: encuentra vulnerabilidades en **webs en producción** y en el **código de las
aplicaciones**, y prepara un informe en Markdown para que **Claude** (claude.ai o Claude Code) las resuelva.

Es una **instalación de Quasar** (`~/Projects/quasar`, núcleo v0.24.1): el núcleo viene de una versión publicada y
todo lo de Stellar va aparte. `README.md` es la referencia del núcleo (Quasar); este fichero, la de Stellar.

> Solo se analizan webs y código **propios o con permiso por escrito**. Cada objetivo tiene la casilla
> «Autoritzat» y sin ella Stellar se niega a analizarlo (también desde el cron, la API y el MCP).

## Cómo se usa

1. **Objectius → Nou**: nombre, tipo (*Web* o *Codi*), la URL o la carpeta / el `.zip` del código, el responsable y
   la casilla **Autoritzat**.
2. **Analitza** (en la fila o en la ficha; permiso propio `scan`). Una web tarda unos segundos o un minuto.
3. Se abre el **Informe**: puntuación, recuentos, evolución, cada hallazgo con la prueba y la solución, y el bloque
   **Informe per a Claude** con **Copia per a Claude** y **Descarrega .md**. Se pega en una conversación nueva de
   claude.ai: ya lleva las instrucciones (revisar si es real, explicar el impacto, dar el cambio exacto, ordenar por
   prioridad y decir los falsos positivos).
4. Lo que no es real o se acepta se marca en **Troballes** (*Fals positiu*, *Risc acceptat*, con una nota). Esa
   decisión se conserva en los análisis siguientes (por huella) y ya no entra en el informe ni en la puntuación.
5. Después de corregir, **Torna a analitzar**: el informe dice cuántos hallazgos son nuevos y cuántos ya no están.

La página **Tauler** (`scan_report`) es el inicio: todos los objetivos ordenados de peor a mejor puntuación y los
últimos análisis.

## Qué comprueba

**Web** (`src/Scanner/WebScanner.php`), sin hacer daño: peticiones de navegador (GET/HEAD), un TRACE, en WordPress
una llamada inocua a `xmlrpc.php`, y un parámetro con comillas en la portada. Nada de formularios, contraseñas ni
cargas de ataque. Máximo 150 peticiones, con pausa entre ellas, y solo al host analizado (IP fijada al principio).

- HTTPS, redirección HTTP→HTTPS, certificado (validez, caducidad) y TLS 1.0/1.1.
- Cabeceras: HSTS, CSP (y si es débil), clickjacking, nosniff, Referrer-Policy, Permissions-Policy, versión del
  servidor/PHP.
- Cookies sin Secure/HttpOnly/SameSite; contenido mixto; formularios por HTTP; scripts externos sin SRI.
- Ficheros expuestos, verificados por su contenido (no basta un 200, para no caer en las 404 «blandas»): `.git`,
  `.svn`, `.env`, copias de `wp-config`/configuración, copias `.zip`/`.sql`, `sftp.json`, `.htpasswd`, Adminer,
  phpinfo, logs (`debug.log`, `error_log`, `laravel.log`), `server-status`, phpMyAdmin, perfiladores
  (Symfony/Telescope), `.DS_Store`.
- Listados de carpetas, CORS que refleja el origen, errores SQL/PHP/trazas visibles, entrada reflejada sin escapar
  (posible XSS), TRACE.
- CMS: WordPress (versión, plugins visibles, XML-RPC, usuarios por la API REST), Joomla, Drupal, PrestaShop.
- Librerías JavaScript (jQuery, Bootstrap, Angular, Lodash, Moment, Vue…) con vulnerabilidades conocidas (OSV.dev).
- security.txt y rutas sensibles en robots.txt.

**Código** (`src/Scanner/CodeScanner.php`), por patrones: PHP, JavaScript/TypeScript, Python y configuración.
Inyección SQL, órdenes del sistema, `include` con datos del usuario, rutas de fichero del usuario, `unserialize`/
`pickle`, `eval`, XSS, redirecciones abiertas, `extract($_POST)`, hashes débiles de contraseña, subidas con el nombre
original, aleatorio débil para tokens, comparaciones `==` de tokens, contaminación de prototipos, modo debug, TLS sin
verificar, CORS `*`, **secretos** con formato conocido (AWS, Stripe, Anthropic, OpenAI, GitHub, Slack, Google,
Telegram, SendGrid, tokens de Quasar, claves privadas), contraseñas escritas en el código, `.env` dentro del proyecto
(peor si está en git) y **dependencias vulnerables** de `composer.lock`, `package-lock.json`, `yarn.lock` y
`requirements.txt` (OSV.dev). Un hallazgo por control y fichero, con las líneas. Se saltan `vendor/`,
`node_modules/`, `dist/`…, los tests (salvo secretos) y las librerías copiadas en el proyecto (llevan cabecera de
licencia). Hay falsos positivos: el informe se lo dice a Claude.

**Los secretos nunca se guardan enteros**: `Redactor` los enmascara (`DB_PASSWORD=su***`) antes de ir a la BD y al
informe.

**Puntuación**: 100 menos lo que resta cada control con su peor gravedad (crítica 30, alta 12, media 5, baja 1) y un
poco por las repeticiones. Solo cuentan los hallazgos abiertos.

## Configuración (`config/config.local.php`)

Ver `config/config.local.example.php`. Lo propio de Stellar:

```php
'template' => 'stellar',          // colores propios y el botón «Copia per a Claude» (templates/stellar/assets/stellar.js)
'api' => ['enabled' => true],     // para el MCP
'stellar' => [
    'code_roots' => ['/home/…/Projects'],   // carpetas del servidor que se pueden analizar como código
    'allow_private' => false,               // true: webs de la red interna (por defecto no, contra SSRF)
    'max_requests' => 150, 'delay_ms' => 150, 'timeout' => 15,
    'osv' => true,                          // vulnerabilidades conocidas (OSV.dev: solo nombres y versiones)
    'tls_legacy' => true,
],
```

## Ficheros de Stellar

| Dónde | Qué |
|---|---|
| `src/Scanner/` | el motor: `WebScanner`, `CodeScanner`, `Osv`, `HttpClient`, `TargetGuard` (qué se puede analizar), `Workspace` (zips), `Redactor`, `Severity`, `ScanRunner` (lanza y guarda), `ReportBuilder` (Markdown) |
| `modules/` | `targets` (objetivos), `scans` (historial), `findings` (hallazgos), `scan_report` (página Tauler/Informe) |
| `src/Hooks/` | `TargetsHooks` (validación y botón Analitza), `FindingsHooks` (recalcula la puntuación al marcar) |
| `src/Pages/ScanReportPage.php` + `templates/default/pages/scan_report.php` | panel e informe; `api()` para el MCP |
| `templates/stellar/` | plantilla propia: `theme.css` y `stellar.js` (copiar al portapapeles; la CSP no permite scripts en línea) |
| `lang/{ca,es,en}/` | `scanner.json` (textos de cada control: título, qué pasa, cómo resolverlo; y el informe), `targets`, `scans`, `findings`, `scan_report`, `app` |
| `database/stellar.sql` | tablas `targets`, `scans`, `findings` |
| `tools/` | `stellar-migrate.php`, `scan.php` (terminal/cron), `mcp.php`, `check-core.php`, `update-core.php` |

**Añadir un control**: el código en `WebScanner`/`CodeScanner` (`add()` o una regla de `rules()`), con un id
`web.xxx`/`code.xxx`, y sus textos `checks.{id}.title|detail|fix` en `lang/{ca,es,en}/scanner.json` (las variables
`{…}` salen de `$vars`; en el código siempre hay `{file}` y `{count}`). Los textos de `fix` son lo que lee Claude:
concretos, con el cambio de configuración o de código.

## Terminal y cron

```bash
php tools/stellar-migrate.php                  # tablas (después de php bin/install.php --no-demo)
php tools/scan.php --target=3 [--md]           # un objetivo (--md imprime el informe)
php tools/scan.php --all                       # todos los activos y autorizados
php tools/scan.php --due=7                     # los no analizados en 7 días (cron)
```

Cron semanal: `0 4 * * 1  php /ruta/stellar/tools/scan.php --due=7 > /dev/null 2>&1`.

## Claude Code (MCP)

`tools/mcp.php`: servidor MCP local (stdio, sin dependencias) que usa la API de Stellar con el token personal
(Perfil → API). Herramientas: `stellar_objectius`, `stellar_informe` (Markdown de la última análisis de un objetivo o
de una análisis), `stellar_analitza` (vuelve a analizar; pide confirmación) y `stellar_marca` (resuelta, acceptada,
fals_positiu con nota; pide confirmación).

```bash
mkdir -p ~/.config/stellar-mcp && echo 'qs_…' > ~/.config/stellar-mcp/token && chmod 600 ~/.config/stellar-mcp/token
claude mcp add stellar --scope user -e STELLAR_URL=https://stellar.example.com -- php ~/Projects/stellar/tools/mcp.php
```

Con el código de la aplicación abierto en Claude Code: «Llegeix l'informe de Stellar de l'objectiu 4 i resol les
troballes altes».

## Límites

No es una auditoría ni un pentest: no inicia sesión, no prueba formularios ni la lógica de negocio, no hace
inyecciones activas, y el análisis de código no sigue los datos entre funciones. Sirve para encontrar rápido lo
evidente y lo que se olvida (ficheros expuestos, cabeceras, versiones, secretos, dependencias) y para que Claude lo
arregle bien. El informe lo dice en «Què no s'ha comprovat».

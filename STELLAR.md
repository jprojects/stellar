# Stellar

Analizador de seguridad interno: encuentra vulnerabilidades en **webs en producción** y en el **código de las
aplicaciones** (carpeta del servidor, `.zip` o **repositorio git** público o privado) y prepara un informe en Markdown
para que **Claude** (claude.ai o Claude Code) las resuelva.

Es una **instalación de Quasar** (`~/Projects/quasar`, núcleo v0.24.1): el núcleo viene de una versión publicada y
todo lo de Stellar va aparte. `README.md` es la referencia del núcleo (Quasar); este fichero, la de Stellar.

> Solo se analizan webs y código **propios o con permiso por escrito**. Cada objetivo tiene la casilla
> «Autoritzat» y sin ella Stellar se niega a analizarlo (también desde el cron, la API y el MCP).

**Índice**: [Cómo se usa](#cómo-se-usa) · [Repositorios git](#repositorios-git) · [Qué comprueba](#qué-comprueba) ·
[Instalación](#instalación) · [Configuración](#configuración) · [Terminal y cron](#terminal-y-cron) ·
[Claude Code (MCP)](#claude-code-mcp) · [Ficheros](#ficheros-de-stellar) · [Mantenimiento](#mantenimiento) ·
[Problemas frecuentes](#problemas-frecuentes) · [Límites](#límites)

## Cómo se usa

1. **Objectius → Nou objectiu**:
   - *Web*: la URL de la portada.
   - *Codi*, con uno de estos **orígenes**:
     - **Repositori git** (por defecto): `https://github.com/jprojects/app` y, si no es la principal, la rama.
     - **Carpeta del servidor**: una ruta dentro de `code_roots`.
     - **Fitxer .zip**: el código comprimido.
   - El responsable o cliente y la casilla **Autoritzat**.
2. **Analitza** (en la fila o en la ficha; permiso propio `scan`). Una web tarda de unos segundos a un minuto; un
   repositorio, lo que tarde en descargarse más unos segundos.
3. Se abre el **informe**:
   - puntuación de 0 a 100, recuentos por gravedad y la evolución de los últimos análisis;
   - cada hallazgo, con dónde está, qué pasa, la prueba (con los secretos enmascarados) y cómo resolverlo;
   - el bloque **Informe per a Claude**, con **Copia per a Claude** y **Descarrega .md**.
4. **Pegar el informe en una conversación nueva de claude.ai** (o en Claude Code con el código abierto). Ya lleva
   las instrucciones: confirmar si cada hallazgo es real, explicar el impacto, dar el cambio exacto, ordenar por
   prioridad y señalar los falsos positivos.
5. **Troballes**: lo que no es real o se acepta se marca como *Fals positiu* o *Risc acceptat*, con una nota.
   - La decisión se conserva en los análisis siguientes (cada hallazgo tiene una huella estable).
   - Ya no entra en el informe ni resta puntuación.
   - *Resolta* sirve para llevar la cuenta; si el problema sigue ahí, el siguiente análisis lo vuelve a abrir.
6. Después de corregir, **Torna a analitzar**: el informe dice cuántos hallazgos son nuevos y cuántos ya no están.

**Tauler** (`scan_report`, el inicio) muestra todos los objetivos activos de peor a mejor puntuación, los totales de
hallazgos críticos, altos y medios, y los últimos análisis (con el error si alguno ha fallado). **Anàlisis** es el
historial completo.

### Permisos

| Permiso | Para qué |
|---|---|
| `scan_report` → Ver | el Tauler y los informes |
| `targets` → Ver / Crear / Editar / Borrar | gestionar objetivos |
| `targets` → **Analitzar** (`scan`) | lanzar análisis (botón y API) |
| `findings` → Ver / Editar | ver hallazgos y marcarlos (falso positivo, aceptado, resuelto) |
| `scans` → Ver / Borrar | el historial |

Se dan por usuario o por grupo en *Administració*. Los administradores lo tienen todo.

## Repositorios git

Un objetivo de código con origen **Repositori git** se descarga en cada análisis en una carpeta temporal, se analiza
y **se borra**: Stellar no guarda copias del código.

- **Cómo lo descarga**: si el servidor tiene `git`, con `git clone --depth 1` de la rama (solo la última versión, sin
  historial, submódulos ni LFS). Así sabe qué ficheros están en el repositorio: un `.env` subido a git sale como
  más grave, porque queda en el historial. Si el servidor no tiene `git` (algunos hostings) y el repositorio es de
  GitHub, descarga la rama en `.zip` con la API, con el mismo token. El informe dice el repositorio, la rama y el
  commit analizado.
- **Repositorios públicos**: no necesitan nada.
- **Repositorios privados (nuestros)**: necesitan un **token de solo lectura** en `config.local.php` del servidor.

### Crear el token de GitHub

1. En GitHub, con la cuenta u organización propietaria (`jprojects`): *Settings → Developer settings → Personal
   access tokens → Fine-grained tokens → Generate new token*.
2. **Resource owner**: la cuenta u organización de los repositorios.
3. **Repository access**: *Only select repositories*, con los que Stellar tenga que analizar (o *All repositories*).
4. **Permissions → Repository permissions → Contents: Read-only**. Nada más (Metadata: Read-only lo añade solo).
5. **Expiration**: por ejemplo, un año. Apúntate cuándo caduca: al caducar, los análisis de repositorios privados
   fallan con «No es pot accedir al repositori».
6. Copia el token (`github_pat_…`) en `config/config.local.php` del servidor:

```php
'stellar' => [
    'git_tokens' => ['github.com' => 'github_pat_…'],
],
```

GitLab: un *Project/Group access token* o *Personal access token* con `read_repository`, en `'gitlab.com' => 'glpat-…'`.
Bitbucket: un *Repository access token* con lectura, en `'bitbucket.org' => '…'`. Un servidor git propio:
`'git.empresa.com' => '…'` (se permite automáticamente al tener token) o, si es público, en `'git_hosts'`.

### Cómo se protege el token

- Solo vive en `config.local.php` (fuera de git): no se guarda en la base de datos, ni en los objetivos, ni en los
  informes, ni en los logs (los mensajes de error se limpian antes de guardarse).
- A `git` le llega como cabecera HTTP por variables de entorno, nunca en la URL ni en los argumentos (no se ve con
  `ps`) ni en `.git/config`. Con la API de GitHub, curl no lo reenvía al servidor de descarga al que redirige.
- Solo se aceptan URL `https://` de los servidores permitidos (`github.com`, `gitlab.com`, `bitbucket.org`, los de
  `git_tokens` y los de `git_hosts`), para que un objetivo no sirva para llegar a la red interna.
- La descarga se hace sin la configuración de git del servidor (sin ayudantes de credenciales ni hooks) y los enlaces
  simbólicos del repositorio quedan como texto.
- Si se filtra: se revoca en GitHub en un clic y solo daba **lectura** de los repositorios elegidos.

## Qué comprueba

### Webs (`src/Scanner/WebScanner.php`)

Sin hacer daño: peticiones de navegador (GET/HEAD), un TRACE, en WordPress una llamada inocua a `xmlrpc.php`, y un
parámetro con comillas en la portada. Nada de formularios, contraseñas ni cargas de ataque. Máximo 150 peticiones,
con pausa entre ellas, y solo al host analizado (la IP se fija al principio).

- **Transporte:** HTTPS, redirección HTTP→HTTPS, certificado (validez y caducidad) y TLS 1.0/1.1.
- **Cabeceras:** HSTS, CSP (y si es débil), protección contra clickjacking, nosniff, Referrer-Policy,
  Permissions-Policy y versión del servidor o de PHP.
- **Cookies sin Secure, HttpOnly o SameSite;** contenido mixto; formularios por HTTP; scripts externos sin SRI.
- **Ficheros expuestos,** verificados por su contenido (no basta un 200, para no caer en las 404 «blandas»):
  - control de versiones y configuración: `.git`, `.svn`, `.env`, copias de `wp-config` o de la configuración;
  - copias de seguridad: `.zip`, `.sql`;
  - credenciales y herramientas: `sftp.json`, `.htpasswd`, Adminer, phpMyAdmin, phpinfo;
  - logs y estado: `debug.log`, `error_log`, `laravel.log`, `server-status`;
  - perfiladores (Symfony, Telescope) y `.DS_Store`.
- **Comportamiento:** listados de carpetas, CORS que refleja el origen, errores SQL/PHP o trazas visibles, entrada
  reflejada sin escapar (posible XSS) y TRACE.
- **CMS:** WordPress (versión, plugins visibles, XML-RPC, usuarios por la API REST), Joomla, Drupal y PrestaShop.
- **Librerías JavaScript** (jQuery, Bootstrap, Angular, Lodash, Moment, Vue…) con vulnerabilidades conocidas, según
  OSV.dev.
- **security.txt** y rutas sensibles en robots.txt.

### Código (`src/Scanner/CodeScanner.php`)

Por patrones, línea a línea: PHP, JavaScript/TypeScript, Python y configuración.

- **Inyecciones:** SQL (alta si la entrada del usuario va a la consulta; media si se concatenan variables), órdenes
  del sistema, `include` con datos del usuario y rutas de fichero del usuario.
- **Ejecución:** `unserialize`/`pickle`/`yaml.load` y `eval`.
- **Web:** XSS (salida sin escapar, `innerHTML`, `v-html`…), redirecciones abiertas y `extract($_POST)`.
- **Criptografía y aleatoriedad:** hashes débiles de contraseña, aleatorio débil para tokens y comparaciones `==` de
  tokens.
- **Otros:** subidas con el nombre original, contaminación de prototipos, modo debug, TLS sin verificar y CORS `*`.
- **Secretos** con formato conocido: AWS, Stripe, Anthropic, OpenAI, GitHub, Slack, Google, Telegram, SendGrid,
  tokens de Quasar y claves privadas.
- **Contraseñas escritas en el código.** No cuentan variables, rutas, claves de idioma ni palabras sueltas como
  `'pass' => 'Correcte'`.
- **`.env` dentro del proyecto,** más grave si está en git.
- **Dependencias vulnerables** de `composer.lock`, `package-lock.json`, `yarn.lock` y `requirements.txt` (OSV.dev).

Un hallazgo por control y fichero, con las líneas. Se saltan:

- `vendor/`, `node_modules/`, `dist/`, `build/` y las cachés;
- los ficheros de más de 1 MB y los minificados;
- los tests, en los que solo se buscan secretos;
- las librerías de terceros copiadas en el proyecto (las que llevan cabecera de licencia).

Hay falsos positivos (es por patrones): el informe se lo dice a Claude y se marcan en *Troballes*.

**Los secretos nunca se guardan enteros**: `Redactor` los enmascara (`DB_PASSWORD=su***`) antes de ir a la BD y al
informe.

**Puntuación**: se parte de 100 y cada control resta una vez, según su peor gravedad: crítica 30, alta 12, media 5,
baja 1. Las repeticiones restan un poco más, hasta 20 puntos como máximo. Solo cuentan los hallazgos abiertos.

## Instalación

Requisitos: PHP 8.1+ con `pdo_mysql`, `mbstring`, `json`, `curl`, `openssl` y `zip`; MySQL 5.7+ o MariaDB 10.3+.
Opcional: `git` en el servidor (si no hay, los repositorios de GitHub se descargan por la API).

### Con SSH

```bash
git clone https://github.com/jprojects/stellar.git && cd stellar
cp config/config.local.example.php config/config.local.php    # y rellénalo (BD, base_url, stellar…)
php bin/install.php --no-demo                                 # tablas del núcleo y el administrador
php tools/stellar-migrate.php                                 # tablas de Stellar
```

El *DocumentRoot* tiene que ser `public/`. `storage/` necesita permiso de escritura para PHP.

### En un hosting sin SSH (cPanel)

1. Sube el código (sin `.git`) y apunta el dominio o subdominio a la carpeta `public/`.
2. Crea la base de datos y su usuario en el panel. Escribe `config/config.local.php` con esos datos: en `'db'`
   normalmente basta `'host' => 'localhost'` y el puerto por defecto.
3. En phpMyAdmin, importa por este orden `database/schema.sql` (núcleo) y `database/stellar.sql` (Stellar).
4. Crea el administrador con el hash de la contraseña. El hash se genera en cualquier PHP, con
   `php -r 'echo password_hash("contraseña", PASSWORD_DEFAULT);'`:

```sql
INSERT INTO users (username, password_hash, name, email, locale, is_admin, active)
VALUES ('kim', '$2y$10$…hash…', 'Kim', 'kim@aficat.com', 'ca', 1, 1);
```

5. El cron (ver abajo), con la ruta de PHP del hosting (p. ej. `/opt/alt/php82/usr/bin/php`).

### Actualizar una instalación con objetivos de código antiguos

Desde la versión con repositorios git, `targets` tiene tres columnas más. `php tools/stellar-migrate.php` las añade
solo. Sin SSH, en phpMyAdmin:

```sql
ALTER TABLE targets
  ADD COLUMN code_source VARCHAR(10) NOT NULL DEFAULT 'path' AFTER url,
  ADD COLUMN repo_url VARCHAR(500) NULL AFTER code_zip,
  ADD COLUMN repo_branch VARCHAR(150) NULL AFTER repo_url;
UPDATE targets SET code_source = 'zip' WHERE kind = 'code' AND COALESCE(code_path, '') = '' AND code_zip IS NOT NULL;
```

## Configuración

Todo en `config/config.local.php` (fuera de git; ejemplo completo en `config/config.local.example.php`). Las claves
de Quasar están en `config/config.php` y en `README.md`.

```php
return [
    'app_name' => 'Stellar',
    'template' => 'stellar',          // colores propios y el botón «Copia per a Claude»
    'debug' => false,                 // true solo en local
    'base_url' => 'https://stellar.example.com',
    'db' => ['host' => 'localhost', 'name' => '…', 'user' => '…', 'pass' => '…'],
    'api' => ['enabled' => true],     // para el MCP

    'stellar' => [
        'code_roots' => [],           // carpetas DEL SERVIDOR que se pueden analizar como código (no dominios)
        'allow_private' => false,     // true: webs de la red interna (por defecto no, contra SSRF)
        'max_requests' => 150,        // peticiones por análisis web
        'delay_ms' => 150,            // pausa entre peticiones
        'timeout' => 15,              // segundos por petición
        'user_agent' => 'Mozilla/5.0 (compatible; Stellar security scanner)',
        'osv' => true,                // vulnerabilidades conocidas con OSV.dev (solo nombres y versiones)
        'tls_legacy' => true,         // probar TLS 1.0/1.1
        'git_tokens' => ['github.com' => 'github_pat_…'],   // repositorios privados (solo lectura)
        'git_hosts' => [],            // otros servidores git permitidos
        'git_timeout' => 300,         // segundos para descargar un repositorio
        'git_binary' => true,         // false: no usar git aunque exista (GitHub por la API)
        'max_files' => 20000,         // ficheros por análisis de código
        'max_file_size' => 1048576,   // bytes por fichero (los mayores se saltan)
    ],
];
```

- **`code_roots`** son rutas del disco del servidor (`/home/usuario/public_html`), no dominios. Si el código no está
  en el servidor, mejor un repositorio git o un `.zip`, y `code_roots` vacío.
- **`allow_private`** permite analizar IP internas: déjalo en `false` salvo que se quiera analizar la intranet a
  propósito.
- **OSV.dev** recibe solo `ecosistema + paquete + versión` (p. ej. `npm jquery 1.12.4`), nunca código ni URL.

## Terminal y cron

```bash
php tools/stellar-migrate.php                  # tablas y columnas nuevas (idempotente)
php tools/scan.php --target=3 [--md]           # un objetivo (--md imprime el informe)
php tools/scan.php --all                       # todos los activos y autorizados
php tools/scan.php --due=7                     # los no analizados en los últimos 7 días (para el cron)
php tools/scan.php --due=7 --locale=es         # textos del informe en castellano (ca, es, en)
```

Cron semanal (lunes a las 4): `0 4 * * 1  php /ruta/stellar/tools/scan.php --due=7 > /dev/null 2>&1`.
Sale con código 1 si algún análisis ha fallado.

## Claude Code (MCP)

`tools/mcp.php` es un servidor MCP local (stdio, sin dependencias) que usa la API de Stellar con el **token personal**
de cada uno (Stellar → Perfil → API): ve y hace lo mismo que ese usuario.

| Herramienta | Qué hace |
|---|---|
| `stellar_objectius` | los objetivos con la última puntuación y los hallazgos críticos, altos y medios |
| `stellar_informe` | el informe en Markdown de la última análisis de un objetivo (`objectiu`) o de una análisis (`analisi`) |
| `stellar_analitza` | vuelve a analizar un objetivo y devuelve el informe nuevo (pide confirmación) |
| `stellar_marca` | marca un hallazgo (`S123`) como `resolta`, `acceptada`, `fals_positiu` u `oberta`, con nota (pide confirmación) |

Alta (una vez por ordenador; vale para todos los proyectos):

```bash
mkdir -p ~/.config/stellar-mcp && echo 'qs_…' > ~/.config/stellar-mcp/token && chmod 600 ~/.config/stellar-mcp/token
claude mcp add stellar --scope user -e STELLAR_URL=https://stellar.example.com -- php ~/Projects/stellar/tools/mcp.php
```

Opcional: `-e STELLAR_LANG=es` para los informes en castellano. Ejemplo de uso con el código de la aplicación abierto en
Claude Code: «Llegeix l'informe de Stellar de l'objectiu 4, comprova les troballes altes i resol les que siguin reals».

## Ficheros de Stellar

| Dónde | Qué |
|---|---|
| `src/Scanner/WebScanner.php` | análisis web |
| `src/Scanner/CodeScanner.php` | análisis de código: reglas, secretos, dependencias |
| `src/Scanner/GitSource.php` | descarga de repositorios git (clone o API de GitHub) |
| `src/Scanner/Osv.php` | consulta de vulnerabilidades conocidas (OSV.dev) |
| `src/Scanner/HttpClient.php`, `TargetGuard.php` | peticiones prudentes y qué se puede analizar |
| `src/Scanner/Workspace.php` | carpeta temporal (zips y repositorios) que se borra al acabar |
| `src/Scanner/Redactor.php`, `Severity.php`, `Finding.php` | enmascarar secretos, gravedades y puntuación, hallazgo |
| `src/Scanner/ScanRunner.php` | lanza un análisis y lo guarda (con la comparación con el anterior) |
| `src/Scanner/ReportBuilder.php` | el informe en Markdown para Claude |
| `modules/` | `targets` (objetivos), `scans` (historial), `findings` (hallazgos), `scan_report` (Tauler e informe) |
| `src/Hooks/TargetsHooks.php` | validación de objetivos y botón Analitza |
| `src/Hooks/FindingsHooks.php` | recalcula la puntuación al marcar un hallazgo |
| `src/Pages/ScanReportPage.php` + `templates/default/pages/scan_report.php` | Tauler e informe; `api()` para el MCP |
| `templates/stellar/` | plantilla propia: `theme.css` y `stellar.js` (copiar al portapapeles; la CSP no permite scripts en línea) |
| `lang/{ca,es,en}/` | `scanner.json` (textos de cada control y del informe), `targets`, `scans`, `findings`, `scan_report`, `app` |
| `database/stellar.sql` | tablas `targets`, `scans`, `findings` |
| `tools/` | `stellar-migrate.php`, `scan.php`, `mcp.php`, `check-core.php`, `update-core.php` |

### Añadir un control

1. El código en `WebScanner` (`$this->add(...)`) o en `CodeScanner` (una regla en `rules()`), con un id `web.xxx` o
   `code.xxx`, la gravedad y el CWE.
2. Sus textos `checks.{id}.title|detail|fix` en `lang/{ca,es,en}/scanner.json`. Las variables `{…}` salen de `$vars`;
   en el código siempre hay `{file}` y `{count}`.
3. El texto de `fix` es lo que lee Claude: concreto, con el cambio de configuración o de código.
4. Probarlo contra algo propio (un servidor local con el fallo puesto a propósito, o un repositorio nuestro) y
   comprobar que no dispara en código correcto (p. ej. el de Quasar).

No se añaden controles intrusivos: fuerza bruta, inyecciones activas, envío de formularios o DoS.

## Mantenimiento

- **Actualizar el núcleo de Quasar**: `php tools/update-core.php X.Y.Z`, después `php tools/stellar-migrate.php`,
  probar y hacer commit. Antes de cada commit, `php tools/check-core.php` tiene que decir «Núcleo intacto».
- **Tokens de git**: renovarlos antes de que caduquen (GitHub avisa por correo).
- **Historial**: los análisis se acumulan; los viejos se pueden borrar en *Anàlisis* (borra también sus hallazgos).
  Las decisiones (falso positivo, aceptado) se conservan mientras quede algún análisis del objetivo que las tenga.

## Problemas frecuentes

| Mensaje | Qué hacer |
|---|---|
| «Aquest objectiu no té marcada l'autorització» | marcar *Autoritzat* en el objetivo (solo si es nuestro o hay permiso por escrito) |
| «… apunta a una adreça interna» | la web resuelve a una IP privada; si es a propósito, `allow_private => true` |
| «La web no respon» | la URL, el DNS o un cortafuegos que bloquea al servidor de Stellar |
| «No es pot accedir al repositori …» | repositorio privado sin token, token caducado o sin acceso a ese repositorio, o URL mal escrita |
| «La branca … no és vàlida o no existeix» | dejar la rama vacía (usa la principal) o revisar el nombre |
| «El servidor no té git i aquest repositori no és de GitHub» | instalar git en el servidor o usar un `.zip` |
| «La carpeta … no és dins de les carpetes permeses» | añadir la carpeta padre a `code_roots` |
| Muchos hallazgos de un mismo tipo que no son reales | marcarlos *Fals positiu*; si es un patrón general, ajustar la regla en `CodeScanner` |
| No aparece «Copia per a Claude» | falta `'template' => 'stellar'` en la config (se puede copiar a mano del recuadro o descargar el .md) |

## Límites

No es una auditoría ni un pentest. No inicia sesión, no prueba formularios ni la lógica de negocio, no hace
inyecciones activas, y el análisis de código no sigue los datos entre funciones ni ficheros.

Sirve para encontrar rápido lo evidente y lo que se olvida (ficheros expuestos, cabeceras, versiones, secretos,
dependencias) y para que Claude lo arregle bien. El informe lo dice en «Què no s'ha comprovat».

<?php
declare(strict_types=1);

namespace Quasar\Scanner;

/**
 * Stellar · análisis estático del código de una aplicación (PHP, JavaScript/TypeScript, Python y ficheros de
 * configuración). Son patrones, no un compilador: busca usos peligrosos (SQL montado con variables, órdenes del
 * sistema, eval, include con datos del usuario, salida sin escapar, TLS sin verificar…), secretos escritos en el
 * código y dependencias con vulnerabilidades conocidas (OSV.dev). Puede haber falsos positivos: el informe se lo dice
 * a Claude para que confirme cada uno antes de cambiar nada.
 *
 * Un hallazgo por control y fichero (con las líneas donde aparece), para que el informe no sean cientos de líneas.
 */
final class CodeScanner
{
    private const SKIP_DIRS = ['.git', '.svn', '.hg', 'node_modules', 'vendor', 'bower_components', '.idea', '.vscode',
        '__pycache__', '.venv', 'venv', 'dist', 'build', '.next', '.nuxt', 'coverage', 'cache', 'tmp', 'uploads',
        'backups', 'logs', '.cache', '.pytest_cache', '.mypy_cache'];

    private const LANGS = [
        'php' => ['php', 'phtml', 'inc', 'module'],
        'js' => ['js', 'mjs', 'cjs', 'jsx', 'ts', 'tsx', 'vue', 'svelte'],
        'py' => ['py'],
        'conf' => ['env', 'ini', 'yml', 'yaml', 'json', 'xml', 'conf', 'toml', 'properties', 'htaccess', 'cfg', 'neon'],
    ];

    /** Entrada del usuario en PHP. */
    private const PHP_SRC = '(\$_(GET|POST|REQUEST|COOKIE|FILES)\b|\$_SERVER\[\s*[\'"](HTTP_\w+|QUERY_STRING|REQUEST_URI|PHP_SELF|PATH_INFO)|php:\/\/input|filter_input\s*\()';

    /** Palabras de SQL en la misma línea. */
    private const SQL = '\b(SELECT\s.+\sFROM|INSERT\s+INTO|UPDATE\s+\S+\s+SET|DELETE\s+FROM|\sWHERE\s|ORDER\s+BY|REPLACE\s+INTO)\b';

    /**
     * Reglas: control, gravedad, lenguajes, patrón, CWE y, opcionalmente, 'need' (también tiene que estar en la
     * línea), 'not' (no puede estar) y 'stronger' => [patrón, gravedad] (si además coincide, más grave).
     */
    private static function rules(): array
    {
        $src = self::PHP_SRC;
        $safeSql = '/(->quote\(|intval\s*\(|\(int\)\s*\$_|esc_sql\(|->prepare\(|real_escape_string\()/i';
        return [
            // ---------------------------------------------------------------- PHP
            ['code.sqli', Severity::HIGH, ['php'], '/(mysql_query|mysqli_query|mysqli_multi_query|pg_query|sqlite_query|->(query|exec|prepare|fetch|fetchAll|fetchValue|fetchColumn|get_results|get_row|get_var|get_col|select|statement|unprepared)|DB::(raw|select|statement|unprepared)|(where|select|orderBy|having)Raw)\s*\(/i',
                'CWE-89', 'need' => '/' . $src . '/', 'not' => $safeSql],
            ['code.sqli', Severity::HIGH, ['php'], '/' . self::SQL . '/i', 'CWE-89', 'need' => '/' . $src . '/', 'not' => $safeSql],
            ['code.sqli', Severity::MEDIUM, ['php'], '/(mysql_query|mysqli_query|pg_query|->(query|exec|fetch|fetchAll|fetchValue|get_results|get_row|get_var|get_col)|DB::(raw|select|statement)|(where|select|orderBy|having)Raw)\s*\(\s*(["\'][^"\']*["\']\s*\.\s*\$|"[^"]*\{?\$[a-z_])/i',
                'CWE-89', 'need' => '/' . self::SQL . '/i', 'not' => '/(intval|\(int\)|ident\(|quote\(|esc_sql|placeholders|implode\(\s*[\'"],\s*[\'"]\s*,\s*array_fill)/i'],
            ['code.cmd_injection', Severity::MEDIUM, ['php'], '/\b(system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\([^)]*\$/', 'CWE-78',
                'not' => '/escapeshell(arg|cmd)/', 'stronger' => ['/' . $src . '/', Severity::CRITICAL]],
            ['code.cmd_injection', Severity::CRITICAL, ['php'], '/(=|\(|return|echo|print)\s*`[^`]*\$_(GET|POST|REQUEST|COOKIE)[^`]*`/', 'CWE-78'],
            ['code.file_inclusion', Severity::CRITICAL, ['php'], '/\b(include|require)(_once)?\b[^;]*' . $src . '/', 'CWE-98'],
            ['code.path_traversal', Severity::HIGH, ['php'], '/\b(file_get_contents|fopen|readfile|file|unlink|copy|rename|file_put_contents|opendir|scandir|show_source|highlight_file|is_file|filesize)\s*\([^;]*' . $src . '/', 'CWE-22',
                'not' => '/(basename\s*\(|file_get_contents\s*\(\s*[\'"]php:\/\/input[\'"]\s*[,)])/'],
            ['code.unserialize', Severity::HIGH, ['php'], '/\bunserialize\s*\([^;]*' . $src . '/', 'CWE-502'],
            ['code.unserialize', Severity::LOW, ['php'], '/\bunserialize\s*\(\s*\$(?!_)/', 'CWE-502', 'not' => '/allowed_classes/'],
            ['code.eval', Severity::HIGH, ['php'], '/(?<![\w>:$])(eval\s*\(|create_function\s*\(|assert\s*\(\s*\$)/', 'CWE-95',
                'stronger' => ['/' . $src . '/', Severity::CRITICAL]],
            ['code.eval', Severity::HIGH, ['php'], '/preg_replace\s*\(\s*([\'"])(.).*\2[a-z]*e[a-z]*\1/', 'CWE-95'],
            ['code.xss', Severity::MEDIUM, ['php'], '/(\b(echo|print)\b[^;]*|<\?=\s*)' . $src . '/', 'CWE-79',
                'not' => '/(htmlspecialchars|htmlentities|esc_html|esc_attr|esc_url|intval|\(int\)|json_encode|strip_tags|\be\(|->e\(|urlencode|number_format)/'],
            ['code.open_redirect', Severity::MEDIUM, ['php'], '/(header\s*\(\s*["\']Location:\s*["\']?\s*\.?|wp_redirect\s*\(|redirect\s*\()[^;]*' . $src . '/i', 'CWE-601',
                'not' => '/wp_safe_redirect|wp_validate_redirect/'],
            ['code.mass_assignment', Severity::MEDIUM, ['php'], '/\b(extract|parse_str)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/', 'CWE-621'],
            ['code.weak_password_hash', Severity::HIGH, ['php'], '/\b(md5|sha1|crc32|hash\s*\(\s*[\'"](md5|sha1|sha256)[\'"])\s*\([^)]*(pass|pwd|clave|contrasenya)/i', 'CWE-916'],
            ['code.weak_password_hash', Severity::HIGH, ['php'], '/\b(md5|sha1)\s*\(\s*\$_(POST|GET|REQUEST)\[\s*[\'"][^\'"]*(pass|pwd)/i', 'CWE-916'],
            ['code.upload', Severity::MEDIUM, ['php'], '/move_uploaded_file\s*\([^;]*\[\s*[\'"]name[\'"]\s*\]/', 'CWE-434'],
            ['code.weak_random', Severity::LOW, ['php'], '/\b(rand|mt_rand|uniqid|lcg_value|str_shuffle)\s*\(/', 'CWE-338',
                'need' => '/(token|secret|password|passwd|salt|nonce|otp|reset|api_?key|session|csrf)/i'],
            ['code.loose_compare', Severity::LOW, ['php'], '/(\$\w*(token|hash|password|secret|signature|csrf)\w*\s*==\s*[^=]|[^=!]==\s*\$\w*(token|hash|password|secret|signature|csrf)\w*\b)/i', 'CWE-697',
                'not' => '/hash_equals|password_verify/'],

            // ---------------------------------------------------------------- JavaScript / TypeScript
            ['code.xss', Severity::MEDIUM, ['js'], '/(\.(inner|outer)HTML\s*\+?=\s*(?![\'"]\s*[\'"]?\s*;?\s*$)(?=[^;]*(\$\{|[\'"`]\s*\+|\+\s*[\w$]|^[^\'"`]))|insertAdjacentHTML\s*\(|document\.write(ln)?\s*\([^)\'"`]|dangerouslySetInnerHTML|\sv-html=|\{@html\s|\$\([^)]*\)\.(html|append|prepend|after|before)\(\s*[\w$]+\s*\))/', 'CWE-79',
                'not' => '/(DOMPurify|sanitize|escapeHtml|escape\(|textContent)/'],
            ['code.eval', Severity::HIGH, ['js'], '/(?<![\w.])(eval\s*\(|new\s+Function\s*\(|set(Timeout|Interval)\s*\(\s*[\'"`])/', 'CWE-95',
                'not' => '/eval\(function\(p,a,c,k,e,[dr]\)/'],
            ['code.cmd_injection', Severity::HIGH, ['js'], '/\b(exec|execSync|spawn|spawnSync)\s*\(\s*(`[^`]*\$\{|[\'"][^\'"]*[\'"]\s*\+|[\w.]+\s*\+)/', 'CWE-78',
                'need' => '/(child_process|exec|spawn)/'],
            ['code.cmd_injection', Severity::HIGH, ['js'], '/shell\s*:\s*true/', 'CWE-78', 'need' => '/(spawn|exec)/'],
            ['code.sqli', Severity::HIGH, ['js'], '/\.(query|raw|execute|\$queryRawUnsafe|\$executeRawUnsafe)\s*\(\s*(`[^`]*\$\{|[\'"][^\'"]*[\'"]\s*\+)/', 'CWE-89',
                'need' => '/' . self::SQL . '/i'],
            ['code.weak_random', Severity::LOW, ['js'], '/Math\.random\s*\(/', 'CWE-338', 'need' => '/(token|secret|password|salt|nonce|otp|session|csrf|key)/i'],
            ['code.open_redirect', Severity::MEDIUM, ['js'], '/(location\.(href|assign|replace)\s*[=(]|res\.redirect\s*\()\s*[^;]*(req\.(query|params|body)|location\.(search|hash)|URLSearchParams)/', 'CWE-601'],
            ['code.prototype_pollution', Severity::MEDIUM, ['js'], '/\[\s*(req\.(query|body|params)\.\w+|key|k|prop)\s*\]\s*=\s*/', 'CWE-1321',
                'need' => '/(req\.(query|body|params)|JSON\.parse)/'],

            // ---------------------------------------------------------------- Python
            ['code.cmd_injection', Severity::HIGH, ['py'], '/subprocess\.\w+\([^)]*shell\s*=\s*True|os\.(system|popen)\s*\(\s*(f[\'"]|[\'"][^\'"]*[\'"]\s*(%|\+|\.format))/', 'CWE-78'],
            ['code.sqli', Severity::HIGH, ['py'], '/\.(execute|executemany|raw|extra)\s*\(\s*(f[\'"]|[\'"][^\'"]*[\'"]\s*(%|\+|\.format))/', 'CWE-89'],
            ['code.unserialize', Severity::HIGH, ['py'], '/\b(pickle|cPickle|dill|marshal)\.loads?\s*\(|yaml\.load\s*\((?![^)]*Loader\s*=\s*(yaml\.)?(Safe|Base)Loader)|yaml\.unsafe_load/', 'CWE-502'],
            ['code.eval', Severity::HIGH, ['py'], '/(?<![\w.])(eval|exec)\s*\(\s*(?![\'"])/', 'CWE-95'],
            ['code.debug_enabled', Severity::MEDIUM, ['py'], '/^\s*DEBUG\s*=\s*True\b|\.run\s*\([^)]*debug\s*=\s*True/', 'CWE-489'],
            ['code.xss', Severity::MEDIUM, ['py'], '/\|\s*safe\b|mark_safe\s*\(|Markup\s*\(\s*f?[\'"]?[^)]*(request\.|\{)/', 'CWE-79'],

            // ---------------------------------------------------------------- todos
            ['code.tls_verify_off', Severity::HIGH, ['php', 'js', 'py', 'conf'], '/(CURLOPT_SSL_VERIFYPEER\s*(,|=>)\s*(false|0)\b|CURLOPT_SSL_VERIFYHOST\s*(,|=>)\s*(false|0)\b|[\'"]verify_peer(_name)?[\'"]\s*=>\s*false|\bverify\s*=\s*False\b|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\'"]?0|sslverify[\'"]?\s*(=>|:|=)\s*false|InsecureSkipVerify:\s*true)/i', 'CWE-295'],
            ['code.debug_enabled', Severity::MEDIUM, ['php', 'conf'], '/(ini_set\s*\(\s*[\'"]display_errors[\'"]\s*,\s*[\'"]?(1|on|true)|^\s*display_errors\s*=\s*(On|1)\b|define\s*\(\s*[\'"]WP_DEBUG_DISPLAY[\'"]\s*,\s*true|^\s*APP_DEBUG\s*=\s*true|error_reporting\s*\(\s*E_ALL\s*\)\s*;\s*ini_set\s*\(\s*[\'"]display_errors)/i', 'CWE-489'],
            ['code.cors_any', Severity::LOW, ['php', 'js', 'py', 'conf'], '/Access-Control-Allow-Origin[\'"]?\s*(:|,|=>)\s*[\'"]?\s*\*|origin\s*:\s*[\'"]\*[\'"]|CORS_(ORIGIN_)?ALLOW_ALL(_ORIGINS)?\s*=\s*True/i', 'CWE-942'],
        ];
    }

    /** Secretos con formato conocido (en cualquier fichero de texto): patrón => tipo. */
    private const SECRETS = [
        '/-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY( BLOCK)?-----/' => 'private_key',
        '/\b(AKIA|ASIA)[A-Z0-9]{16}\b/' => 'aws',
        '/\bsk_live_[A-Za-z0-9]{20,}\b|\brk_live_[A-Za-z0-9]{20,}\b/' => 'stripe',
        '/\bsk-ant-(api|admin)\d{2}-[A-Za-z0-9_\-]{20,}/' => 'anthropic',
        '/\bsk-(proj-)?[A-Za-z0-9_\-]{40,}\b/' => 'openai',
        '/\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{50,}/' => 'github',
        '/\bxox[abposr]-[A-Za-z0-9\-]{10,}/' => 'slack',
        '/https:\/\/hooks\.slack\.com\/services\/[A-Z0-9]+\/[A-Z0-9]+\/[A-Za-z0-9]+/' => 'slack_webhook',
        '/\bAIza[0-9A-Za-z_\-]{35}\b/' => 'google',
        '/\b\d{8,10}:AA[A-Za-z0-9_\-]{33}\b/' => 'telegram',
        '/\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b/' => 'sendgrid',
        '/\b(sq0atp|sq0csp)-[A-Za-z0-9_\-]{22,}/' => 'square',
        '/\bqs_[A-Za-z0-9]{32,}\b/' => 'quasar',
    ];

    /** Credenciales escritas en el código: clave = 'valor'. */
    private const CREDENTIAL = '/(?<![\w-])(pass(word|wd)?|pwd|db_?pass(word)?|secret|client_?secret|api_?key|apikey|access_?token|auth_?token|private_?key|smtp_?pass(word)?)[\'"]?\s*(=>|=|:)\s*[\'"]([^\'"\s]{6,})[\'"]/i';
    /** Valores que no son una credencial de verdad. */
    private const NOT_CREDENTIAL = '/^(\$|%|\{|<|\[|process\.env|getenv|env\(|os\.environ|config\(|null|none|true|false|password|passwd|secret|changeme|change_me|your[_-]|xxx|\*{3,}|example|required|string|text|hidden|current-password|new-password|sha\d+|md5|bcrypt|argon)/i';

    /** @var array<string,array{check:string,severity:string,cwe:?string,file:string,lines:list<string>,vars:array}> */
    private array $groups = [];
    /** @var list<array> */
    private array $notes = [];
    /** @var array<string,bool>|null ficheros que están en git (si es un repositorio) */
    private ?array $tracked = null;
    private int $files = 0;
    private int $vendored = 0;
    private int $lines = 0;
    private array $langs = [];

    public function __construct(private readonly array $options = [], private readonly ?Osv $osv = null)
    {
    }

    /** @return array{findings:list<Finding>,notes:list<array>,meta:array} */
    public function run(string $dir): array
    {
        $dir = rtrim($dir, '/');
        $this->tracked = $this->gitFiles($dir);
        $maxFiles = (int) ($this->options['max_files'] ?? 20000);
        $maxSize = (int) ($this->options['max_file_size'] ?? 1048576);
        $lockfiles = [];

        $it = new \RecursiveIteratorIterator(
            new \RecursiveCallbackFilterIterator(
                new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS),
                static fn (\SplFileInfo $f) => !($f->isDir() && in_array($f->getFilename(), self::SKIP_DIRS, true)) && !$f->isLink()
            ),
            \RecursiveIteratorIterator::LEAVES_ONLY
        );
        foreach ($it as $file) {
            /** @var \SplFileInfo $file */
            $rel = substr($file->getPathname(), strlen($dir) + 1);
            $name = $file->getFilename();
            if (in_array($name, ['composer.lock', 'package-lock.json', 'yarn.lock', 'requirements.txt'], true)) {
                $lockfiles[] = $rel;
            }
            if ($this->files >= $maxFiles) {
                $this->notes[] = ['notes.max_files', ['max' => $maxFiles]];
                break;
            }
            if ($file->getSize() > $maxSize || !$file->isReadable()) {
                continue;
            }
            $lang = $this->lang($name);
            if ($lang === null) {
                continue;
            }
            $this->files++;
            $this->langs[$lang] = ($this->langs[$lang] ?? 0) + 1;
            $this->scanFile($file->getPathname(), $rel, $lang);
        }
        $this->dependencies($dir, $lockfiles);

        $findings = [];
        foreach ($this->groups as $g) {
            $first = $g['lines'][0] ?? '';
            $line = preg_match('/^L(\d+)/', $first, $m) ? ':' . $m[1] : '';
            $findings[] = new Finding($g['check'], $g['severity'], $g['vars'] + ['file' => $g['file'], 'count' => (string) max(1, count($g['lines']))],
                $g['file'] . $line, Redactor::clean(implode("\n", array_slice($g['lines'], 0, 6)) . (count($g['lines']) > 6 ? "\n… +" . (count($g['lines']) - 6) : ''), 900),
                $g['cwe'], $g['key'] ?? '');
        }
        return ['findings' => $findings, 'notes' => $this->notes, 'meta' => ['files' => $this->files, 'vendored' => $this->vendored, 'lines' => $this->lines, 'languages' => $this->langs, 'git' => $this->tracked !== null]];
    }

    private function lang(string $name): ?string
    {
        if (preg_match('/^\.env(\..+)?$/', $name)) {
            return 'conf';
        }
        if (preg_match('/\.min\.(js|css)$/', $name) || in_array($name, ['package-lock.json', 'composer.lock', 'yarn.lock'], true)) {
            return null;
        }
        $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
        if ($name === '.htaccess' || $name === '.user.ini') {
            return 'conf';
        }
        foreach (self::LANGS as $lang => $exts) {
            if (in_array($ext, $exts, true)) {
                return $lang;
            }
        }
        return null;
    }

    private function scanFile(string $path, string $rel, string $lang): void
    {
        $content = (string) @file_get_contents($path);
        if ($content === '' || str_contains(substr($content, 0, 1024), "\0")) {
            return;
        }
        $isTest = (bool) preg_match('#(^|/)(tests?|spec|__tests__|fixtures|examples?)/|\.(test|spec)\.\w+$#i', $rel);
        $isLangFile = (bool) preg_match('#(^|/)(lang|locales?|i18n|translations)/#i', $rel);
        // Librería de terceros copiada en el proyecto (jQuery, plugins…): solo se buscan secretos; sus fallos se
        // ven en las dependencias o en el análisis web de las librerías
        $isVendored = $lang === 'js' && preg_match('/@license|\(c\)\s*\d{4}|copyright|released under the|@version\s+\d|\* v\d+\.\d+\.\d+/i', substr($content, 0, 800));
        $this->vendored += $isVendored ? 1 : 0;
        $isExample = (bool) preg_match('/\.(example|sample|dist|template)$|\.env\.(example|sample|dist)$/i', $rel);
        $rules = self::rules();
        $lines = preg_split('/\r\n|\n|\r/', $content) ?: [];
        $this->lines += count($lines);

        if (preg_match('/^\.env(\.(?!example|sample|dist|template).+)?$/', basename($rel)) && preg_match('/^\s*[A-Z_]*(PASS|SECRET|KEY|TOKEN)[A-Z_]*\s*=\s*\S{4,}/m', $content)) {
            $committed = $this->tracked !== null && isset($this->tracked[$rel]);
            $this->group('code.env_file', $committed ? Severity::HIGH : Severity::MEDIUM, 'CWE-538', $rel, 'L1: ' . basename($rel), ['committed' => $committed ? 'git' : '-']);
        }

        foreach ($lines as $i => $line) {
            if (strlen($line) > 1500) {
                continue;   // código minificado o datos
            }
            $n = $i + 1;
            $trim = ltrim($line);
            $comment = $trim === '' || str_starts_with($trim, '//') || str_starts_with($trim, '*') || str_starts_with($trim, '/*') || ($lang !== 'js' && str_starts_with($trim, '#'));

            foreach (self::SECRETS as $re => $kind) {
                if (preg_match($re, $line)) {
                    $this->group('code.secret', Severity::CRITICAL, 'CWE-798', $rel, "L$n: " . trim($line), ['kind' => $kind], $kind);
                }
            }
            if (!$isLangFile && !$isExample && !$comment && preg_match(self::CREDENTIAL, $line, $m) && !preg_match(self::NOT_CREDENTIAL, $m[5])
                && !preg_match('/^[a-z_]+(\.[a-z_]+)+$/i', $m[5])) {
                $this->group('code.hardcoded_credential', $isTest ? Severity::LOW : Severity::HIGH, 'CWE-798', $rel, "L$n: " . trim($line));
            }
            if ($comment || $isTest || $isVendored) {
                continue;
            }
            foreach ($rules as $r) {
                [$check, $severity, $langs, $re, $cwe] = $r;
                if (!in_array($lang, $langs, true) || !preg_match($re, $line)) {
                    continue;
                }
                if ((isset($r['need']) && !preg_match($r['need'], $line)) || (isset($r['not']) && preg_match($r['not'], $line))) {
                    continue;
                }
                if (isset($r['stronger']) && preg_match($r['stronger'][0], $line)) {
                    $severity = $r['stronger'][1];
                }
                $this->group($check, $severity, $cwe, $rel, "L$n: " . trim($line));
            }
        }
    }

    private function group(string $check, string $severity, ?string $cwe, string $file, string $line, array $vars = [], string $key = ''): void
    {
        $id = $check . '|' . $file . '|' . $key;
        if (!isset($this->groups[$id])) {
            $this->groups[$id] = ['check' => $check, 'severity' => $severity, 'cwe' => $cwe, 'file' => $file, 'lines' => [], 'vars' => $vars, 'key' => $key];
        } elseif (Severity::rank($severity) < Severity::rank($this->groups[$id]['severity'])) {
            $this->groups[$id]['severity'] = $severity;
        }
        if (!in_array($line, $this->groups[$id]['lines'], true)) {
            $this->groups[$id]['lines'][] = mb_substr($line, 0, 240);
        }
    }

    // ------------------------------------------------------------------------------------------------ dependencias

    /** @param list<string> $lockfiles */
    private function dependencies(string $dir, array $lockfiles): void
    {
        if (!$lockfiles) {
            return;
        }
        if ($this->osv === null) {
            $this->notes[] = ['notes.osv_off', []];
            return;
        }
        foreach ($lockfiles as $rel) {
            $packages = $this->parseLock($dir . '/' . $rel, basename($rel));
            if (!$packages) {
                continue;
            }
            $byPkg = [];
            foreach ($this->osv->check($packages) as $v) {
                $byPkg[$v['package']['name'] . '@' . $v['package']['version']][] = $v;
            }
            foreach ($byPkg as $vulns) {
                usort($vulns, static fn ($a, $b) => Severity::rank($a['severity']) <=> Severity::rank($b['severity']));
                $p = $vulns[0]['package'];
                $fixed = array_filter(array_column($vulns, 'fixed'));
                usort($fixed, 'version_compare');
                $lines = array_map(static fn ($v) => ($v['aliases'][0] ?? $v['id']) . ' · ' . $v['summary'], array_slice($vulns, 0, 8));
                $this->groups['dep|' . $rel . '|' . $p['name']] = [
                    'check' => 'code.dep_vulnerable', 'severity' => $vulns[0]['severity'], 'cwe' => 'CWE-1104', 'file' => $rel,
                    'lines' => $lines, 'key' => $p['name'],
                    'vars' => ['package' => $p['name'], 'version' => $p['version'], 'ecosystem' => $p['ecosystem'], 'vulns' => (string) count($vulns), 'fixed' => $fixed ? (string) end($fixed) : '?'],
                ];
            }
            if ($this->osv->error !== null) {
                $this->notes[] = ['notes.osv_failed', ['error' => $this->osv->error]];
                return;
            }
        }
    }

    /** @return list<array{ecosystem:string,name:string,version:string}> */
    private function parseLock(string $path, string $name): array
    {
        $raw = (string) @file_get_contents($path);
        $out = [];
        switch ($name) {
            case 'composer.lock':
                $j = json_decode($raw, true) ?: [];
                foreach (array_merge($j['packages'] ?? [], $j['packages-dev'] ?? []) as $p) {
                    $out[] = ['ecosystem' => 'Packagist', 'name' => (string) $p['name'], 'version' => ltrim((string) $p['version'], 'v')];
                }
                break;
            case 'package-lock.json':
                $j = json_decode($raw, true) ?: [];
                foreach ($j['packages'] ?? [] as $key => $p) {
                    if ($key !== '' && isset($p['version'])) {
                        $out[] = ['ecosystem' => 'npm', 'name' => (string) ($p['name'] ?? preg_replace('#^.*node_modules/#', '', $key)), 'version' => (string) $p['version']];
                    }
                }
                if (!isset($j['packages'])) {
                    $walk = static function (array $deps) use (&$walk, &$out): void {
                        foreach ($deps as $n => $p) {
                            if (isset($p['version'])) {
                                $out[] = ['ecosystem' => 'npm', 'name' => (string) $n, 'version' => (string) $p['version']];
                            }
                            $walk($p['dependencies'] ?? []);
                        }
                    };
                    $walk($j['dependencies'] ?? []);
                }
                break;
            case 'yarn.lock':
                if (preg_match_all('/^"?(@?[^@\s"]+)@[^\n]*\n\s+version:? "?([^"\s]+)"?/m', $raw, $m, PREG_SET_ORDER)) {
                    foreach ($m as $p) {
                        $out[] = ['ecosystem' => 'npm', 'name' => $p[1], 'version' => $p[2]];
                    }
                }
                break;
            case 'requirements.txt':
                if (preg_match_all('/^\s*([A-Za-z0-9_.\-]+)(\[[^\]]*\])?\s*==\s*([0-9][^\s;#]*)/m', $raw, $m, PREG_SET_ORDER)) {
                    foreach ($m as $p) {
                        $out[] = ['ecosystem' => 'PyPI', 'name' => $p[1], 'version' => $p[3]];
                    }
                }
                break;
        }
        // Sin repetidos (package-lock tiene la misma versión en muchas carpetas)
        $uniq = [];
        foreach ($out as $p) {
            $uniq[$p['ecosystem'] . '|' . $p['name'] . '|' . $p['version']] = $p;
        }
        return array_values($uniq);
    }

    /** @return array<string,bool>|null */
    private function gitFiles(string $dir): ?array
    {
        if (!is_dir($dir . '/.git') || !function_exists('shell_exec')) {
            return null;
        }
        $out = @shell_exec('git -C ' . escapeshellarg($dir) . ' ls-files 2>/dev/null');
        return is_string($out) && $out !== '' ? array_fill_keys(array_filter(explode("\n", $out)), true) : null;
    }
}

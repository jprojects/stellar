<?php
declare(strict_types=1);

namespace Quasar\Scanner;

/**
 * Stellar · análisis de una web en producción, **sin hacer daño**: peticiones como las de un navegador o un buscador
 * (GET/HEAD, un TRACE y, en WordPress, una llamada inocua demo.sayHello a xmlrpc.php), sin enviar formularios, sin
 * probar contraseñas y sin cargas de ataque (lo más «activo» es añadir a la portada un parámetro con comillas para ver
 * si la web lo devuelve sin escapar o muestra un error).
 *
 * Controles: HTTPS y redirección, certificado y protocolos TLS antiguos, cabeceras de seguridad, cookies, versión del
 * servidor, contenido mixto, formularios, ficheros expuestos (.git, .env, copias, logs, phpinfo…) verificados por su
 * contenido, listados de carpetas, CORS, errores y modo depuración visibles, parámetros reflejados, TRACE, CMS
 * (WordPress, Joomla, Drupal, PrestaShop) y librerías JavaScript con vulnerabilidades conocidas (OSV.dev).
 *
 * Devuelve hallazgos (Finding) y notas de lo que no se ha podido comprobar.
 */
final class WebScanner
{
    /** Ficheros que no deberían ser públicos: ruta => [control, gravedad, firma (regex sobre el contenido), CWE]. */
    private const EXPOSED = [
        '/.git/HEAD' => ['web.vcs_exposed', Severity::CRITICAL, '/^(ref: refs\/|[0-9a-f]{40}\s*$)/', 'CWE-527'],
        '/.git/config' => ['web.vcs_exposed', Severity::CRITICAL, '/^\s*\[core\]/m', 'CWE-527'],
        '/.svn/entries' => ['web.vcs_exposed', Severity::CRITICAL, '/^(\d+\s*$|<\?xml.*wc-entries)/s', 'CWE-527'],
        '/.svn/wc.db' => ['web.vcs_exposed', Severity::CRITICAL, '/^SQLite format 3/', 'CWE-527'],
        '/.env' => ['web.env_exposed', Severity::CRITICAL, '/^\s*[A-Z][A-Z0-9_]{2,}\s*=/m', 'CWE-538'],
        '/.env.local' => ['web.env_exposed', Severity::CRITICAL, '/^\s*[A-Z][A-Z0-9_]{2,}\s*=/m', 'CWE-538'],
        '/.env.production' => ['web.env_exposed', Severity::CRITICAL, '/^\s*[A-Z][A-Z0-9_]{2,}\s*=/m', 'CWE-538'],
        '/.env.backup' => ['web.env_exposed', Severity::CRITICAL, '/^\s*[A-Z][A-Z0-9_]{2,}\s*=/m', 'CWE-538'],
        '/wp-config.php.bak' => ['web.config_backup', Severity::CRITICAL, '/<\?php|DB_PASSWORD/', 'CWE-530'],
        '/wp-config.php~' => ['web.config_backup', Severity::CRITICAL, '/<\?php|DB_PASSWORD/', 'CWE-530'],
        '/wp-config.php.old' => ['web.config_backup', Severity::CRITICAL, '/<\?php|DB_PASSWORD/', 'CWE-530'],
        '/wp-config.php.save' => ['web.config_backup', Severity::CRITICAL, '/<\?php|DB_PASSWORD/', 'CWE-530'],
        '/wp-config.txt' => ['web.config_backup', Severity::CRITICAL, '/<\?php|DB_PASSWORD/', 'CWE-530'],
        '/configuration.php.bak' => ['web.config_backup', Severity::CRITICAL, '/<\?php|\$password/', 'CWE-530'],
        '/config.php.bak' => ['web.config_backup', Severity::CRITICAL, '/<\?php/', 'CWE-530'],
        '/config/config.local.php.bak' => ['web.config_backup', Severity::CRITICAL, '/<\?php/', 'CWE-530'],
        '/backup.zip' => ['web.backup_exposed', Severity::CRITICAL, '/^PK\x03\x04/', 'CWE-530'],
        '/backup.tar.gz' => ['web.backup_exposed', Severity::CRITICAL, '/^\x1f\x8b/', 'CWE-530'],
        '/www.zip' => ['web.backup_exposed', Severity::CRITICAL, '/^PK\x03\x04/', 'CWE-530'],
        '/site.zip' => ['web.backup_exposed', Severity::CRITICAL, '/^PK\x03\x04/', 'CWE-530'],
        '/{host}.zip' => ['web.backup_exposed', Severity::CRITICAL, '/^PK\x03\x04/', 'CWE-530'],
        '/backup.sql' => ['web.backup_exposed', Severity::CRITICAL, '/(CREATE TABLE|INSERT INTO|-- MySQL dump|-- MariaDB dump|-- phpMyAdmin SQL Dump)/i', 'CWE-530'],
        '/dump.sql' => ['web.backup_exposed', Severity::CRITICAL, '/(CREATE TABLE|INSERT INTO|-- MySQL dump|-- MariaDB dump|-- phpMyAdmin SQL Dump)/i', 'CWE-530'],
        '/database.sql' => ['web.backup_exposed', Severity::CRITICAL, '/(CREATE TABLE|INSERT INTO|-- MySQL dump|-- MariaDB dump|-- phpMyAdmin SQL Dump)/i', 'CWE-530'],
        '/db.sql' => ['web.backup_exposed', Severity::CRITICAL, '/(CREATE TABLE|INSERT INTO|-- MySQL dump|-- MariaDB dump|-- phpMyAdmin SQL Dump)/i', 'CWE-530'],
        '/.vscode/sftp.json' => ['web.ftp_config_exposed', Severity::CRITICAL, '/"(host|remotePath)"\s*:/', 'CWE-538'],
        '/sftp-config.json' => ['web.ftp_config_exposed', Severity::CRITICAL, '/"(host|remote_path)"\s*:/', 'CWE-538'],
        '/.htpasswd' => ['web.htpasswd_exposed', Severity::HIGH, '/^[^:\s]+:(\$apr1\$|\$2[aby]\$|\{SHA\}|[A-Za-z0-9.\/]{13}\s*$)/m', 'CWE-538'],
        '/adminer.php' => ['web.adminer_exposed', Severity::HIGH, '/Adminer/', 'CWE-668'],
        '/phpinfo.php' => ['web.phpinfo_exposed', Severity::MEDIUM, '/phpinfo\(\)|<title>PHP \d/', 'CWE-200'],
        '/info.php' => ['web.phpinfo_exposed', Severity::MEDIUM, '/phpinfo\(\)|<title>PHP \d/', 'CWE-200'],
        '/test.php' => ['web.phpinfo_exposed', Severity::MEDIUM, '/phpinfo\(\)|<title>PHP \d/', 'CWE-200'],
        '/wp-content/debug.log' => ['web.log_exposed', Severity::MEDIUM, '/PHP (Fatal error|Warning|Notice|Parse error|Deprecated)/', 'CWE-532'],
        '/error_log' => ['web.log_exposed', Severity::MEDIUM, '/PHP (Fatal error|Warning|Notice|Parse error|Deprecated)/', 'CWE-532'],
        '/error.log' => ['web.log_exposed', Severity::MEDIUM, '/PHP (Fatal error|Warning|Notice|Parse error|Deprecated)|\[(error|crit)\]/', 'CWE-532'],
        '/debug.log' => ['web.log_exposed', Severity::MEDIUM, '/PHP (Fatal error|Warning|Notice|Parse error|Deprecated)|Stack trace/', 'CWE-532'],
        '/storage/logs/laravel.log' => ['web.log_exposed', Severity::MEDIUM, '/\[\d{4}-\d\d-\d\d [\d:]+\] \w+\.(ERROR|WARNING|INFO)/', 'CWE-532'],
        '/server-status' => ['web.server_status', Severity::MEDIUM, '/Apache Server Status/', 'CWE-200'],
        '/phpmyadmin/' => ['web.phpmyadmin_exposed', Severity::MEDIUM, '/phpMyAdmin/', 'CWE-668'],
        '/_profiler/' => ['web.debug_mode', Severity::HIGH, '/Symfony Profiler/', 'CWE-489'],
        '/telescope' => ['web.debug_mode', Severity::HIGH, '/Laravel Telescope|<title>Telescope/', 'CWE-489'],
        '/.DS_Store' => ['web.junk_files', Severity::LOW, '/^\x00\x00\x00\x01Bud1/', 'CWE-538'],
        '/.idea/workspace.xml' => ['web.junk_files', Severity::LOW, '/<project version=/', 'CWE-538'],
    ];

    /** Carpetas en las que se busca un listado de ficheros. */
    private const LISTING_DIRS = ['/uploads/', '/images/', '/files/', '/backup/', '/wp-content/uploads/', '/storage/', '/tmp/'];

    /** Errores y trazas que no deberían verse en producción: patrón => tipo. */
    private const ERROR_PATTERNS = [
        '/You have an error in your SQL syntax|SQLSTATE\[\w+\]|mysqli?_[a-z_]+\(\)|PDOException|ORA-\d{5}|pg_query\(\)|Unclosed quotation mark/i' => 'sql',
        '/<b>(Fatal error|Warning|Notice|Parse error|Deprecated)<\/b>:|PHP (Fatal error|Warning|Notice):/' => 'php',
        '/Stack trace:|Traceback \(most recent call last\)|\bat [a-z]+\.[A-Za-z.$]+\([A-Za-z]+\.java:\d+\)/' => 'trace',
        '/Whoops! There was an error|ignition-|You\'re seeing this error because you have <code>DEBUG = True<\/code>|Symfony Exception|<title>Laravel<\/title>.*?Exception/s' => 'debug',
    ];

    /** Librerías JavaScript: paquete npm => patrón de la cabecera de licencia del fichero (grupo 1 = versión). */
    private const JS_BANNERS = [
        'jquery' => '/jQuery (?:JavaScript Library )?v(\d+\.\d+\.\d+)/',
        'jquery-ui' => '/jQuery UI - v(\d+\.\d+\.\d+)/',
        'jquery-migrate' => '/jQuery Migrate (?:- )?v(\d+\.\d+\.\d+)/',
        'bootstrap' => '/Bootstrap v(\d+\.\d+\.\d+)/',
        'angular' => '/AngularJS v(\d+\.\d+\.\d+)/',
        'lodash' => '/(?:@license )?Lodash (?:lodash\.com )?(?:v)?(\d+\.\d+\.\d+)/i',
        'underscore' => '/Underscore\.js (\d+\.\d+\.\d+)/',
        'moment' => '/version : (\d+\.\d+\.\d+)[\s\S]{0,80}momentjs/',
        'vue' => '/Vue\.js v(\d+\.\d+\.\d+)/',
        'handlebars' => '/Handlebars(?:\.js)? v(\d+\.\d+\.\d+)/i',
        'dompurify' => '/DOMPurify (\d+\.\d+\.\d+)/',
        'axios' => '/[Aa]xios v(\d+\.\d+\.\d+)/',
    ];

    /** Scripts de terceros que no pueden llevar integrity porque cambian solos. */
    private const SRI_EXEMPT = '/(googletagmanager|google-analytics|gstatic|google\.com\/recaptcha|googleapis\.com\/maps|facebook\.net|hotjar|clarity\.ms|cookiebot|cookieyes|stripe\.com|paypal\.com|hs-scripts|doubleclick)/i';

    /** @var list<Finding> */
    private array $findings = [];
    /** @var list<array{0:string,1:array}> notas (clave de idioma + variables) */
    private array $notes = [];
    private HttpClient $http;
    private string $origin = '';
    private ?array $baseline = null;
    /** @var array<string,mixed> */
    private array $meta = [];

    /**
     * @param array $target  TargetGuard::web()
     * @param array $options user_agent, max_requests, delay_ms, timeout, osv (bool), tls_legacy (bool)
     */
    public function __construct(private array $target, private readonly array $options = [], private readonly ?Osv $osv = null)
    {
        $this->http = $this->client($target['host'], $target['ips']);
    }

    /** @return array{findings:list<Finding>,notes:list<array>,requests:int,meta:array} */
    public function run(): array
    {
        $home = $this->home();
        try {
            $this->transport($home);
            $this->headers($home);
            $this->cookies($home);
            $libs = $this->html($home);
            $this->baseline();
            $this->exposedFiles();
            $this->listings();
            $this->cors();
            $this->errorsAndReflection();
            $this->trace();
            $this->cms($home);
            $this->wellKnown();
            $this->jsLibraries($libs);
        } catch (RequestLimitException) {
            $this->notes[] = ['notes.request_limit', ['max' => (int) ($this->options['max_requests'] ?? 150)]];
        }
        return ['findings' => $this->findings, 'notes' => $this->notes, 'requests' => $this->http->count(), 'meta' => $this->meta];
    }

    // ------------------------------------------------------------------------------------------------ portada

    /** Portada, siguiendo redirecciones dentro del mismo dominio (también con o sin www). */
    private function home(): array
    {
        $url = $this->target['url'];
        $chain = [];
        for ($i = 0; $i < 6; $i++) {
            $resp = $this->http->get($url);
            if ($resp['error'] !== null) {
                throw new ScanException('errors.unreachable', ['url' => $url, 'error' => $resp['error']]);
            }
            $location = HttpClient::header($resp, 'location');
            if ($resp['status'] < 300 || $resp['status'] >= 400 || $location === null) {
                break;
            }
            $next = self::absolute($location, $url);
            $chain[] = $resp['status'] . ' → ' . $next;
            $nextHost = strtolower((string) parse_url($next, PHP_URL_HOST));
            if ($nextHost !== $this->target['host']) {
                if (preg_replace('/^www\./', '', $nextHost) !== preg_replace('/^www\./', '', $this->target['host'])) {
                    throw new ScanException('errors.redirect_away', ['url' => $next]);
                }
                $guard = (new TargetGuard((array) ($this->options['guard'] ?? [])))->web($next);
                $this->target = $guard;
                $this->http = $this->client($guard['host'], $guard['ips'], $this->http->count());
            }
            $url = $next;
        }
        if ($resp['status'] >= 400 && $resp['status'] !== 401 && $resp['status'] !== 403) {
            $this->notes[] = ['notes.home_status', ['status' => $resp['status']]];
        }
        $p = parse_url($url);
        $this->target['scheme'] = strtolower((string) $p['scheme']);
        $this->origin = $this->target['scheme'] . '://' . $this->target['host'] . (isset($p['port']) ? ':' . $p['port'] : '');
        $this->meta = [
            'final_url' => $url,
            'redirects' => $chain,
            'ip' => $resp['ip'],
            'status' => $resp['status'],
            'server' => HttpClient::header($resp, 'server'),
        ];
        return $resp;
    }

    // ------------------------------------------------------------------------------------------------ HTTPS y TLS

    private function transport(array $home): void
    {
        $host = $this->target['host'];
        if ($this->target['scheme'] === 'http') {
            // ¿Hay HTTPS aunque no se use?
            $https = $this->http->request('HEAD', "https://$host/", [], 1024);
            if ($https['error'] !== null || $https['status'] === 0) {
                $this->add('web.no_https', Severity::HIGH, [], $this->meta['final_url'], 'HTTP ' . $home['status'] . ' (sin HTTPS)', 'CWE-319');
                if ($this->hasPassword($home['body'])) {
                    $this->add('web.form_http', Severity::HIGH, [], $this->meta['final_url'], '<input type="password"> en una página HTTP', 'CWE-319');
                }
                return;
            }
            $this->add('web.no_https_redirect', Severity::HIGH, [], $this->meta['final_url'], "http://$host/ → HTTP " . $home['status'], 'CWE-319');
        } else {
            $plain = $this->http->request('HEAD', "http://$host/", [], 1024);
            $loc = (string) HttpClient::header($plain, 'location');
            if ($plain['error'] === null && $plain['status'] > 0 && !($plain['status'] >= 300 && $plain['status'] < 400 && str_starts_with(strtolower($loc), 'https://'))) {
                $this->add('web.no_https_redirect', Severity::MEDIUM, [], "http://$host/", "http://$host/ → HTTP " . $plain['status'] . ($loc !== '' ? " ($loc)" : ''), 'CWE-319');
            }
        }
        $this->certificate();
        if (($this->options['tls_legacy'] ?? true) !== false) {
            $this->legacyTls();
        }
    }

    private function certificate(): void
    {
        $host = $this->target['host'];
        $ip = $this->target['ips'][0];
        $port = $this->target['port'] ?? 443;
        $connect = static function (bool $verify) use ($host, $ip, $port, &$err) {
            $ctx = stream_context_create(['ssl' => [
                'capture_peer_cert' => true, 'verify_peer' => $verify, 'verify_peer_name' => $verify,
                'peer_name' => $host, 'SNI_enabled' => true, 'allow_self_signed' => !$verify,
            ]]);
            $target = 'ssl://' . (str_contains($ip, ':') ? "[$ip]" : $ip) . ':' . $port;
            $s = @stream_socket_client($target, $errno, $errstr, 10, STREAM_CLIENT_CONNECT, $ctx);
            if ($s === false) {
                $err = trim(preg_replace('/\s+/', ' ', (string) (error_get_last()['message'] ?? $errstr)));
                return null;
            }
            $params = stream_context_get_params($s);
            fclose($s);
            return $params['options']['ssl']['peer_certificate'] ?? null;
        };
        $err = null;
        $cert = $connect(true);
        if ($cert === null) {
            $verifyError = $err;
            $cert = $connect(false);
            if ($cert === null) {
                $this->notes[] = ['notes.tls_failed', ['error' => (string) $err]];
                return;
            }
            $this->add('web.tls_invalid', Severity::CRITICAL, ['error' => self::short((string) $verifyError)], "https://$host/", (string) $verifyError, 'CWE-295');
        }
        $info = openssl_x509_parse($cert) ?: [];
        $days = (int) floor(((int) ($info['validTo_time_t'] ?? 0) - time()) / 86400);
        $this->meta['tls'] = [
            'issuer' => (string) ($info['issuer']['O'] ?? $info['issuer']['CN'] ?? ''),
            'expires' => date('Y-m-d', (int) ($info['validTo_time_t'] ?? 0)),
            'days' => $days,
        ];
        if ($days < 0) {
            $this->add('web.tls_expired', Severity::CRITICAL, ['date' => $this->meta['tls']['expires']], "https://$host/", 'notAfter: ' . $this->meta['tls']['expires'], 'CWE-298');
        } elseif ($days < 21) {
            $this->add('web.tls_expiring', Severity::MEDIUM, ['days' => $days, 'date' => $this->meta['tls']['expires']], "https://$host/", 'notAfter: ' . $this->meta['tls']['expires'], 'CWE-298');
        }
    }

    /** ¿Acepta TLS 1.0 o 1.1? (obsoletos desde 2021, RFC 8996). */
    private function legacyTls(): void
    {
        if (!defined('CURL_SSLVERSION_MAX_TLSv1_1')) {
            return;
        }
        foreach (['TLS 1.0' => [CURL_SSLVERSION_TLSv1_0, CURL_SSLVERSION_MAX_TLSv1_0], 'TLS 1.1' => [CURL_SSLVERSION_TLSv1_1, CURL_SSLVERSION_MAX_TLSv1_1]] as $name => [$min, $max]) {
            $r = $this->http->request('HEAD', $this->origin . '/', [], 1024, [
                CURLOPT_SSLVERSION => $min | $max,
                CURLOPT_SSL_CIPHER_LIST => 'DEFAULT@SECLEVEL=0',
                CURLOPT_SSL_VERIFYPEER => false,
                CURLOPT_SSL_VERIFYHOST => 0,
            ]);
            if ($r['error'] === null && $r['status'] > 0) {
                $this->add('web.tls_legacy', Severity::MEDIUM, ['protocol' => $name], $this->origin . '/', "Handshake $name OK", 'CWE-327', $name);
            }
        }
    }

    // ------------------------------------------------------------------------------------------------ cabeceras

    private function headers(array $r): void
    {
        $url = $this->meta['final_url'];
        $h = static fn (string $n) => HttpClient::header($r, $n);
        $https = $this->target['scheme'] === 'https';

        if ($https) {
            $hsts = $h('strict-transport-security');
            if ($hsts === null) {
                $this->add('web.hsts_missing', Severity::MEDIUM, [], $url, 'Strict-Transport-Security: —', 'CWE-319');
            } elseif (preg_match('/max-age\s*=\s*"?(\d+)/i', $hsts, $m) && (int) $m[1] < 15552000) {
                $this->add('web.hsts_weak', Severity::LOW, ['days' => intdiv((int) $m[1], 86400)], $url, "Strict-Transport-Security: $hsts", 'CWE-319');
            }
        }

        $csp = $h('content-security-policy');
        if ($csp === null) {
            $this->add('web.csp_missing', Severity::MEDIUM, [], $url, 'Content-Security-Policy: —', 'CWE-1021');
        } else {
            $script = preg_match('/(?:^|;)\s*script-src\s+([^;]*)/i', $csp, $m) ? $m[1]
                : (preg_match('/(?:^|;)\s*default-src\s+([^;]*)/i', $csp, $m) ? $m[1] : '*');
            $weak = [];
            if (str_contains($script, "'unsafe-inline'") && !preg_match("/'(nonce-|sha(256|384|512)-|strict-dynamic)/", $script)) {
                $weak[] = "'unsafe-inline'";
            }
            if (str_contains($script, "'unsafe-eval'")) {
                $weak[] = "'unsafe-eval'";
            }
            if (preg_match('/(^|\s)(\*|https?:|data:)(\s|$)/', $script)) {
                $weak[] = 'script-src *';
            }
            if ($weak) {
                $this->add('web.csp_weak', Severity::LOW, ['issues' => implode(', ', $weak)], $url, 'Content-Security-Policy: ' . $csp, 'CWE-1021');
            }
        }

        $xfo = $h('x-frame-options');
        if ($xfo === null && ($csp === null || !preg_match('/frame-ancestors/i', $csp))) {
            $this->add('web.clickjacking', Severity::MEDIUM, [], $url, 'X-Frame-Options: — · frame-ancestors: —', 'CWE-1021');
        }
        if (strtolower((string) $h('x-content-type-options')) !== 'nosniff') {
            $this->add('web.nosniff_missing', Severity::LOW, [], $url, 'X-Content-Type-Options: ' . ($h('x-content-type-options') ?? '—'), 'CWE-693');
        }
        if ($h('referrer-policy') === null) {
            $this->add('web.referrer_missing', Severity::LOW, [], $url, 'Referrer-Policy: —', 'CWE-200');
        }
        if ($h('permissions-policy') === null) {
            $this->add('web.permissions_missing', Severity::INFO, [], $url, 'Permissions-Policy: —', 'CWE-693');
        }

        foreach (['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version', 'x-generator', 'x-drupal-cache', 'x-runtime'] as $name) {
            foreach ($r['headers'][$name] ?? [] as $value) {
                if ($name === 'server' && !preg_match('/\d/', $value)) {
                    continue;   // "Server: nginx" sin versión no dice gran cosa
                }
                if ($name === 'x-drupal-cache' || $name === 'x-runtime') {
                    continue;
                }
                $this->add('web.server_version', Severity::LOW, ['header' => self::title($name), 'value' => $value], $url, self::title($name) . ': ' . $value, 'CWE-200', $name);
            }
        }
    }

    private function cookies(array $r): void
    {
        $https = $this->target['scheme'] === 'https';
        foreach ($r['headers']['set-cookie'] ?? [] as $raw) {
            $parts = array_map('trim', explode(';', $raw));
            $name = trim((string) strstr($parts[0], '=', true));
            if ($name === '') {
                continue;
            }
            $attrs = strtolower(implode(';', array_slice($parts, 1)));
            $missing = [];
            if ($https && !preg_match('/(^|;)secure(;|$)/', $attrs)) {
                $missing[] = 'Secure';
            }
            $csrfCookie = (bool) preg_match('/xsrf|csrf/i', $name);
            if (!$csrfCookie && !preg_match('/(^|;)httponly(;|$)/', $attrs)) {
                $missing[] = 'HttpOnly';
            }
            if (!str_contains($attrs, 'samesite=')) {
                $missing[] = 'SameSite';
            }
            if (!$missing) {
                continue;
            }
            $session = (bool) preg_match('/sess|sid$|^sid|auth|token|login|remember|logged|jwt/i', $name);
            $severity = $session && (in_array('Secure', $missing, true) || in_array('HttpOnly', $missing, true)) ? Severity::MEDIUM : Severity::LOW;
            $this->add('web.cookie_flags', $severity, ['cookie' => $name, 'missing' => implode(', ', $missing)], $this->meta['final_url'],
                'Set-Cookie: ' . $name . '=…; ' . implode('; ', array_slice($parts, 1)), 'CWE-614', $name);
        }
    }

    // ------------------------------------------------------------------------------------------------ HTML de la portada

    /** @return array{found:array<string,string>,scripts:list<string>} librerías JS de las URL (paquete => versión) y scripts propios para leer */
    private function html(array $r): array
    {
        $body = $r['body'];
        $url = $this->meta['final_url'];
        $libs = ['found' => [], 'scripts' => []];
        if ($body === '' || !preg_match('/<(html|head|body|script)\b/i', $body)) {
            return $libs;
        }

        if ($this->target['scheme'] === 'https') {
            preg_match_all('/<(?:script|img|iframe|audio|video|source|embed)\b[^>]*\ssrc=["\'](http:\/\/[^"\']+)|<link\b[^>]*rel=["\']?stylesheet[^>]*href=["\'](http:\/\/[^"\']+)|<link\b[^>]*href=["\'](http:\/\/[^"\']+)["\'][^>]*rel=["\']?stylesheet/i', $body, $m);
            $mixed = array_values(array_unique(array_filter(array_merge($m[1], $m[2], $m[3]))));
            if ($mixed) {
                $this->add('web.mixed_content', Severity::MEDIUM, ['count' => count($mixed)], $url, implode("\n", array_slice($mixed, 0, 6)), 'CWE-319');
            }
            if (preg_match_all('/<form\b[^>]*action=["\'](http:\/\/[^"\']+)/i', $body, $fm)) {
                $this->add('web.form_http', Severity::HIGH, [], $url, implode("\n", array_unique($fm[1])), 'CWE-319');
            }
        }

        // Scripts de otros dominios sin integrity (SRI)
        preg_match_all('/<script\b([^>]*)>/i', $body, $sm);
        $noSri = [];
        foreach ($sm[1] as $attrs) {
            if (!preg_match('/\ssrc=["\']([^"\']+)/i', $attrs, $src)) {
                continue;
            }
            $abs = self::absolute(html_entity_decode($src[1]), $url);
            $host = strtolower((string) parse_url($abs, PHP_URL_HOST));
            if ($host === $this->target['host']) {
                $libs['scripts'][] = $abs;
            } elseif ($host !== '' && !preg_match('/\sintegrity=/i', $attrs) && !preg_match(self::SRI_EXEMPT, $abs)) {
                $noSri[] = $abs;
            }
            $this->libraryFromUrl($abs, $libs['found']);
        }
        if ($noSri) {
            $this->add('web.sri_missing', Severity::LOW, ['count' => count($noSri)], $url, implode("\n", array_slice(array_unique($noSri), 0, 6)), 'CWE-353');
        }

        // Generador declarado (WordPress 6.4.2, Joomla! - Open Source…)
        if (preg_match('/<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)/i', $body, $g)
            || preg_match('/<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']generator/i', $body, $g)) {
            $this->meta['generator'] = html_entity_decode($g[1]);
        }
        return $libs;
    }

    private function libraryFromUrl(string $url, array &$found): void
    {
        $path = (string) parse_url($url, PHP_URL_PATH);
        $names = implode('|', array_map('preg_quote', array_keys(self::JS_BANNERS)));
        // CDN: /npm/jquery@3.4.1/, /ajax/libs/jquery/3.4.1/, jquery-3.4.1.min.js, bootstrap.4.3.1.js
        if (preg_match('#(?:/npm/|/ajax/libs/|/)(' . $names . ')(?:@|/|-|\.)v?(\d+\.\d+\.\d+)(?:/|\.|$)#i', $path, $m)) {
            $found[strtolower($m[1])] = $m[2];
            return;
        }
        // jQuery de WordPress: /wp-includes/js/jquery/jquery.min.js?ver=3.7.1
        if (preg_match('#/wp-includes/js/jquery/(jquery|jquery-migrate)(?:\.min)?\.js$#', $path, $m)
            && preg_match('/(?:^|&)ver=(\d+\.\d+\.\d+)/', (string) parse_url($url, PHP_URL_QUERY), $v)) {
            $found[$m[1]] = $v[1];
        }
    }

    // ------------------------------------------------------------------------------------------------ ficheros expuestos

    /** Respuesta de una página que no existe: para descartar las 404 «blandas» (200 con la portada). */
    private function baseline(): void
    {
        $r = $this->http->get($this->origin . '/stellar-' . bin2hex(random_bytes(6)) . '.txt', [], 65536);
        $this->baseline = ['status' => $r['status'], 'len' => strlen($r['body']), 'body' => $r['body']];
        foreach (self::ERROR_PATTERNS as $re => $kind) {
            if (preg_match($re, $r['body'], $m)) {
                $this->add('web.error_disclosure', $kind === 'debug' ? Severity::HIGH : Severity::MEDIUM, ['kind' => $kind], $this->origin . '/(404)', "GET {$r['url']}\n" . self::context($r['body'], $m[0]), 'CWE-209', $kind);
                break;
            }
        }
    }

    private function looksLikeBaseline(array $r): bool
    {
        if ($this->baseline === null || $this->baseline['status'] !== 200 || $r['status'] !== 200) {
            return false;
        }
        $len = strlen($r['body']);
        return $len > 0 && abs($len - $this->baseline['len']) <= max(64, $this->baseline['len'] * 0.05);
    }

    private function exposedFiles(): void
    {
        $base = rtrim($this->origin, '/');
        foreach (self::EXPOSED as $path => [$check, $severity, $signature, $cwe]) {
            $path = str_replace('{host}', $this->target['host'], $path);
            $r = $this->http->get($base . $path, [], 16384);
            if ($r['status'] !== 200 || $r['body'] === '' || $this->looksLikeBaseline($r) || !preg_match($signature, $r['body'])) {
                continue;
            }
            $binary = preg_match('/[\x00-\x08\x0e-\x1f]/', substr($r['body'], 0, 512)) === 1;
            $evidence = 'HTTP 200 · ' . (HttpClient::header($r, 'content-type') ?? '?') . "\n"
                . ($binary ? '[binario: ' . bin2hex(substr($r['body'], 0, 8)) . '…]' : Redactor::clean(substr($r['body'], 0, 400), 400));
            $this->add($check, $severity, ['path' => $path], $base . $path, $evidence, $cwe, $path);
        }
    }

    private function listings(): void
    {
        foreach (self::LISTING_DIRS as $dir) {
            $r = $this->http->get($this->origin . $dir, [], 32768);
            if ($r['status'] === 200 && preg_match('/<title>Index of \/|<h1>Index of \/|Directory listing for \//i', $r['body'])) {
                preg_match_all('/<a href="([^"?\/][^"]*)"/i', $r['body'], $m);
                $this->add('web.dir_listing', Severity::MEDIUM, ['path' => $dir], $this->origin . $dir,
                    'Index of ' . $dir . "\n" . implode("\n", array_slice($m[1], 0, 8)), 'CWE-548', $dir);
            }
        }
    }

    // ------------------------------------------------------------------------------------------------ comportamiento

    private function cors(): void
    {
        $evil = 'https://stellar-cors-check.example';
        $r = $this->http->get($this->meta['final_url'], ['Origin' => $evil], 4096);
        $acao = HttpClient::header($r, 'access-control-allow-origin');
        $creds = strtolower((string) HttpClient::header($r, 'access-control-allow-credentials')) === 'true';
        if ($acao === $evil) {
            $this->add('web.cors_reflect', $creds ? Severity::HIGH : Severity::MEDIUM, ['credentials' => $creds ? 'true' : 'false'], $this->meta['final_url'],
                "Origin: $evil\nAccess-Control-Allow-Origin: $acao" . ($creds ? "\nAccess-Control-Allow-Credentials: true" : ''), 'CWE-942');
        } elseif ($acao === '*' && $creds) {
            $this->add('web.cors_reflect', Severity::MEDIUM, ['credentials' => 'true'], $this->meta['final_url'], "Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true", 'CWE-942');
        }
    }

    /** Un parámetro con comillas y < en la portada: ¿error visible? ¿se devuelve sin escapar? */
    private function errorsAndReflection(): void
    {
        $mark = 'stl' . bin2hex(random_bytes(3));
        $payload = $mark . '"\'<b>';
        $url = rtrim($this->meta['final_url'], '?&') . (str_contains($this->meta['final_url'], '?') ? '&' : '?')
            . http_build_query(['q' => $payload, 's' => $payload, 'id' => $payload, 'search' => $payload]);
        $r = $this->http->get($url, [], 1048576);
        // Ubicación estable (sin el marcador aleatorio) para que la huella sea la misma en cada análisis
        $where = $this->meta['final_url'] . ' (?q= &s= &id= &search=)';
        if (str_contains($r['body'], $payload)) {
            $this->add('web.reflected_input', Severity::MEDIUM, [], $where, "GET $url\n" . self::context($r['body'], $payload), 'CWE-79');
        }
        foreach (self::ERROR_PATTERNS as $re => $kind) {
            if (preg_match($re, $r['body'], $m) && !preg_match($re, $this->baseline['body'] ?? '')) {
                $this->add('web.error_disclosure', $kind === 'debug' ? Severity::HIGH : Severity::MEDIUM, ['kind' => $kind], $where, "GET $url\n" . self::context($r['body'], $m[0]), 'CWE-209', $kind . ':param');
                break;
            }
        }
    }

    private function trace(): void
    {
        $r = $this->http->request('TRACE', $this->origin . '/', ['X-Stellar' => 'trace'], 4096);
        if ($r['status'] === 200 && str_contains($r['body'], 'X-Stellar')) {
            $this->add('web.trace_enabled', Severity::LOW, [], $this->origin . '/', "TRACE / → 200\n" . substr($r['body'], 0, 200), 'CWE-693');
        }
    }

    // ------------------------------------------------------------------------------------------------ CMS

    private function cms(array $home): void
    {
        $body = $home['body'];
        $gen = (string) ($this->meta['generator'] ?? '');
        $cms = null;
        $version = null;
        if (preg_match('/WordPress\s*([\d.]+)?/i', $gen, $m) || str_contains($body, '/wp-content/') || str_contains($body, '/wp-includes/')) {
            $cms = 'WordPress';
            $version = $m[1] ?? null;
            $this->wordpress($body, $version);
        } elseif (preg_match('/Joomla!?\s*([\d.]+)?/i', $gen, $m) || str_contains($body, '/media/jui/') || str_contains($body, '/media/system/js/')) {
            $cms = 'Joomla';
            $version = $m[1] ?? null;
            $x = $this->http->get($this->origin . '/administrator/manifests/files/joomla.xml', [], 8192);
            if ($x['status'] === 200 && preg_match('/<version>([\d.]+)<\/version>/', $x['body'], $v)) {
                $version = $v[1];
                $this->add('web.cms_version', Severity::LOW, ['cms' => 'Joomla', 'version' => $version], $x['url'], '<version>' . $version . '</version>', 'CWE-200', 'joomla.xml');
            }
        } elseif (preg_match('/Drupal\s*([\d.]+)?/i', $gen . ' ' . (HttpClient::header($home, 'x-generator') ?? ''), $m)) {
            $cms = 'Drupal';
            $version = $m[1] ?? null;
        } elseif (preg_match('/prestashop/i', $gen . $body)) {
            $cms = 'PrestaShop';
        }
        if ($cms !== null) {
            $this->meta['cms'] = $cms . ($version ? " $version" : '');
        }
        if ($cms !== null && $version !== null && $gen !== '' && str_contains($gen, $version)) {
            $this->add('web.cms_version', Severity::LOW, ['cms' => $cms, 'version' => $version], $this->meta['final_url'], '<meta name="generator" content="' . $gen . '">', 'CWE-200', 'generator');
        }
    }

    private function wordpress(string $body, ?string $version): void
    {
        // Plugins y versión (de las URL ?ver=): para que se comprueben a mano o con Claude
        preg_match_all('#/wp-content/plugins/([a-z0-9_\-]+)/[^"\'\s]*?(?:\?ver=([\d.]+))?["\'\s]#i', $body, $m, PREG_SET_ORDER);
        $plugins = [];
        foreach ($m as $p) {
            $plugins[$p[1]] = ($plugins[$p[1]] ?? '') ?: ($p[2] ?? '');
        }
        if ($plugins) {
            ksort($plugins);
            $list = implode(', ', array_map(static fn ($k, $v) => $v !== '' ? "$k $v" : $k, array_keys($plugins), $plugins));
            $this->add('web.wp_plugins', Severity::INFO, ['count' => count($plugins), 'plugins' => $list], $this->meta['final_url'], $list, null);
        }

        $x = $this->http->request('POST', $this->origin . '/xmlrpc.php', ['Content-Type' => 'text/xml'], 8192, [
            CURLOPT_POSTFIELDS => '<?xml version="1.0"?><methodCall><methodName>demo.sayHello</methodName></methodCall>',
        ]);
        if ($x['status'] === 200 && str_contains($x['body'], '<methodResponse>')) {
            $this->add('web.wp_xmlrpc', Severity::MEDIUM, [], $this->origin . '/xmlrpc.php', "POST /xmlrpc.php demo.sayHello → 200\n" . substr($x['body'], 0, 200), 'CWE-307');
        }

        $u = $this->http->get($this->origin . '/wp-json/wp/v2/users?per_page=10', [], 65536);
        $users = json_decode($u['body'], true);
        if ($u['status'] === 200 && is_array($users) && isset($users[0]['slug'])) {
            $slugs = array_slice(array_column($users, 'slug'), 0, 10);
            $this->add('web.wp_user_enum', Severity::MEDIUM, ['users' => implode(', ', $slugs)], $u['url'], 'slug: ' . implode(', ', $slugs), 'CWE-200');
        }

        if ($version === null) {
            $readme = $this->http->get($this->origin . '/readme.html', [], 8192);
            if ($readme['status'] === 200 && preg_match('/Version ([\d.]+)/', $readme['body'], $v)) {
                $this->add('web.cms_version', Severity::LOW, ['cms' => 'WordPress', 'version' => $v[1]], $readme['url'], 'readme.html: Version ' . $v[1], 'CWE-200', 'readme');
                $this->meta['cms'] = 'WordPress ' . $v[1];
            }
        }
    }

    // ------------------------------------------------------------------------------------------------ robots, security.txt

    private function wellKnown(): void
    {
        $sec = $this->http->get($this->origin . '/.well-known/security.txt', [], 8192);
        if (!($sec['status'] === 200 && preg_match('/^Contact:/mi', $sec['body']))) {
            $this->add('web.security_txt', Severity::INFO, [], $this->origin . '/.well-known/security.txt', 'HTTP ' . $sec['status'], null);
        }
        $robots = $this->http->get($this->origin . '/robots.txt', [], 32768);
        if ($robots['status'] === 200 && preg_match_all('/^\s*Disallow:\s*(\S*(?:admin|backup|bak|old|test|dev|staging|private|secret|config|sql|dump|tmp|intranet)\S*)/mi', $robots['body'], $m)) {
            $paths = array_slice(array_unique($m[1]), 0, 12);
            $this->add('web.robots_paths', Severity::INFO, ['paths' => implode(', ', $paths)], $robots['url'], implode("\n", array_map(static fn ($p) => "Disallow: $p", $paths)), 'CWE-200');
        }
    }

    // ------------------------------------------------------------------------------------------------ librerías JS

    private function jsLibraries(array $libs): void
    {
        $found = $libs['found'];
        // Cabeceras de licencia de los scripts propios (los 6 primeros)
        foreach (array_slice(array_unique($libs['scripts']), 0, 6) as $src) {
            $r = $this->http->get($src, [], 6144);
            if ($r['status'] !== 200) {
                continue;
            }
            foreach (self::JS_BANNERS as $pkg => $re) {
                if (!isset($found[$pkg]) && preg_match($re, $r['body'], $m)) {
                    $found[$pkg] = $m[1];
                }
            }
        }
        $this->meta['js_libraries'] = $found;
        if (!$found) {
            return;
        }
        if ($this->osv === null) {
            $this->notes[] = ['notes.osv_off', []];
            return;
        }
        $packages = array_map(static fn ($n, $v) => ['ecosystem' => 'npm', 'name' => $n, 'version' => $v], array_keys($found), $found);
        $byPkg = [];
        foreach ($this->osv->check($packages) as $v) {
            $byPkg[$v['package']['name']][] = $v;
        }
        if ($this->osv->error !== null) {
            $this->notes[] = ['notes.osv_failed', ['error' => $this->osv->error]];
        }
        foreach ($byPkg as $name => $vulns) {
            usort($vulns, static fn ($a, $b) => Severity::rank($a['severity']) <=> Severity::rank($b['severity']));
            $fixed = array_filter(array_column($vulns, 'fixed'));
            usort($fixed, 'version_compare');
            $this->add('web.js_vulnerable', $vulns[0]['severity'], [
                'package' => $name, 'version' => $found[$name], 'count' => count($vulns),
                'fixed' => $fixed ? (string) end($fixed) : '?',
            ], $this->meta['final_url'], implode("\n", array_map(static fn ($v) => ($v['aliases'][0] ?? $v['id']) . ' · ' . $v['summary'], array_slice($vulns, 0, 8))), 'CWE-1104', $name);
        }
    }

    // ------------------------------------------------------------------------------------------------ utilidades

    private function add(string $check, string $severity, array $vars, string $location, string $evidence, ?string $cwe, string $key = ''): void
    {
        $this->findings[] = new Finding($check, $severity, array_map('strval', $vars), $location, Redactor::clean($evidence), $cwe, $key);
    }

    private function client(string $host, array $ips, int $used = 0): HttpClient
    {
        return new HttpClient(
            $host,
            $ips,
            (string) ($this->options['user_agent'] ?? 'Mozilla/5.0 (compatible; Stellar security scanner)'),
            max(10, (int) ($this->options['max_requests'] ?? 150) - $used),
            (int) ($this->options['delay_ms'] ?? 150),
            (int) ($this->options['timeout'] ?? 15),
        );
    }

    private function hasPassword(string $html): bool
    {
        return (bool) preg_match('/<input[^>]+type=["\']?password/i', $html);
    }

    public static function absolute(string $ref, string $base): string
    {
        if (preg_match('#^https?://#i', $ref)) {
            return $ref;
        }
        $b = parse_url($base);
        $origin = $b['scheme'] . '://' . $b['host'] . (isset($b['port']) ? ':' . $b['port'] : '');
        if (str_starts_with($ref, '//')) {
            return $b['scheme'] . ':' . $ref;
        }
        if (str_starts_with($ref, '/')) {
            return $origin . $ref;
        }
        $dir = preg_replace('#/[^/]*$#', '/', (string) ($b['path'] ?? '/'));
        return $origin . $dir . $ref;
    }

    /** Un trozo del texto alrededor de lo encontrado. */
    private static function context(string $body, string $needle, int $around = 160): string
    {
        $pos = strpos($body, $needle);
        if ($pos === false) {
            return substr($body, 0, $around * 2);
        }
        $start = max(0, $pos - $around);
        return ($start > 0 ? '…' : '') . substr($body, $start, strlen($needle) + $around * 2) . '…';
    }

    private static function title(string $header): string
    {
        return implode('-', array_map('ucfirst', explode('-', $header)));
    }

    private static function short(string $s): string
    {
        return mb_substr(preg_replace('/^.*?: /', '', $s) ?? $s, 0, 160);
    }
}

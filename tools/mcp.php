#!/usr/bin/env php
<?php
/**
 * Stellar · servidor MCP para Claude Code (local, stdio, sin dependencias): Claude lee los informes de seguridad de
 * Stellar, los resuelve en el código que tenga abierto y, con tu confirmación, lanza un análisis nuevo o marca
 * hallazgos (resuelto, falso positivo, riesgo aceptado). Usa la API de Stellar con TU token personal (Perfil → API):
 * ve y hace lo mismo que tú, nada más.
 *
 * Alta en Claude Code (una vez; disponible en todos los proyectos):
 *
 *   claude mcp add stellar --scope user \
 *     -e STELLAR_URL=https://stellar.example.com -e STELLAR_TOKEN=qs_… \
 *     -- php /home/…/stellar/tools/mcp.php
 *
 * Sin STELLAR_TOKEN, el token se lee de ~/.config/stellar-mcp/token (o de STELLAR_TOKEN_FILE), con permisos 600.
 * Opcional: STELLAR_LANG (ca, es, en; idioma de los informes, por defecto ca).
 * Protocolo: JSON-RPC 2.0, un mensaje por línea en stdin/stdout (los avisos van a stderr).
 */
declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    exit(1);
}

const MCP_VERSION = '2025-06-18';
const STATUSES = ['oberta' => 'open', 'resolta' => 'fixed', 'acceptada' => 'accepted', 'fals_positiu' => 'false_positive'];

$base = rtrim((string) getenv('STELLAR_URL'), '/');
$home = (string) (getenv('HOME') ?: getenv('USERPROFILE') ?: '');
$token = (string) getenv('STELLAR_TOKEN');
if ($token === '') {
    $tokenFile = (string) (getenv('STELLAR_TOKEN_FILE') ?: ($home . '/.config/stellar-mcp/token'));
    $token = is_readable($tokenFile) ? trim((string) file_get_contents($tokenFile)) : '';
}
$lang = in_array(getenv('STELLAR_LANG'), ['ca', 'es', 'en'], true) ? (string) getenv('STELLAR_LANG') : 'ca';

// ------------------------------------------------------------------------------------------------- API de Stellar

final class StellarApi
{
    public function __construct(private readonly string $base, private readonly string $token, private readonly string $lang)
    {
    }

    /** @return array<string,mixed> */
    public function call(string $method, string $path, array $query = [], ?array $body = null, int $timeout = 60): array
    {
        $url = $this->base . '/index.php?r=api&p=' . rawurlencode('v1/' . ltrim($path, '/')) . '&' . http_build_query($query + ['lang' => $this->lang]);
        $headers = ['Accept: application/json', 'Authorization: Bearer ' . $this->token, 'X-Api-Key: ' . $this->token];
        if ($body !== null) {
            $headers[] = 'Content-Type: application/json';
        }
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => $timeout,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_USERAGENT => 'Stellar-MCP/1.0',
        ] + (PHP_OS_FAMILY === 'Windows' && defined('CURLSSLOPT_NATIVE_CA') ? [CURLOPT_SSL_OPTIONS => CURLSSLOPT_NATIVE_CA] : [])
          + ($body !== null ? [CURLOPT_POSTFIELDS => json_encode($body, JSON_UNESCAPED_UNICODE)] : []));
        $raw = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        if ($raw === false) {
            throw new RuntimeException('No es pot connectar amb Stellar: ' . curl_error($ch));
        }
        $data = json_decode((string) $raw, true);
        if (!is_array($data)) {
            throw new RuntimeException("Stellar ha respost $status sense JSON (revisa STELLAR_URL)");
        }
        if ($status >= 400) {
            throw new RuntimeException('Stellar: ' . ($data['error'] ?? "error $status"));
        }
        return $data;
    }
}

// ------------------------------------------------------------------------------------------------- herramientas

final class Tools
{
    public function __construct(private readonly StellarApi $api)
    {
    }

    public static function definitions(): array
    {
        $target = ['type' => 'integer', 'description' => "Número de l'objectiu (de stellar_objectius)"];
        return [
            [
                'name' => 'stellar_objectius',
                'description' => "Llista els objectius de Stellar (webs i aplicacions) amb la darrera puntuació de seguretat i les troballes crítiques, altes i mitjanes.",
                'inputSchema' => ['type' => 'object', 'properties' => new stdClass()],
                'annotations' => ['readOnlyHint' => true],
            ],
            [
                'name' => 'stellar_informe',
                'description' => "L'informe de seguretat d'una anàlisi en Markdown: context, cada troballa amb on és, la prova i com resoldre-la. "
                    . "Indica 'objectiu' (darrera anàlisi) o 'analisi'. Abans de canviar codi, comprova cada troballa: pot haver-hi falsos positius.",
                'inputSchema' => ['type' => 'object', 'properties' => [
                    'objectiu' => $target,
                    'analisi' => ['type' => 'integer', 'description' => "Número de l'anàlisi"],
                ]],
                'annotations' => ['readOnlyHint' => true],
            ],
            [
                'name' => 'stellar_analitza',
                'description' => "Torna a analitzar un objectiu ara (una web pot trigar un minut) i en retorna l'informe nou. "
                    . "Fa peticions a la web real: demana confirmació a l'usuari abans.",
                'inputSchema' => ['type' => 'object', 'properties' => ['objectiu' => $target], 'required' => ['objectiu']],
                'annotations' => ['readOnlyHint' => false, 'openWorldHint' => true],
            ],
            [
                'name' => 'stellar_marca',
                'description' => "Canvia l'estat d'una troballa (el número S… de l'informe): oberta, resolta, acceptada (risc acceptat) o fals_positiu, "
                    . "amb una nota del motiu. Les acceptades i els falsos positius ja no surten als informes següents. Demana confirmació a l'usuari abans.",
                'inputSchema' => ['type' => 'object', 'properties' => [
                    'troballa' => ['type' => 'integer', 'description' => 'Número de la troballa (S123 → 123)'],
                    'estat' => ['type' => 'string', 'enum' => array_keys(STATUSES)],
                    'nota' => ['type' => 'string', 'description' => 'Per què (surt a l\'informe)'],
                ], 'required' => ['troballa', 'estat']],
            ],
        ];
    }

    public function call(string $name, array $args): array
    {
        return match ($name) {
            'stellar_objectius' => $this->targets(),
            'stellar_informe' => $this->report((int) ($args['objectiu'] ?? 0), (int) ($args['analisi'] ?? 0)),
            'stellar_analitza' => $this->scan((int) ($args['objectiu'] ?? 0)),
            'stellar_marca' => $this->mark((int) ($args['troballa'] ?? 0), (string) ($args['estat'] ?? ''), (string) ($args['nota'] ?? '')),
            default => throw new InvalidArgumentException("Eina desconeguda: $name"),
        };
    }

    private function targets(): array
    {
        $d = $this->api->call('GET', 'pages/scan_report');
        $data = $d['data'] ?? $d;
        $out = ['| # | Objectiu | Tipus | Puntuació | Crítiques | Altes | Mitjanes | Darrera anàlisi |', '|---|---|---|---|---|---|---|---|'];
        foreach ($data['targets'] ?? [] as $t) {
            $out[] = sprintf('| %d | %s%s | %s | %s | %s | %s | %s | %s |', $t['id'], $t['name'], (int) $t['authorized'] ? '' : ' (sense autorització)', $t['kind'],
                $t['last_score'] ?? '—', $t['critical'] ?? '—', $t['high'] ?? '—', $t['medium'] ?? '—', $t['last_scan_at'] ?? 'mai');
        }
        return self::text(count($out) > 2 ? implode("\n", $out) : 'Encara no hi ha cap objectiu a Stellar.');
    }

    private function report(int $target, int $scan): array
    {
        if ($target <= 0 && $scan <= 0) {
            throw new InvalidArgumentException("Indica 'objectiu' o 'analisi'");
        }
        $d = $this->api->call('GET', 'pages/scan_report', $scan > 0 ? ['id' => $scan] : ['target' => $target]);
        $data = $d['data'] ?? $d;
        if (($data['scan']['status'] ?? '') !== 'done') {
            return self::text("L'anàlisi #" . ($data['scan']['id'] ?? '?') . ' no està acabada: ' . ($data['scan']['error'] ?? $data['scan']['status'] ?? ''));
        }
        return self::text((string) $data['markdown']);
    }

    private function scan(int $target): array
    {
        if ($target <= 0) {
            throw new InvalidArgumentException("Falta l'objectiu");
        }
        $this->api->call('POST', "targets/$target/actions/scan", [], [], 900);
        return $this->report($target, 0);
    }

    private function mark(int $finding, string $status, string $note): array
    {
        if ($finding <= 0 || !isset(STATUSES[$status])) {
            throw new InvalidArgumentException('Falta la troballa o l\'estat no és vàlid');
        }
        $body = ['status' => STATUSES[$status]] + ($note !== '' ? ['comment' => $note] : []);
        $r = $this->api->call('PATCH', "findings/$finding", [], $body);
        return self::text("Troballa S$finding: " . ($r['_display']['status'] ?? $r['status'] ?? $status) . '.');
    }

    private static function text(string $text): array
    {
        return ['content' => [['type' => 'text', 'text' => $text]]];
    }
}

// ------------------------------------------------------------------------------------------------- bucle JSON-RPC

function send(array $message): void
{
    fwrite(STDOUT, json_encode($message, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . "\n");
    fflush(STDOUT);
}

$tools = ($base !== '' && $token !== '') ? new Tools(new StellarApi($base, $token, $lang)) : null;
if ($tools === null) {
    fwrite(STDERR, "stellar-mcp: falten STELLAR_URL i el token (STELLAR_TOKEN o ~/.config/stellar-mcp/token)\n");
}

while (($line = fgets(STDIN)) !== false) {
    $line = trim($line);
    if ($line === '') {
        continue;
    }
    $msg = json_decode($line, true);
    if (!is_array($msg) || !isset($msg['method'])) {
        if (is_array($msg) && array_key_exists('id', $msg)) {
            continue;
        }
        send(['jsonrpc' => '2.0', 'id' => null, 'error' => ['code' => -32700, 'message' => 'Parse error']]);
        continue;
    }
    $id = $msg['id'] ?? null;
    $method = (string) $msg['method'];
    if ($id === null) {
        continue;
    }
    try {
        $result = match ($method) {
            'initialize' => [
                'protocolVersion' => (string) ($msg['params']['protocolVersion'] ?? MCP_VERSION),
                'capabilities' => ['tools' => new stdClass()],
                'serverInfo' => ['name' => 'stellar', 'version' => '1.0.0'],
                'instructions' => "Stellar analitza la seguretat de les webs i aplicacions de l'empresa. Llegeix l'informe amb stellar_informe, "
                    . "comprova cada troballa al codi abans de canviar res (pot haver-hi falsos positius) i no tornis a analitzar ni marquis "
                    . "troballes sense que l'usuari ho hagi confirmat.",
            ],
            'ping' => new stdClass(),
            'tools/list' => ['tools' => Tools::definitions()],
            'tools/call' => (function () use ($tools, $msg) {
                if ($tools === null) {
                    return ['content' => [['type' => 'text', 'text' => 'Falta el token: desa\'l a ~/.config/stellar-mcp/token (Stellar → Perfil → API) o posa STELLAR_TOKEN.']], 'isError' => true];
                }
                try {
                    return $tools->call((string) ($msg['params']['name'] ?? ''), (array) ($msg['params']['arguments'] ?? []));
                } catch (Throwable $e) {
                    return ['content' => [['type' => 'text', 'text' => $e->getMessage()]], 'isError' => true];
                }
            })(),
            default => throw new BadMethodCallException($method),
        };
        send(['jsonrpc' => '2.0', 'id' => $id, 'result' => $result]);
    } catch (BadMethodCallException $e) {
        send(['jsonrpc' => '2.0', 'id' => $id, 'error' => ['code' => -32601, 'message' => 'Method not found: ' . $e->getMessage()]]);
    } catch (Throwable $e) {
        send(['jsonrpc' => '2.0', 'id' => $id, 'error' => ['code' => -32603, 'message' => $e->getMessage()]]);
    }
}

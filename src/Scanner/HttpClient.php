<?php
declare(strict_types=1);

namespace Quasar\Scanner;

/**
 * Stellar · cliente HTTP del análisis web (curl). Prudente por diseño:
 * - solo habla con el host analizado, con la IP resuelta al principio (CURLOPT_RESOLVE): un cambio de DNS a mitad
 *   del análisis no lo lleva a otra máquina;
 * - límite de peticiones por análisis, pausa entre peticiones y tamaño máximo de respuesta;
 * - nunca sigue redirecciones por su cuenta (las sigue WebScanner, comprobando el destino).
 */
final class HttpClient
{
    private int $count = 0;
    private float $last = 0.0;

    /**
     * @param string $host       host analizado
     * @param list<string> $ips  IP permitidas (TargetGuard::resolve)
     */
    public function __construct(
        private readonly string $host,
        private readonly array $ips,
        private readonly string $userAgent,
        private readonly int $maxRequests = 150,
        private readonly int $delayMs = 150,
        private readonly int $timeout = 15,
    ) {
    }

    public function count(): int
    {
        return $this->count;
    }

    public function remaining(): int
    {
        return max(0, $this->maxRequests - $this->count);
    }

    /**
     * @param array<string,string> $headers
     * @return array{status:int,headers:array<string,list<string>>,body:string,url:string,error:?string,time:float,ip:?string,truncated:bool}
     */
    public function request(string $method, string $url, array $headers = [], int $maxBytes = 524288, array $curlExtra = []): array
    {
        $parts = parse_url($url);
        $host = strtolower((string) ($parts['host'] ?? ''));
        if ($host !== $this->host) {
            throw new \RuntimeException("Stellar no sale del host analizado ($host)");
        }
        if ($this->count >= $this->maxRequests) {
            throw new RequestLimitException('Límite de peticiones del análisis alcanzado');
        }
        $wait = $this->last + $this->delayMs / 1000 - microtime(true);
        if ($wait > 0) {
            usleep((int) ($wait * 1_000_000));
        }
        $this->count++;

        $scheme = strtolower((string) ($parts['scheme'] ?? 'https'));
        $port = (int) ($parts['port'] ?? ($scheme === 'http' ? 80 : 443));
        $respHeaders = [];
        $body = '';
        $truncated = false;
        $ch = curl_init($url);
        $h = ['User-Agent: ' . $this->userAgent, 'Accept: */*'];
        foreach ($headers as $k => $v) {
            $h[] = "$k: $v";
        }
        curl_setopt_array($ch, [
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_NOBODY => $method === 'HEAD',
            CURLOPT_HTTPHEADER => $h,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_TIMEOUT => $this->timeout,
            CURLOPT_CONNECTTIMEOUT => 8,
            CURLOPT_ENCODING => '',
            CURLOPT_RESOLVE => ["$host:$port:" . implode(',', array_map(static fn (string $ip) => str_contains($ip, ':') ? "[$ip]" : $ip, $this->ips))],
            CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
            CURLOPT_HEADERFUNCTION => static function ($ch, string $line) use (&$respHeaders): int {
                if (str_starts_with($line, 'HTTP/')) {
                    $respHeaders = [];   // 100 Continue y similares
                } elseif (($p = strpos($line, ':')) !== false) {
                    $respHeaders[strtolower(trim(substr($line, 0, $p)))][] = trim(substr($line, $p + 1));
                }
                return strlen($line);
            },
            CURLOPT_WRITEFUNCTION => static function ($ch, string $chunk) use (&$body, &$truncated, $maxBytes): int {
                if (strlen($body) >= $maxBytes) {
                    $truncated = true;
                    return 0;   // corta la descarga
                }
                $body .= $chunk;
                return strlen($chunk);
            },
        ] + $curlExtra);
        $ok = curl_exec($ch);
        $this->last = microtime(true);
        $error = $ok === false && !$truncated ? curl_error($ch) : null;
        return [
            'status' => (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE),
            'headers' => $respHeaders,
            'body' => strlen($body) > $maxBytes ? substr($body, 0, $maxBytes) : $body,
            'url' => $url,
            'error' => $error,
            'time' => (float) curl_getinfo($ch, CURLINFO_TOTAL_TIME),
            'ip' => curl_getinfo($ch, CURLINFO_PRIMARY_IP) ?: null,
            'truncated' => $truncated,
        ];
    }

    public function get(string $url, array $headers = [], int $maxBytes = 524288): array
    {
        return $this->request('GET', $url, $headers, $maxBytes);
    }

    /** Primera cabecera con ese nombre (en minúsculas). */
    public static function header(array $resp, string $name): ?string
    {
        return $resp['headers'][strtolower($name)][0] ?? null;
    }
}

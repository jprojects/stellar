<?php
declare(strict_types=1);

namespace Quasar\Scanner;

/**
 * Stellar · qué se puede analizar. Stellar hace peticiones desde el servidor donde está instalado y lee carpetas de
 * ese servidor: sin estos límites serviría para llegar a la red interna (SSRF) o para leer ficheros de otros.
 *
 * - Webs: solo http/https; el host no puede resolver a una IP privada, local o reservada salvo
 *   'stellar' => ['allow_private' => true] (para analizar la intranet a propósito).
 * - Código: la carpeta tiene que estar dentro de 'stellar' => ['code_roots' => [...]].
 */
final class TargetGuard
{
    public function __construct(private readonly array $config)
    {
    }

    /** @return array{url:string,scheme:string,host:string,port:?int,path:string,ips:list<string>} */
    public function web(string $url): array
    {
        $url = trim($url);
        if (!preg_match('#^https?://#i', $url)) {
            $url = 'https://' . $url;
        }
        $p = parse_url($url);
        $host = strtolower(rtrim((string) ($p['host'] ?? ''), '.'));
        if ($p === false || $host === '' || isset($p['user']) || isset($p['pass'])) {
            throw new ScanException('errors.bad_url', ['url' => $url]);
        }
        $ips = $this->resolve($host);
        if (!$ips) {
            throw new ScanException('errors.dns', ['host' => $host]);
        }
        if (empty($this->config['allow_private'])) {
            foreach ($ips as $ip) {
                if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                    throw new ScanException('errors.private_ip', ['host' => $host, 'ip' => $ip]);
                }
            }
        }
        return [
            'url' => $url,
            'scheme' => strtolower((string) $p['scheme']),
            'host' => $host,
            'port' => isset($p['port']) ? (int) $p['port'] : null,
            'path' => (string) ($p['path'] ?? '/') ?: '/',
            'ips' => $ips,
        ];
    }

    /** Carpeta de código: ruta real, dentro de una de las raíces permitidas. */
    public function codePath(string $path): string
    {
        $real = realpath(trim($path));
        if ($real === false || !is_dir($real)) {
            throw new ScanException('errors.no_dir', ['path' => $path]);
        }
        foreach ((array) ($this->config['code_roots'] ?? []) as $root) {
            $root = realpath((string) $root);
            if ($root !== false && ($real === $root || str_starts_with($real, rtrim($root, '/') . '/'))) {
                return $real;
            }
        }
        throw new ScanException('errors.dir_not_allowed', ['path' => $real]);
    }

    /** @return list<string> */
    private function resolve(string $host): array
    {
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            return [$host];
        }
        $ips = [];
        foreach (@dns_get_record($host, DNS_A | DNS_AAAA) ?: [] as $r) {
            $ips[] = $r['ip'] ?? $r['ipv6'] ?? null;
        }
        if (!$ips) {
            $ips = @gethostbynamel($host) ?: [];
        }
        return array_values(array_unique(array_filter($ips)));
    }
}

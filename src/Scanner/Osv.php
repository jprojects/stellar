<?php
declare(strict_types=1);

namespace Quasar\Scanner;

/**
 * Stellar · vulnerabilidades conocidas de dependencias con OSV.dev (https://osv.dev, gratuita y sin clave; agrupa los
 * avisos de GitHub, npm, Packagist, PyPI…). Solo se envían nombres de paquete y versiones, nunca código.
 * Se desactiva con 'stellar' => ['osv' => false].
 */
final class Osv
{
    private const BATCH = 'https://api.osv.dev/v1/querybatch';
    private const VULN = 'https://api.osv.dev/v1/vulns/';
    private const MAX_DETAILS = 80;

    private int $details = 0;
    /** @var array<string,?array> */
    private array $cache = [];
    public ?string $error = null;

    public function __construct(private readonly int $timeout = 20)
    {
    }

    /**
     * @param list<array{ecosystem:string,name:string,version:string}> $packages ecosystem: npm | Packagist | PyPI
     * @return list<array{package:array,id:string,aliases:list<string>,summary:string,severity:string,fixed:?string}>
     */
    public function check(array $packages): array
    {
        $packages = array_values(array_filter($packages, static fn ($p) => $p['name'] !== '' && preg_match('/^\d/', $p['version'])));
        $out = [];
        foreach (array_chunk($packages, 500) as $chunk) {
            $resp = $this->post(self::BATCH, ['queries' => array_map(static fn ($p) => [
                'package' => ['ecosystem' => $p['ecosystem'], 'name' => $p['name']],
                'version' => $p['version'],
            ], $chunk)]);
            if ($resp === null) {
                return $out;
            }
            foreach ($resp['results'] ?? [] as $i => $r) {
                foreach ($r['vulns'] ?? [] as $v) {
                    $d = $this->detail((string) $v['id']);
                    if ($d === null) {
                        continue;
                    }
                    $out[] = [
                        'package' => $chunk[$i],
                        'id' => (string) $v['id'],
                        'aliases' => array_values(array_filter((array) ($d['aliases'] ?? []), static fn ($a) => str_starts_with((string) $a, 'CVE-'))),
                        'summary' => trim((string) ($d['summary'] ?? '')),
                        'severity' => self::severity($d),
                        'fixed' => self::fixed($d, $chunk[$i]['name']),
                    ];
                }
            }
        }
        return $out;
    }

    private function detail(string $id): ?array
    {
        if (array_key_exists($id, $this->cache)) {
            return $this->cache[$id];
        }
        if (++$this->details > self::MAX_DETAILS) {
            return $this->cache[$id] = ['id' => $id];   // sin detalle: cuenta igual, con gravedad media
        }
        return $this->cache[$id] = $this->request(self::VULN . rawurlencode($id), null);
    }

    private static function severity(array $d): string
    {
        $label = $d['database_specific']['severity'] ?? null;
        if (is_string($label)) {
            return Severity::fromAdvisory($label);
        }
        foreach ($d['affected'] ?? [] as $a) {
            if (is_string($a['ecosystem_specific']['severity'] ?? null)) {
                return Severity::fromAdvisory($a['ecosystem_specific']['severity']);
            }
        }
        return Severity::MEDIUM;
    }

    /** Primera versión que lo corrige, si OSV la da. */
    private static function fixed(array $d, string $name): ?string
    {
        foreach ($d['affected'] ?? [] as $a) {
            if (strcasecmp((string) ($a['package']['name'] ?? ''), $name) !== 0) {
                continue;
            }
            foreach ($a['ranges'] ?? [] as $r) {
                foreach ($r['events'] ?? [] as $e) {
                    if (isset($e['fixed'])) {
                        return (string) $e['fixed'];
                    }
                }
            }
        }
        return null;
    }

    private function post(string $url, array $body): ?array
    {
        return $this->request($url, $body);
    }

    private function request(string $url, ?array $body): ?array
    {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => $this->timeout,
            CURLOPT_CONNECTTIMEOUT => 8,
            CURLOPT_USERAGENT => 'Stellar',
            CURLOPT_HTTPHEADER => ['Content-Type: application/json', 'Accept: application/json'],
        ] + ($body !== null ? [CURLOPT_POST => true, CURLOPT_POSTFIELDS => json_encode($body)] : []));
        $raw = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        if ($raw === false || $status >= 400) {
            $this->error = $raw === false ? curl_error($ch) : "HTTP $status";
            return null;
        }
        $data = json_decode((string) $raw, true);
        return is_array($data) ? $data : null;
    }
}

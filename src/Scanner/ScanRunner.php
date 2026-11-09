<?php
declare(strict_types=1);

namespace Quasar\Scanner;

use Quasar\Core\Database;
use Quasar\Core\Log;

/**
 * Stellar · lanza el análisis de un objetivo y guarda el resultado: la fila de `scans`, los hallazgos en `findings`
 * (con sus textos en el idioma de quien lo lanza) y el resumen en `targets`. Lo usan el botón «Analitza» (hooks del
 * módulo targets), tools/scan.php (cron) y el MCP (por la API).
 *
 * Compara con el análisis anterior del mismo objetivo: marca los hallazgos nuevos, cuenta los que ya no aparecen y
 * conserva lo que alguien decidió («acceptat», «fals positiu»), para no tener que volver a revisarlos cada vez.
 *
 * Configuración (config.local.php), todo opcional:
 *   'stellar' => [
 *       'code_roots' => ['/home/…/Projects'],   // carpetas del servidor que se pueden analizar como código
 *       'allow_private' => false,               // true: permite analizar webs de la red interna
 *       'max_requests' => 150, 'delay_ms' => 150, 'timeout' => 15,
 *       'user_agent' => 'Mozilla/5.0 (compatible; Stellar security scanner)',
 *       'osv' => true,                          // vulnerabilidades de dependencias con OSV.dev
 *       'tls_legacy' => true,                   // probar TLS 1.0/1.1
 *   ]
 */
final class ScanRunner
{
    /** @param \Closure(string,array=):string $t textos de lang/{idioma}/scanner.json */
    public function __construct(
        private readonly Database $db,
        private readonly array $config,
        private readonly \Closure $t,
        private readonly string $locale,
    ) {
    }

    /** @return int id del análisis (también si ha fallado: la fila lleva el error) */
    public function run(int $targetId, ?int $userId = null): int
    {
        $target = $this->db->fetch('SELECT * FROM targets WHERE id = ?', [$targetId]);
        if ($target === null) {
            throw new \RuntimeException("Stellar: el objetivo $targetId no existe");
        }
        $scanId = (int) $this->db->insert('scans', [
            'target_id' => $targetId,
            'kind' => $target['kind'],
            'status' => 'running',
            'locale' => $this->locale,
            'user_id' => $userId,
            'started_at' => date('Y-m-d H:i:s'),
        ]);
        @set_time_limit(900);
        $start = time();
        $opts = (array) ($this->config['stellar'] ?? []);
        $osv = ($opts['osv'] ?? true) !== false ? new Osv() : null;

        try {
            if (!(int) $target['authorized']) {
                throw new ScanException('errors.not_authorized');
            }
            if ($target['kind'] === 'web') {
                $guard = new TargetGuard($opts);
                $result = (new WebScanner($guard->web((string) $target['url']), $opts + ['guard' => $opts], $osv))->run();
            } else {
                $result = $this->runCode($target, $opts, $osv);
            }
            $this->store($scanId, $target, $result, time() - $start);
            Log::info('Stellar: análisis {scan} de «{target}» acabado', ['scan' => $scanId, 'target' => $target['name']]);
        } catch (ScanException $e) {
            $this->fail($scanId, ($this->t)('errors.' . preg_replace('/^errors\./', '', $e->getMessage()), $e->vars), $start);
        } catch (\Throwable $e) {
            Log::error('Stellar: el análisis {scan} ha fallado: {message}', ['scan' => $scanId, 'message' => $e->getMessage(), 'exception' => $e]);
            $this->fail($scanId, ($this->t)('errors.internal', ['error' => $e->getMessage()]), $start);
        }
        return $scanId;
    }

    private function runCode(array $target, array $opts, ?Osv $osv): array
    {
        $scanner = new CodeScanner($opts, $osv);
        if (trim((string) $target['code_path']) !== '') {
            $dir = (new TargetGuard($opts))->codePath((string) $target['code_path']);
            return $scanner->run($dir);
        }
        $media = $target['code_zip'] ? $this->db->fetch('SELECT * FROM media WHERE id = ?', [(int) $target['code_zip']]) : null;
        if ($media === null) {
            throw new ScanException('errors.no_source');
        }
        $uploads = rtrim((string) ($this->config['uploads_dir'] ?? QS_ROOT . '/storage/uploads'), '/');
        $file = realpath($uploads . '/' . $media['path']);
        if ($file === false || !str_starts_with($file, (string) realpath($uploads))) {
            throw new ScanException('errors.no_source');
        }
        $ws = new Workspace(QS_ROOT . '/storage/scans');
        try {
            $result = $scanner->run($ws->extract($file));
            $result['meta']['zip'] = (string) $media['original_name'];
            return $result;
        } finally {
            $ws->cleanup();
        }
    }

    /** @param array{findings:list<Finding>,notes:list<array>,meta:array,requests?:int} $result */
    private function store(int $scanId, array $target, array $result, int $duration): void
    {
        $targetId = (int) $target['id'];
        // Lo que se decidió en análisis anteriores (por huella) y lo que había abierto en el último
        $decided = [];
        foreach ($this->db->fetchAll(
            "SELECT fingerprint, status, comment FROM findings WHERE target_id = ? AND status IN ('accepted', 'false_positive') ORDER BY id",
            [$targetId]
        ) as $r) {
            $decided[$r['fingerprint']] = $r;
        }
        $prevScan = $this->db->fetchValue("SELECT MAX(id) FROM scans WHERE target_id = ? AND status = 'done' AND id < ?", [$targetId, $scanId]);
        $prev = $prevScan ? array_flip(array_column($this->db->fetchAll(
            "SELECT fingerprint FROM findings WHERE scan_id = ? AND status <> 'fixed'",
            [(int) $prevScan]
        ), 'fingerprint')) : [];

        $findings = $result['findings'];
        usort($findings, static fn (Finding $a, Finding $b) => [Severity::rank($a->severity), $a->check, $a->location] <=> [Severity::rank($b->severity), $b->check, $b->location]);
        $counts = array_fill_keys(Severity::ALL, 0);
        $scored = [];
        $seen = [];
        $new = 0;
        $this->db->transaction(function () use ($findings, $scanId, $targetId, $decided, $prev, $prevScan, &$counts, &$scored, &$seen, &$new): void {
            foreach ($findings as $f) {
                $fp = $f->fingerprint();
                if (isset($seen[$fp])) {
                    continue;
                }
                $seen[$fp] = true;
                $status = $decided[$fp]['status'] ?? 'open';
                $isNew = $prevScan && !isset($prev[$fp]);
                $new += $isNew ? 1 : 0;
                if ($status === 'open') {
                    $counts[$f->severity]++;
                    $scored[] = ['check' => $f->check, 'severity' => $f->severity];
                }
                $this->db->insert('findings', [
                    'scan_id' => $scanId,
                    'target_id' => $targetId,
                    'check_id' => $f->check,
                    'category' => $f->category(),
                    'severity' => $f->severity,
                    'title' => mb_substr(($this->t)("checks.{$f->check}.title", $f->vars), 0, 255),
                    'detail' => ($this->t)("checks.{$f->check}.detail", $f->vars),
                    'fix' => ($this->t)("checks.{$f->check}.fix", $f->vars),
                    'location' => mb_substr($f->location, 0, 700),
                    'evidence' => $f->evidence,
                    'cwe' => $f->cwe,
                    'fingerprint' => $fp,
                    'status' => $status,
                    'is_new' => $isNew ? 1 : 0,
                    'comment' => $decided[$fp]['comment'] ?? null,
                ]);
            }
        });
        $fixed = count(array_diff_key($prev, $seen));
        $score = Severity::score($scored);
        $notes = array_map(fn (array $n) => ($this->t)($n[0], $n[1]), $result['notes']);
        $this->db->update('scans', [
            'status' => 'done',
            'score' => $score,
            'critical' => $counts['critical'], 'high' => $counts['high'], 'medium' => $counts['medium'],
            'low' => $counts['low'], 'info' => $counts['info'],
            'new_count' => $new,
            'fixed_count' => $fixed,
            'requests' => (int) ($result['requests'] ?? 0),
            'duration' => $duration,
            'notes' => json_encode($notes, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
            'meta' => json_encode($result['meta'], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE),
            'finished_at' => date('Y-m-d H:i:s'),
        ], 'id', $scanId);
        $this->db->update('targets', ['last_scan_id' => $scanId, 'last_score' => $score, 'last_scan_at' => date('Y-m-d H:i:s')], 'id', $targetId);
    }

    private function fail(int $scanId, string $error, int $start): void
    {
        $this->db->update('scans', [
            'status' => 'failed',
            'error' => mb_substr($error, 0, 500),
            'duration' => time() - $start,
            'finished_at' => date('Y-m-d H:i:s'),
        ], 'id', $scanId);
    }
}

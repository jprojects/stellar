<?php
declare(strict_types=1);

namespace Quasar\Pages;

use Quasar\Controllers\Page;
use Quasar\Core\HttpException;
use Quasar\Scanner\ReportBuilder;
use Quasar\Scanner\Severity;

/**
 * Stellar · página «Informe» (modules/scan_report.json).
 *
 *   index.php?r=page&m=scan_report                     panel: todos los objetivos con su última puntuación
 *   index.php?r=page&m=scan_report&id=N                el informe del análisis N (hallazgos + Markdown para Claude)
 *   index.php?r=page&m=scan_report&target=N            el último análisis acabado del objetivo N
 *   index.php?r=page&m=scan_report&a=markdown&id=N     descarga el informe en .md
 *
 * API (para el MCP): GET /api/v1/pages/scan_report[?id=N|?target=N] → el panel o el informe con el Markdown.
 */
final class ScanReportPage extends Page
{
    public function index(): void
    {
        $scan = $this->requestedScan();
        if ($scan === null) {
            $this->view(['mode' => 'dashboard'] + $this->dashboard());
            return;
        }
        [$scan, $target, $findings] = $scan;
        $title = $target['name'] . ' · #' . $scan['id'];
        $this->view([
            'mode' => 'report',
            'scan' => $scan,
            'target' => $target,
            'findings' => $findings,
            'markdown' => $scan['status'] === 'done' ? $this->markdown($scan, $target, $findings) : '',
            'history' => $this->app->db->fetchAll(
                "SELECT id, score, status, started_at FROM scans WHERE target_id = ? ORDER BY id DESC LIMIT 12",
                [(int) $target['id']]
            ),
            'canScan' => $this->allowed('scan', $this->otherModule('targets')) && (int) $target['authorized'] && (int) $target['active'],
            'canEditFindings' => $this->allowed('edit', $this->otherModule('findings')),
            'scanRunUrl' => $this->app->url('action', ['m' => 'targets', 'a' => 'scan']),
            'downloadUrl' => $this->pageUrl('markdown', ['id' => $scan['id']]),
            'dashboardUrl' => $this->pageUrl(),
            'reportUrl' => fn (int $id) => $this->pageUrl('index', ['id' => $id]),
            'heading' => $title,
            'breadcrumbs' => [[$this->text('title'), $this->pageUrl()], [$title, null]],
        ]);
    }

    /** GET: el informe en Markdown como fichero. */
    public function actionMarkdown(): void
    {
        $data = $this->requestedScan();
        if ($data === null || $data[0]['status'] !== 'done') {
            throw new HttpException(404);
        }
        [$scan, $target] = $data;
        $slug = trim((string) preg_replace('/[^a-z0-9]+/', '-', strtolower(iconv('UTF-8', 'ASCII//TRANSLIT', (string) $target['name']) ?: 'informe')), '-');
        header('Content-Type: text/markdown; charset=utf-8');
        header('Content-Disposition: attachment; filename="stellar-' . ($slug ?: 'informe') . '-' . (int) $scan['id'] . '.md"');
        header('X-Content-Type-Options: nosniff');
        echo $this->markdown(...$data);
        exit;
    }

    public function api(): ?array
    {
        $data = $this->requestedScan();
        if ($data === null) {
            return $this->dashboard();
        }
        [$scan, $target, $findings] = $data;
        return [
            'scan' => $scan,
            'target' => array_intersect_key($target, array_flip(['id', 'name', 'kind', 'url', 'code_path', 'owner', 'last_score'])),
            'findings' => array_map(static fn ($f) => array_intersect_key($f, array_flip(['id', 'severity', 'status', 'title', 'location', 'check_id', 'cwe', 'is_new'])), $findings),
            'markdown' => $scan['status'] === 'done' ? $this->markdown($scan, $target, $findings) : null,
        ];
    }

    // ------------------------------------------------------------------------------------------------

    /** @return array{0:array,1:array,2:list<array>}|null */
    private function requestedScan(): ?array
    {
        $db = $this->app->db;
        $id = $this->param('id', '');
        $target = $this->param('target', '');
        if (ctype_digit((string) $id) && $id !== '') {
            $scan = $db->fetch('SELECT * FROM scans WHERE id = ?', [(int) $id]);
        } elseif (ctype_digit((string) $target) && $target !== '') {
            $scan = $db->fetch(
                "SELECT * FROM scans WHERE target_id = ? ORDER BY status = 'done' DESC, id DESC LIMIT 1",
                [(int) $target]
            );
        } else {
            return null;
        }
        if ($scan === null) {
            throw new HttpException(404);
        }
        $t = $db->fetch('SELECT * FROM targets WHERE id = ?', [(int) $scan['target_id']]) ?? throw new HttpException(404);
        $findings = $db->fetchAll(
            "SELECT * FROM findings WHERE scan_id = ?
              ORDER BY FIELD(status, 'open', 'accepted', 'false_positive', 'fixed'), FIELD(severity, 'critical', 'high', 'medium', 'low', 'info'), id",
            [(int) $scan['id']]
        );
        return [$scan, $t, $findings];
    }

    private function markdown(array $scan, array $target, array $findings): string
    {
        $date = date($this->text('format.datetime'), (int) strtotime((string) ($scan['finished_at'] ?? $scan['started_at'])));
        return $this->builder()->markdown($scan, $target, $findings, $date);
    }

    private function builder(): ReportBuilder
    {
        return new ReportBuilder(fn (string $k, array $v = []): string => $this->text('scanner:' . $k, $v));
    }

    private function dashboard(): array
    {
        $db = $this->app->db;
        $targets = $db->fetchAll(
            "SELECT t.id, t.name, t.kind, t.url, t.code_path, t.owner, t.authorized, t.active, t.last_score, t.last_scan_at, t.last_scan_id,
                    s.critical, s.high, s.medium, s.low, s.new_count, s.fixed_count
               FROM targets t LEFT JOIN scans s ON s.id = t.last_scan_id
              WHERE t.active = 1
              ORDER BY t.last_score IS NULL, t.last_score, t.name"
        );
        $totals = ['targets' => count($targets), 'critical' => 0, 'high' => 0, 'medium' => 0, 'never' => 0];
        foreach ($targets as $t) {
            $totals['critical'] += (int) $t['critical'];
            $totals['high'] += (int) $t['high'];
            $totals['medium'] += (int) $t['medium'];
            $totals['never'] += $t['last_scan_id'] === null ? 1 : 0;
        }
        return [
            'targets' => $targets,
            'totals' => $totals,
            'recent' => $db->fetchAll(
                "SELECT s.id, s.status, s.score, s.started_at, s.error, t.name FROM scans s JOIN targets t ON t.id = s.target_id ORDER BY s.id DESC LIMIT 8"
            ),
        ];
    }

    /** Tono (qs-tone-*) de una puntuación. */
    public static function scoreTone(?int $score): string
    {
        return $score === null ? 'gray' : ($score >= 85 ? 'green' : ($score >= 60 ? 'amber' : 'red'));
    }

    public static function severityTone(string $s): string
    {
        return Severity::tone($s);
    }
}

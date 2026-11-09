<?php
declare(strict_types=1);

namespace Quasar\Scanner;

/**
 * Stellar · el informe en Markdown pensado para pegarlo en claude.ai (o para que Claude Code lo lea por el MCP):
 * instrucciones para Claude, contexto del objetivo, tabla resumen y cada hallazgo con dónde está, qué pasa, la prueba
 * (sin secretos) y cómo resolverlo. Los hallazgos marcados como acceptats, falsos positius o resolts no entran.
 * Se genera al momento a partir de la BD, así que refleja los cambios de estado que se hayan hecho después.
 */
final class ReportBuilder
{
    /** @param \Closure(string,array=):string $t textos de lang/{idioma}/scanner.json */
    public function __construct(private readonly \Closure $t)
    {
    }

    /**
     * @param array $scan     fila de scans
     * @param array $target   fila de targets
     * @param list<array> $findings filas de findings del análisis
     */
    public function markdown(array $scan, array $target, array $findings, string $date): string
    {
        $t = $this->t;
        $open = array_values(array_filter($findings, static fn ($f) => $f['status'] === 'open'));
        $main = array_values(array_filter($open, static fn ($f) => $f['severity'] !== Severity::INFO));
        $info = array_values(array_filter($open, static fn ($f) => $f['severity'] === Severity::INFO));
        $skipped = count($findings) - count($open);
        $meta = json_decode((string) ($scan['meta'] ?? ''), true) ?: [];
        $notes = json_decode((string) ($scan['notes'] ?? ''), true) ?: [];
        $kind = $target['kind'] === 'web' ? 'web' : 'code';

        $md = [];
        $md[] = '# ' . $t('report.title', ['target' => $target['name']]);
        $md[] = '';
        $md[] = '> ' . str_replace("\n", "\n> ", $t("report.intro_$kind"));
        $md[] = '';
        $md[] = '## ' . $t('report.context');
        $md[] = '';
        $where = $kind === 'web' ? (string) ($meta['final_url'] ?? $target['url'])
            : (string) (isset($meta['repo']['repo']) ? $meta['repo']['repo'] : ($meta['zip'] ?? $target['code_path'] ?? ''));
        $md[] = '- **' . $t('report.target') . ':** ' . $target['name'] . ' · ' . $t("kinds.$kind") . ' · `' . $where . '`';
        $md[] = '- **' . $t('report.date') . ':** ' . $date . ' · ' . $t('report.scan_id', ['id' => $scan['id']]);
        $md[] = '- **' . $t('report.score') . ':** ' . (int) $scan['score'] . '/100 · ' . $this->counts($scan);
        if ((int) $scan['new_count'] || (int) $scan['fixed_count']) {
            $md[] = '- **' . $t('report.changes') . ':** ' . $t('report.changes_text', ['new' => $scan['new_count'], 'fixed' => $scan['fixed_count']]);
        }
        foreach ($this->environment($kind, $meta) as $line) {
            $md[] = '- ' . $line;
        }
        $md[] = '';

        if (!$main) {
            $md[] = '## ' . $t('report.findings');
            $md[] = '';
            $md[] = $t('report.none');
            $md[] = '';
        } else {
            $md[] = '## ' . $t('report.summary');
            $md[] = '';
            $md[] = '| # | ' . $t('report.col_severity') . ' | ' . $t('report.col_finding') . ' | ' . $t('report.col_where') . ' |';
            $md[] = '|---|---|---|---|';
            foreach ($main as $f) {
                $md[] = '| S' . $f['id'] . ' | ' . $t('severity.' . $f['severity']) . ' | ' . self::cell($f['title']) . ((int) $f['is_new'] ? ' *(' . $t('report.new') . ')*' : '')
                    . ' | ' . self::cell(self::shortLocation((string) $f['location'])) . ' |';
            }
            $md[] = '';
            $md[] = '## ' . $t('report.findings');
            foreach ($main as $f) {
                $md[] = '';
                $md[] = '### S' . $f['id'] . ' · ' . mb_strtoupper($t('severity.' . $f['severity'])) . ' · ' . $f['title'];
                $md[] = '';
                $md[] = '- **' . $t('report.where') . ':** `' . str_replace('`', "'", (string) $f['location']) . '`';
                if ($f['cwe']) {
                    $n = preg_replace('/\D/', '', (string) $f['cwe']);
                    $md[] = '- **' . $t('report.reference') . ':** [' . $f['cwe'] . '](https://cwe.mitre.org/data/definitions/' . $n . '.html)';
                }
                if ($f['comment']) {
                    $md[] = '- **' . $t('report.comment') . ':** ' . trim((string) $f['comment']);
                }
                $md[] = '';
                $md[] = '**' . $t('report.what') . '** ' . trim((string) $f['detail']);
                if (trim((string) $f['evidence']) !== '') {
                    $md[] = '';
                    $md[] = '**' . $t('report.evidence') . '**';
                    $md[] = '';
                    $fence = str_contains((string) $f['evidence'], '```') ? '~~~~' : '```';
                    $md[] = $fence;
                    $md[] = trim((string) $f['evidence']);
                    $md[] = $fence;
                }
                $md[] = '';
                $md[] = '**' . $t('report.fix') . '** ' . trim((string) $f['fix']);
            }
            $md[] = '';
        }

        if ($info) {
            $md[] = '## ' . $t('report.info');
            $md[] = '';
            foreach ($info as $f) {
                $md[] = '- **S' . $f['id'] . '** ' . $f['title'] . ' — ' . trim((string) $f['fix']);
            }
            $md[] = '';
        }

        $md[] = '## ' . $t('report.limits');
        $md[] = '';
        foreach ($notes as $n) {
            $md[] = '- ' . $n;
        }
        if ($skipped) {
            $md[] = '- ' . $t('report.skipped', ['count' => $skipped]);
        }
        $md[] = '- ' . $t("report.limits_$kind");
        $md[] = '';
        $md[] = '## ' . $t('report.ask');
        $md[] = '';
        $md[] = $t("report.ask_$kind");
        $md[] = '';
        return implode("\n", $md);
    }

    public function counts(array $scan): string
    {
        $parts = [];
        foreach (Severity::ALL as $s) {
            if ((int) $scan[$s] > 0) {
                $parts[] = (int) $scan[$s] . ' ' . mb_strtolower(($this->t)("severity_n.$s"));
            }
        }
        return $parts ? implode(', ', $parts) : ($this->t)('report.no_findings');
    }

    /** @return list<string> */
    private function environment(string $kind, array $meta): array
    {
        $t = $this->t;
        $out = [];
        if ($kind === 'web') {
            $bits = array_filter([
                !empty($meta['server']) ? 'Server: ' . $meta['server'] : null,
                !empty($meta['cms']) ? 'CMS: ' . $meta['cms'] : null,
                !empty($meta['tls']['expires']) ? 'TLS: ' . ($meta['tls']['issuer'] ?? '') . ' → ' . $meta['tls']['expires'] : null,
                !empty($meta['js_libraries']) ? 'JS: ' . implode(', ', array_map(static fn ($k, $v) => "$k $v", array_keys($meta['js_libraries']), $meta['js_libraries'])) : null,
            ]);
            if ($bits) {
                $out[] = '**' . $t('report.environment') . ':** ' . implode(' · ', $bits);
            }
            if (!empty($meta['redirects'])) {
                $out[] = '**' . $t('report.redirects') . ':** ' . implode(' · ', (array) $meta['redirects']);
            }
        } else {
            if (!empty($meta['repo']['repo'])) {
                $r = $meta['repo'];
                $out[] = '**' . $t('report.repo') . ':** `' . $r['repo'] . '`' . (!empty($r['branch']) ? ' · ' . $r['branch'] : '') . (!empty($r['commit']) ? ' · commit `' . $r['commit'] . '`' : '');
            }
            $langs = implode(', ', array_map(static fn ($k, $v) => "$k ($v)", array_keys((array) ($meta['languages'] ?? [])), (array) ($meta['languages'] ?? [])));
            $out[] = '**' . $t('report.code_size') . ':** ' . $t('report.code_size_text', [
                'files' => (int) ($meta['files'] ?? 0), 'lines' => number_format((int) ($meta['lines'] ?? 0), 0, ',', '.'), 'langs' => $langs ?: '—',
            ]);
        }
        return $out;
    }

    private static function cell(string $s): string
    {
        return str_replace(['|', "\n"], ['\\|', ' '], $s);
    }

    private static function shortLocation(string $loc): string
    {
        $loc = preg_replace('#^https?://[^/]+#', '', $loc) ?: '/';
        return mb_strlen($loc) > 60 ? mb_substr($loc, 0, 57) . '…' : $loc;
    }
}

<?php
declare(strict_types=1);

namespace Quasar\Hooks;

use Quasar\Core\Action;
use Quasar\Core\ActionResult;
use Quasar\Core\ModuleHooks;
use Quasar\Core\User;
use Quasar\Scanner\GitSource;
use Quasar\Scanner\ScanRunner;

/**
 * Stellar · objetivos (modules/targets.json): validación al guardar y el botón «Analitza» (permiso propio `scan`).
 */
final class TargetsHooks extends ModuleHooks
{
    public function beforeSave(array &$data, ?string $id, ?array $existing, User $user): ?string
    {
        $kind = (string) ($data['kind'] ?? $existing['kind'] ?? 'web');
        if ($kind === 'web') {
            $url = trim((string) ($data['url'] ?? $existing['url'] ?? ''));
            if ($url === '') {
                return 'errors.url_required';
            }
            if (!preg_match('#^https?://#i', $url)) {
                $url = 'https://' . $url;
            }
            $host = parse_url($url, PHP_URL_HOST);
            if (!is_string($host) || !preg_match('/^[a-z0-9.-]+$/i', $host) || !in_array(strtolower((string) parse_url($url, PHP_URL_SCHEME)), ['http', 'https'], true)) {
                return 'errors.url_invalid';
            }
            if (array_key_exists('url', $data)) {
                $data['url'] = $url;
            }
            return null;
        }
        $source = (string) ($data['code_source'] ?? $existing['code_source'] ?? 'path');
        if ($source === 'git') {
            $repo = trim((string) ($data['repo_url'] ?? $existing['repo_url'] ?? ''));
            if ($repo === '') {
                return 'errors.repo_required';
            }
            if (!preg_match('#^(https://)?[a-z0-9.-]+\.[a-z]{2,}(/[A-Za-z0-9_.\-]+){2,}(\.git)?/?$#i', $repo)) {
                return 'errors.repo_invalid';
            }
            if (array_key_exists('repo_url', $data)) {
                $data['repo_url'] = preg_match('#^https://#i', $repo) ? rtrim($repo, '/') : 'https://' . rtrim($repo, '/');
            }
            if (!GitSource::validBranch(trim((string) ($data['repo_branch'] ?? $existing['repo_branch'] ?? '')))) {
                return 'errors.branch_invalid';
            }
        } elseif ($source === 'path' ? trim((string) ($data['code_path'] ?? $existing['code_path'] ?? '')) === '' : empty($data['code_zip'] ?? $existing['code_zip'] ?? null)) {
            return 'errors.source_required';
        }
        return null;
    }

    public function scan(Action $a): ActionResult
    {
        if (!(int) $a->row['authorized']) {
            return ActionResult::error($a->t('scanner:errors.not_authorized'));
        }
        $t = static fn (string $key, array $vars = []): string => $a->t('scanner:' . $key, $vars);
        $config = ['stellar' => (array) $a->config('stellar', []), 'uploads_dir' => $a->config('uploads_dir')];
        $runner = new ScanRunner($a->db, $config, $t, $a->user->locale() ?? (string) $a->config('locale', 'ca'));
        $scanId = $runner->run((int) $a->id, $a->user->id());
        $scan = $a->db->fetch('SELECT status, error, score FROM scans WHERE id = ?', [$scanId]);
        if (($scan['status'] ?? '') !== 'done') {
            return ActionResult::error((string) ($scan['error'] ?? $a->t('flash.scan_failed')));
        }
        return ActionResult::redirect(
            $a->url('page', ['m' => 'scan_report', 'id' => $scanId]),
            $a->t('flash.scanned', ['score' => (int) $scan['score']])
        );
    }
}

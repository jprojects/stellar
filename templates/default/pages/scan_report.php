<?php
/**
 * Stellar · página "scan_report" (Quasar\Pages\ScanReportPage): panel de objetivos e informe de un análisis.
 * Los estilos van aquí y no en style.css, que es del núcleo. El botón «Copia per a Claude» lo activa
 * templates/stellar/assets/stellar.js (sin él, el Markdown se puede seleccionar y copiar a mano o descargar).
 *
 * @var \Quasar\Core\View $this
 * @var string $mode  dashboard | report
 * dashboard: @var list<array> $targets  @var array $totals  @var list<array> $recent
 * report:    @var array $scan  @var array $target  @var list<array> $findings  @var string $markdown  @var list<array> $history
 *            @var bool $canScan  @var bool $canEditFindings  @var string $scanRunUrl  @var string $downloadUrl  @var string $dashboardUrl  @var callable $reportUrl
 */
use Quasar\Pages\ScanReportPage;

$dt = fn (?string $d): string => $d ? date($this->t('format.datetime'), (int) strtotime($d)) : '—';
$ring = fn (?int $s, string $cls = ''): string => '<span class="stl-ring ' . $cls . ' qs-tone-' . ScanReportPage::scoreTone($s) . '" style="--p: ' . (int) $s . '"><span>' . ($s === null ? '—' : (int) $s) . '</span></span>';
$sev = fn (string $s): string => '<span class="qs-tag qs-tone-' . ScanReportPage::severityTone($s) . '">' . $this->e($this->t('scanner:severity.' . $s)) . '</span>';
?>
<style>
.stl { display: grid; gap: 14px; max-width: 1180px; flex-shrink: 0; }
.stl-box { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); min-width: 0; }
.stl-head { display: flex; align-items: center; gap: 10px; padding: 11px 14px; border-bottom: 1px solid var(--border); flex-wrap: wrap; }
.stl-head h2 { margin: 0; font-size: 14.5px; flex: 1; min-width: 160px; }
.stl-head .qs-icon { color: var(--primary); }
.stl-muted { color: var(--text-muted); font-size: 12.5px; }
.stl-kpis { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 14px; }
.stl-kpi { padding: 12px 14px; }
.stl-kpi b { display: block; font-size: 24px; line-height: 1.2; color: var(--t, var(--text)); }
.stl-kpi span { color: var(--text-muted); font-size: 12px; }
.stl-ring { --p: 0; position: relative; display: inline-grid; place-items: center; width: 44px; height: 44px; border-radius: 50%; flex-shrink: 0;
  background: conic-gradient(var(--t, var(--tone-gray)) calc(var(--p) * 1%), var(--surface-alt) 0); }
.stl-ring::before { content: ""; position: absolute; inset: 5px; border-radius: 50%; background: var(--surface); }
.stl-ring span { position: relative; font-weight: 700; font-size: 13px; }
.stl-ring.is-big { width: 84px; height: 84px; }
.stl-ring.is-big::before { inset: 8px; }
.stl-ring.is-big span { font-size: 24px; }
.stl-table { width: 100%; border-collapse: collapse; font-size: 13px; }
.stl-table th { text-align: left; font-weight: 600; color: var(--text-muted); font-size: 12px; padding: 8px 14px; border-bottom: 1px solid var(--border); }
.stl-table td { padding: 8px 14px; border-bottom: 1px solid var(--border); vertical-align: middle; }
.stl-table tr:last-child td { border-bottom: 0; }
.stl-table tr:hover td { background: var(--row-hover); }
.stl-table a { color: var(--text); text-decoration: none; font-weight: 600; }
.stl-table a:hover { color: var(--primary); }
.stl-num { text-align: right; white-space: nowrap; font-variant-numeric: tabular-nums; }
.stl-where { color: var(--text-muted); font-size: 12px; overflow-wrap: anywhere; }
.stl-score { display: flex; gap: 18px; align-items: center; padding: 14px; flex-wrap: wrap; }
.stl-score-main { flex: 1; min-width: 220px; }
.stl-score-main h3 { margin: 0 0 4px; font-size: 15px; }
.stl-counts { display: flex; gap: 6px; flex-wrap: wrap; margin-top: 6px; }
.stl-history { display: flex; gap: 4px; align-items: flex-end; height: 34px; }
.stl-history a { display: block; width: 9px; border-radius: 2px 2px 0 0; background: var(--t, var(--tone-gray)); opacity: .55; }
.stl-history a.is-current, .stl-history a:hover { opacity: 1; }
.stl-findings { list-style: none; margin: 0; padding: 0; }
.stl-finding + .stl-finding { border-top: 1px solid var(--border); }
.stl-finding > details > summary { display: flex; gap: 10px; align-items: center; padding: 10px 14px; cursor: pointer; list-style: none; }
.stl-finding > details > summary::-webkit-details-marker { display: none; }
.stl-finding > details > summary:hover { background: var(--row-hover); }
.stl-finding-title { flex: 1; min-width: 0; }
.stl-finding-title strong { font-weight: 600; }
.stl-finding.is-closed .stl-finding-title strong { text-decoration: line-through; color: var(--text-muted); }
.stl-finding-body { padding: 0 14px 14px 14px; display: grid; gap: 8px; font-size: 13px; }
.stl-finding-body p { margin: 0; }
.stl-label { font-weight: 600; color: var(--text-muted); font-size: 12px; display: block; margin-bottom: 2px; }
.stl-pre { margin: 0; padding: 8px 10px; background: var(--surface-alt); border: 1px solid var(--border); border-radius: var(--radius);
  font: 12px/1.45 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; white-space: pre-wrap; overflow-wrap: anywhere; max-height: 260px; overflow: auto; }
.stl-fix { padding: 8px 10px; border-left: 3px solid var(--tone-green); background: color-mix(in srgb, var(--tone-green) 9%, var(--surface)); border-radius: 4px; }
.stl-md { width: 100%; min-height: 320px; resize: vertical; box-sizing: border-box; padding: 10px 12px; border: 0; border-top: 1px solid var(--border);
  background: var(--surface-alt); color: var(--text); font: 12px/1.5 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; border-radius: 0 0 var(--radius) var(--radius); }
.stl-actions { display: flex; gap: 8px; flex-wrap: wrap; }
.stl-empty { padding: 26px 14px; text-align: center; color: var(--text-muted); }
.stl-error { padding: 14px; color: var(--tone-red); }
@media (max-width: 700px) { .stl-hide-sm { display: none; } .stl-table td, .stl-table th { padding: 8px 10px; } }
</style>

<div class="stl">
<?php if ($mode === 'dashboard'): ?>

  <div class="stl-kpis">
    <div class="stl-box stl-kpi"><b><?= (int) $totals['targets'] ?></b><span><?= $this->e($this->t('kpi.targets')) ?></span></div>
    <div class="stl-box stl-kpi qs-tone-red"><b><?= (int) $totals['critical'] ?></b><span><?= $this->e($this->t('kpi.critical')) ?></span></div>
    <div class="stl-box stl-kpi qs-tone-orange"><b><?= (int) $totals['high'] ?></b><span><?= $this->e($this->t('kpi.high')) ?></span></div>
    <div class="stl-box stl-kpi qs-tone-amber"><b><?= (int) $totals['medium'] ?></b><span><?= $this->e($this->t('kpi.medium')) ?></span></div>
    <div class="stl-box stl-kpi"><b><?= (int) $totals['never'] ?></b><span><?= $this->e($this->t('kpi.never')) ?></span></div>
  </div>

  <section class="stl-box">
    <div class="stl-head"><?= $this->icon('crosshair') ?><h2><?= $this->e($this->t('targets_heading')) ?></h2>
      <a class="qs-btn qs-btn-sm" href="<?= $this->url('edit', ['m' => 'targets']) ?>"><?= $this->icon('plus') ?> <?= $this->e($this->t('new_target')) ?></a>
    </div>
    <?php if (!$targets): ?>
      <div class="stl-empty"><?= $this->e($this->t('no_targets')) ?></div>
    <?php else: ?>
      <table class="stl-table">
        <thead><tr>
          <th style="width: 56px"></th><th><?= $this->e($this->t('col.target')) ?></th>
          <th class="stl-num"><?= $this->e($this->t('scanner:severity.critical')) ?></th>
          <th class="stl-num"><?= $this->e($this->t('scanner:severity.high')) ?></th>
          <th class="stl-num stl-hide-sm"><?= $this->e($this->t('scanner:severity.medium')) ?></th>
          <th class="stl-hide-sm"><?= $this->e($this->t('col.last')) ?></th>
        </tr></thead>
        <tbody>
        <?php foreach ($targets as $t): ?>
          <?php $href = $t['last_scan_id'] ? $this->url('page', ['m' => 'scan_report', 'target' => $t['id']]) : $this->url('edit', ['m' => 'targets', 'id' => $t['id']]); ?>
          <tr>
            <td><?= $ring($t['last_score'] === null ? null : (int) $t['last_score']) ?></td>
            <td>
              <a href="<?= $href ?>"><?= $this->e($t['name']) ?></a>
              <?php if (!(int) $t['authorized']): ?> <span class="qs-tag qs-tone-red"><?= $this->e($this->t('not_authorized')) ?></span><?php endif ?>
              <div class="stl-where"><?= $this->icon($t['kind'] === 'web' ? 'globe' : 'code') ?> <?= $this->e((string) ($t['url'] ?: $t['code_path'] ?: '.zip')) ?><?= $t['owner'] ? ' · ' . $this->e($t['owner']) : '' ?></div>
            </td>
            <td class="stl-num"><?= $t['last_scan_id'] ? (int) $t['critical'] : '—' ?></td>
            <td class="stl-num"><?= $t['last_scan_id'] ? (int) $t['high'] : '—' ?></td>
            <td class="stl-num stl-hide-sm"><?= $t['last_scan_id'] ? (int) $t['medium'] : '—' ?></td>
            <td class="stl-muted stl-hide-sm"><?= $t['last_scan_at'] ? $this->e($dt($t['last_scan_at'])) : $this->e($this->t('never')) ?></td>
          </tr>
        <?php endforeach ?>
        </tbody>
      </table>
    <?php endif ?>
  </section>

  <?php if ($recent): ?>
  <section class="stl-box">
    <div class="stl-head"><?= $this->icon('history') ?><h2><?= $this->e($this->t('recent_heading')) ?></h2>
      <a class="qs-btn qs-btn-sm qs-btn-ghost" href="<?= $this->url('list', ['m' => 'scans']) ?>"><?= $this->e($this->t('see_all')) ?></a>
    </div>
    <table class="stl-table"><tbody>
      <?php foreach ($recent as $s): ?>
        <tr>
          <td class="stl-muted" style="width: 150px"><?= $this->e($dt($s['started_at'])) ?></td>
          <td><?php if ($s['status'] === 'done'): ?><a href="<?= $this->url('page', ['m' => 'scan_report', 'id' => $s['id']]) ?>"><?= $this->e($s['name']) ?></a><?php else: ?><?= $this->e($s['name']) ?><?php endif ?>
            <?php if ($s['status'] === 'failed'): ?><div class="stl-where" style="color: var(--tone-red)"><?= $this->e((string) $s['error']) ?></div><?php endif ?></td>
          <td class="stl-num"><?= $s['status'] === 'done' ? (int) $s['score'] . '/100' : '<span class="qs-tag qs-tone-' . ($s['status'] === 'failed' ? 'red' : 'blue') . '">' . $this->e($this->t('scans:status.' . $s['status'])) . '</span>' ?></td>
        </tr>
      <?php endforeach ?>
    </tbody></table>
  </section>
  <?php endif ?>

<?php else: /* report */ ?>
  <?php
    $open = array_filter($findings, static fn ($f) => $f['status'] === 'open');
    $closed = count($findings) - count($open);
  ?>
  <section class="stl-box">
    <div class="stl-score">
      <?= $ring($scan['status'] === 'done' ? (int) $scan['score'] : null, 'is-big') ?>
      <div class="stl-score-main">
        <h3><?= $this->e($target['name']) ?> <span class="stl-muted">· <?= $this->e($this->t('scanner:kinds.' . $target['kind'])) ?></span></h3>
        <div class="stl-where"><?= $this->e((string) ($target['url'] ?: $target['code_path'] ?: '.zip')) ?></div>
        <div class="stl-muted"><?= $this->e($this->t('scan_info', ['id' => $scan['id'], 'date' => $dt($scan['started_at']), 'duration' => (int) $scan['duration']])) ?></div>
        <?php if ($scan['status'] === 'done'): ?>
          <div class="stl-counts">
            <?php foreach (['critical', 'high', 'medium', 'low', 'info'] as $s): ?>
              <?php if ((int) $scan[$s]): ?><span class="qs-tag qs-tone-<?= ScanReportPage::severityTone($s) ?>"><?= (int) $scan[$s] ?> <?= $this->e(mb_strtolower($this->t('scanner:severity_n.' . $s))) ?></span><?php endif ?>
            <?php endforeach ?>
            <?php if ((int) $scan['new_count']): ?><span class="qs-tag qs-tone-blue"><?= $this->e($this->t('new_count', ['n' => $scan['new_count']])) ?></span><?php endif ?>
            <?php if ((int) $scan['fixed_count']): ?><span class="qs-tag qs-tone-green"><?= $this->e($this->t('fixed_count', ['n' => $scan['fixed_count']])) ?></span><?php endif ?>
          </div>
        <?php endif ?>
      </div>
      <?php if (count($history) > 1): ?>
        <div class="stl-history" title="<?= $this->e($this->t('history')) ?>">
          <?php foreach (array_reverse($history) as $h): ?>
            <?php if ($h['status'] === 'done'): ?>
              <a href="<?= $this->e($reportUrl((int) $h['id'])) ?>" class="qs-tone-<?= ScanReportPage::scoreTone((int) $h['score']) ?><?= (int) $h['id'] === (int) $scan['id'] ? ' is-current' : '' ?>"
                 style="height: <?= max(3, (int) $h['score'] * 34 / 100) ?>px" title="#<?= (int) $h['id'] ?> · <?= $this->e($dt($h['started_at'])) ?> · <?= (int) $h['score'] ?>"></a>
            <?php endif ?>
          <?php endforeach ?>
        </div>
      <?php endif ?>
    </div>
    <div class="stl-head" style="border-top: 1px solid var(--border); border-bottom: 0">
      <div class="stl-actions">
        <a class="qs-btn qs-btn-sm qs-btn-ghost" href="<?= $this->e($dashboardUrl) ?>"><?= $this->icon('arrow-left') ?> <?= $this->e($this->t('back')) ?></a>
        <a class="qs-btn qs-btn-sm" href="<?= $this->url('edit', ['m' => 'targets', 'id' => $target['id']]) ?>"><?= $this->icon('crosshair') ?> <?= $this->e($this->t('target')) ?></a>
        <a class="qs-btn qs-btn-sm" href="<?= $this->url('list', ['m' => 'findings', 'f' => ['scan_id' => (int) $scan['id']]]) ?>"><?= $this->icon('list-checks') ?> <?= $this->e($this->t('manage_findings')) ?></a>
        <?php if ($canScan): ?>
          <button type="button" class="qs-btn qs-btn-sm qs-btn-primary"
                  data-qs-action="<?= $this->json(['run' => $scanRunUrl, 'id' => (string) $target['id'], 'label' => $this->t('rescan'), 'confirm' => $this->t('targets:confirm.scan')]) ?>">
            <?= $this->icon('radar') ?> <?= $this->e($this->t('rescan')) ?></button>
        <?php endif ?>
      </div>
    </div>
  </section>

  <?php if ($scan['status'] === 'failed'): ?>
    <section class="stl-box stl-error"><?= $this->icon('triangle-alert') ?> <?= $this->e((string) $scan['error']) ?></section>
  <?php elseif ($scan['status'] === 'running'): ?>
    <section class="stl-box stl-empty"><?= $this->e($this->t('running')) ?></section>
  <?php else: ?>

  <section class="stl-box">
    <div class="stl-head"><?= $this->icon('sparkles') ?><h2><?= $this->e($this->t('claude_heading')) ?></h2>
      <div class="stl-actions">
        <button type="button" class="qs-btn qs-btn-sm qs-btn-primary" data-stellar-copy="stl-md" data-copied="<?= $this->e($this->t('copied')) ?>" hidden><?= $this->icon('clipboard-copy') ?> <?= $this->e($this->t('copy')) ?></button>
        <a class="qs-btn qs-btn-sm" href="<?= $this->e($downloadUrl) ?>"><?= $this->icon('download') ?> <?= $this->e($this->t('download')) ?></a>
      </div>
    </div>
    <div class="stl-head stl-muted" style="border-bottom: 0"><?= $this->e($this->t('claude_help')) ?></div>
    <textarea id="stl-md" class="stl-md" readonly spellcheck="false"><?= $this->e($markdown) ?></textarea>
  </section>

  <section class="stl-box">
    <div class="stl-head"><?= $this->icon('shield-alert') ?><h2><?= $this->e($this->t('findings_heading', ['n' => count($open)])) ?></h2>
      <?php if ($closed): ?><span class="stl-muted"><?= $this->e($this->t('closed_count', ['n' => $closed])) ?></span><?php endif ?>
    </div>
    <?php if (!$findings): ?>
      <div class="stl-empty"><?= $this->icon('shield-check') ?> <?= $this->e($this->t('scanner:report.none')) ?></div>
    <?php else: ?>
      <ul class="stl-findings">
        <?php foreach ($findings as $f): ?>
          <li class="stl-finding<?= $f['status'] !== 'open' ? ' is-closed' : '' ?>">
            <details>
              <summary>
                <?= $sev($f['severity']) ?>
                <span class="stl-finding-title"><strong><?= $this->e($f['title']) ?></strong>
                  <span class="stl-where"><br><?= $this->e((string) $f['location']) ?></span></span>
                <?php if ((int) $f['is_new']): ?><span class="qs-tag qs-tone-blue"><?= $this->e($this->t('scanner:report.new')) ?></span><?php endif ?>
                <?php if ($f['status'] !== 'open'): ?><span class="qs-tag"><?= $this->e($this->t('findings:status.' . $f['status'])) ?></span><?php endif ?>
                <span class="stl-muted">S<?= (int) $f['id'] ?></span>
              </summary>
              <div class="stl-finding-body">
                <p><?= $this->e((string) $f['detail']) ?></p>
                <?php if (trim((string) $f['evidence']) !== ''): ?>
                  <div><span class="stl-label"><?= $this->e($this->t('scanner:report.evidence')) ?></span><pre class="stl-pre"><?= $this->e((string) $f['evidence']) ?></pre></div>
                <?php endif ?>
                <div class="stl-fix"><span class="stl-label"><?= $this->e($this->t('scanner:report.fix')) ?></span><?= $this->e((string) $f['fix']) ?></div>
                <div class="stl-actions">
                  <?php if ($f['cwe']): ?><a class="qs-btn qs-btn-sm qs-btn-ghost" target="_blank" rel="noopener" href="https://cwe.mitre.org/data/definitions/<?= (int) preg_replace('/\D/', '', (string) $f['cwe']) ?>.html"><?= $this->icon('book-open') ?> <?= $this->e($f['cwe']) ?></a><?php endif ?>
                  <?php if ($canEditFindings): ?><a class="qs-btn qs-btn-sm" href="<?= $this->url('edit', ['m' => 'findings', 'id' => $f['id']]) ?>"><?= $this->icon('pencil') ?> <?= $this->e($this->t('mark')) ?></a><?php endif ?>
                </div>
              </div>
            </details>
          </li>
        <?php endforeach ?>
      </ul>
    <?php endif ?>
  </section>
  <?php endif ?>
<?php endif ?>
</div>
<?php if ($this->hasAsset('stellar.js')): ?><script src="<?= $this->asset('stellar.js') ?>" defer></script><?php endif ?>

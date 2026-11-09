#!/usr/bin/env php
<?php
/**
 * Stellar · lanza análisis desde la terminal o el cron.
 *
 *   php tools/scan.php --target=3            un objetivo
 *   php tools/scan.php --all                 todos los activos y autorizados
 *   php tools/scan.php --due=7               los que no se han analizado en los últimos 7 días (para el cron)
 *   opciones: --locale=ca|es|en (idioma de los textos; por defecto el de la config)  --md (imprime el informe)
 *
 * Cron semanal de ejemplo: 0 4 * * 1  php /ruta/stellar/tools/scan.php --due=7 > /dev/null 2>&1
 */
declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    exit(1);
}
$config = require dirname(__DIR__) . '/src/bootstrap.php';

use Quasar\Core\Database;
use Quasar\Core\Lang;
use Quasar\Scanner\ReportBuilder;
use Quasar\Scanner\ScanRunner;

$opts = getopt('', ['target:', 'all', 'due:', 'locale:', 'md']);
$locale = (string) ($opts['locale'] ?? $config['locale'] ?? 'ca');
$lang = new Lang(QS_ROOT . '/lang', $locale, (string) ($config['fallback_locale'] ?? 'es'));
$t = static fn (string $k, array $v = []): string => $lang->get('scanner:' . $k, $v);

try {
    $db = new Database($config['db']);
    if (isset($opts['target'])) {
        $ids = [(int) $opts['target']];
    } elseif (isset($opts['all']) || isset($opts['due'])) {
        $sql = 'SELECT id FROM targets WHERE active = 1 AND authorized = 1';
        $params = [];
        if (isset($opts['due'])) {
            $sql .= ' AND (last_scan_at IS NULL OR last_scan_at < ?)';
            $params[] = date('Y-m-d H:i:s', time() - max(1, (int) $opts['due']) * 86400);
        }
        $ids = array_map('intval', array_column($db->fetchAll($sql . ' ORDER BY id', $params), 'id'));
    } else {
        fwrite(STDERR, "Uso: php tools/scan.php --target=N | --all | --due=DÍAS [--locale=ca] [--md]\n");
        exit(2);
    }

    $runner = new ScanRunner($db, $config, $t, $locale);
    $failed = 0;
    foreach ($ids as $id) {
        $name = (string) $db->fetchValue('SELECT name FROM targets WHERE id = ?', [$id]);
        echo "→ $name (#$id)… ";
        $scanId = $runner->run($id);
        $scan = $db->fetch('SELECT * FROM scans WHERE id = ?', [$scanId]);
        if ($scan['status'] !== 'done') {
            $failed++;
            echo 'ERROR: ' . $scan['error'] . PHP_EOL;
            continue;
        }
        $builder = new ReportBuilder($t);
        printf("%d/100 · %s · %ds (análisis #%d)\n", $scan['score'], $builder->counts($scan), $scan['duration'], $scanId);
        if (isset($opts['md'])) {
            $target = $db->fetch('SELECT * FROM targets WHERE id = ?', [$id]);
            $findings = $db->fetchAll('SELECT * FROM findings WHERE scan_id = ? ORDER BY id', [$scanId]);
            echo PHP_EOL . $builder->markdown($scan, $target, $findings, date('d/m/Y H:i')) . PHP_EOL;
        }
    }
    exit($failed ? 1 : 0);
} catch (\Throwable $e) {
    fwrite(STDERR, 'Error: ' . $e->getMessage() . PHP_EOL);
    exit(1);
}

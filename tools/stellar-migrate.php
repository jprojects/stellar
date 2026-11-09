#!/usr/bin/env php
<?php
/**
 * Stellar · crea o actualiza las tablas propias (database/stellar.sql). Idempotente: se puede ejecutar siempre.
 * Las del núcleo las crea `php bin/install.php` (antes que esto).
 *
 *   php tools/stellar-migrate.php
 */
declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    exit(1);
}
$config = require dirname(__DIR__) . '/src/bootstrap.php';

use Quasar\Core\Database;

try {
    $db = new Database($config['db']);
    $sql = (string) file_get_contents(QS_ROOT . '/database/stellar.sql');
    $sql = (string) preg_replace('/^\s*--.*$/m', '', $sql);
    $n = 0;
    foreach (array_filter(array_map('trim', explode(";\n", $sql))) as $statement) {
        $db->query($statement);
        $n++;
    }
    echo "Stellar: $n sentencias aplicadas (tablas targets, scans, findings).\n";
} catch (\Throwable $e) {
    fwrite(STDERR, 'Error: ' . $e->getMessage() . PHP_EOL);
    exit(1);
}

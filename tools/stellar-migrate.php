#!/usr/bin/env php
<?php
/**
 * Stellar · crea o actualiza las tablas propias (database/stellar.sql). Idempotente: se puede ejecutar siempre.
 * Las del núcleo las crea `php bin/install.php` (antes que esto). Las columnas añadidas después de crear una tabla
 * van en COLUMNS (se añaden si faltan).
 *
 *   php tools/stellar-migrate.php
 */
declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    exit(1);
}
$config = require dirname(__DIR__) . '/src/bootstrap.php';

use Quasar\Core\Database;

/** Columnas añadidas a tablas ya existentes: tabla => [columna => definición]. */
const COLUMNS = [
    'targets' => [
        'code_source' => "VARCHAR(10) NOT NULL DEFAULT 'path' AFTER url",
        'repo_url' => 'VARCHAR(500) NULL AFTER code_zip',
        'repo_branch' => 'VARCHAR(150) NULL AFTER repo_url',
    ],
];

try {
    $db = new Database($config['db']);
    $sql = (string) file_get_contents(QS_ROOT . '/database/stellar.sql');
    $sql = (string) preg_replace('/^\s*--.*$/m', '', $sql);
    $n = 0;
    foreach (array_filter(array_map('trim', explode(";\n", $sql))) as $statement) {
        $db->query($statement);
        $n++;
    }
    $added = [];
    foreach (COLUMNS as $table => $columns) {
        foreach ($columns as $column => $definition) {
            $exists = $db->fetchValue(
                'SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ?',
                [$table, $column]
            );
            if (!(int) $exists) {
                $db->query("ALTER TABLE `$table` ADD COLUMN `$column` $definition");
                $added[] = "$table.$column";
            }
        }
    }
    if (in_array('targets.code_source', $added, true)) {
        // Objetivos de código que ya había: el origen es el .zip si no tienen carpeta
        $db->query("UPDATE targets SET code_source = 'zip' WHERE kind = 'code' AND COALESCE(code_path, '') = '' AND code_zip IS NOT NULL");
    }
    echo "Stellar: $n sentencias aplicadas (tablas targets, scans, findings)" . ($added ? '; columnas nuevas: ' . implode(', ', $added) : '') . ".\n";
} catch (\Throwable $e) {
    fwrite(STDERR, 'Error: ' . $e->getMessage() . PHP_EOL);
    exit(1);
}

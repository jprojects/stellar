<?php
declare(strict_types=1);

namespace Quasar\Hooks;

use Quasar\Core\ModuleHooks;
use Quasar\Core\User;
use Quasar\Scanner\Severity;

/**
 * Stellar · hallazgos (modules/findings.json): solo se cambia el estado y la nota. Al guardar se recalculan los
 * recuentos y la puntuación del análisis (un falso positivo o un riesgo aceptado ya no cuentan) y, si es el último
 * análisis del objetivo, también la del objetivo.
 */
final class FindingsHooks extends ModuleHooks
{
    public function afterSave(string $id, array $data, bool $isNew, User $user): void
    {
        $scanId = (int) $this->db->fetchValue('SELECT scan_id FROM findings WHERE id = ?', [(int) $id]);
        if ($scanId) {
            self::recompute($this->db, $scanId);
        }
    }

    public static function recompute(\Quasar\Core\Database $db, int $scanId): void
    {
        $rows = $db->fetchAll("SELECT check_id AS `check`, severity FROM findings WHERE scan_id = ? AND status = 'open'", [$scanId]);
        $counts = array_fill_keys(Severity::ALL, 0);
        foreach ($rows as $r) {
            $counts[$r['severity']] = ($counts[$r['severity']] ?? 0) + 1;
        }
        $score = Severity::score($rows);
        $db->update('scans', ['score' => $score] + $counts, 'id', $scanId);
        $db->query('UPDATE targets SET last_score = ? WHERE last_scan_id = ?', [$score, $scanId]);
    }
}

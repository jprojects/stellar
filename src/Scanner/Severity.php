<?php
declare(strict_types=1);

namespace Quasar\Scanner;

/** Stellar · gravedades de los hallazgos, su orden y lo que restan a la puntuación (100 = sin problemas). */
final class Severity
{
    public const CRITICAL = 'critical';
    public const HIGH = 'high';
    public const MEDIUM = 'medium';
    public const LOW = 'low';
    public const INFO = 'info';

    /** De más a menos grave. */
    public const ALL = [self::CRITICAL, self::HIGH, self::MEDIUM, self::LOW, self::INFO];

    private const WEIGHT = [self::CRITICAL => 30, self::HIGH => 12, self::MEDIUM => 5, self::LOW => 1, self::INFO => 0];

    public static function valid(string $s): bool
    {
        return in_array($s, self::ALL, true);
    }

    public static function rank(string $s): int
    {
        $i = array_search($s, self::ALL, true);
        return $i === false ? 99 : $i;
    }

    /**
     * Puntuación 0-100. Cada control cuenta una vez con su peor gravedad (veinte cookies sin un atributo no son
     * veinte problemas distintos) y las repeticiones suman un poco más.
     * @param iterable<array{check:string,severity:string}> $findings
     */
    public static function score(iterable $findings): int
    {
        $worst = [];
        $extra = 0.0;
        foreach ($findings as $f) {
            $w = self::WEIGHT[$f['severity']] ?? 0;
            if (isset($worst[$f['check']])) {
                $extra += min($w, $worst[$f['check']]) * 0.2;
                $worst[$f['check']] = max($worst[$f['check']], $w);
            } else {
                $worst[$f['check']] = $w;
            }
        }
        return max(0, (int) round(100 - array_sum($worst) - min($extra, 20)));
    }

    /** Color de la plantilla (qs-tone-*) para una gravedad. */
    public static function tone(string $s): string
    {
        return [self::CRITICAL => 'red', self::HIGH => 'orange', self::MEDIUM => 'amber', self::LOW => 'blue', self::INFO => 'gray'][$s] ?? 'gray';
    }

    /** Gravedad a partir de una puntuación CVSS o de la etiqueta de GitHub/OSV. */
    public static function fromAdvisory(?string $label, ?float $cvss = null): string
    {
        $label = strtoupper((string) $label);
        if ($cvss !== null) {
            return $cvss >= 9 ? self::CRITICAL : ($cvss >= 7 ? self::HIGH : ($cvss >= 4 ? self::MEDIUM : self::LOW));
        }
        return match ($label) {
            'CRITICAL' => self::CRITICAL,
            'HIGH' => self::HIGH,
            'MODERATE', 'MEDIUM' => self::MEDIUM,
            'LOW' => self::LOW,
            default => self::MEDIUM,
        };
    }
}

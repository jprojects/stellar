<?php
declare(strict_types=1);

namespace Quasar\Scanner;

/**
 * Stellar · quita los secretos de las pruebas antes de guardarlas o de pasarlas a Claude: una clave encontrada en el
 * código o en un .env publicado no tiene que acabar copiada en un chat. Deja los primeros caracteres para reconocerla.
 */
final class Redactor
{
    private const PATTERNS = [
        // clave = valor en .env, PHP, JS, YAML… cuando el nombre parece un secreto
        '/((?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|apikey|auth|private[_-]?key|client[_-]?secret|access[_-]?key|credentials?)[A-Za-z0-9_\-]*["\']?\s*(?:=>|=|:)\s*["\']?)(?![\$(])([^"\'\s,;()]{4,}+)(?!\()/i',
        // tokens con formato conocido
        '/\b(AKIA|ASIA)[A-Z0-9]{16}\b/',
        '/\b(sk|rk|pk)_(live|test)_[A-Za-z0-9]{10,}\b/',
        '/\bsk-ant-[A-Za-z0-9_\-]{10,}\b/',
        '/\bsk-[A-Za-z0-9]{20,}\b/',
        '/\bgh[pousr]_[A-Za-z0-9]{20,}\b/',
        '/\bxox[abposr]-[A-Za-z0-9\-]{10,}\b/',
        '/\bAIza[0-9A-Za-z_\-]{30,}\b/',
        '/\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b/',
        '/\b(qs_)[A-Za-z0-9]{16,}\b/',
    ];

    public static function clean(string $text, int $max = 600): string
    {
        // Claves privadas: fuera el bloque entero
        $text = (string) preg_replace('/-----BEGIN ([A-Z ]*)PRIVATE KEY-----.*?(-----END \1PRIVATE KEY-----|$)/s', '-----BEGIN $1PRIVATE KEY----- [***] -----END $1PRIVATE KEY-----', $text);
        $text = (string) preg_replace_callback(self::PATTERNS[0], static fn (array $m) => $m[1] . self::mask($m[2]), $text);
        foreach (array_slice(self::PATTERNS, 1) as $re) {
            $text = (string) preg_replace_callback($re, static fn (array $m) => self::mask($m[0]), $text);
        }
        $text = trim($text);
        return mb_strlen($text) > $max ? mb_substr($text, 0, $max) . ' […]' : $text;
    }

    public static function mask(string $secret): string
    {
        return mb_substr($secret, 0, min(4, intdiv(mb_strlen($secret), 3))) . '***';
    }
}

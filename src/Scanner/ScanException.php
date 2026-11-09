<?php
declare(strict_types=1);

namespace Quasar\Scanner;

/**
 * Stellar · el análisis no se puede hacer (destino no permitido, web que no responde, carpeta fuera de las
 * permitidas…). El mensaje es una clave de lang/{idioma}/scanner.json (errors.*) y $vars sus variables.
 */
final class ScanException extends \RuntimeException
{
    /** @param array<string,string|int> $vars */
    public function __construct(string $key, public readonly array $vars = [])
    {
        parent::__construct($key);
    }
}

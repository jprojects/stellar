<?php
declare(strict_types=1);

namespace Quasar\Scanner;

/**
 * Stellar · un hallazgo de un análisis. El título, la explicación y la solución no se guardan aquí: salen de
 * lang/{idioma}/scanner.json (checks.{check}.title|detail|fix) con las variables de $vars, en el idioma de quien
 * lanza el análisis.
 */
final class Finding
{
    /**
     * @param string $check     id del control (p. ej. "web.hsts_missing"): clave de los textos en scanner.json
     * @param string $severity  Severity::*
     * @param array<string,string|int> $vars variables de los textos
     * @param string $location  URL, ruta o fichero:línea
     * @param string $evidence  la prueba (ya sin secretos: pasa por Redactor)
     * @param string $key       distingue dos hallazgos del mismo control en el mismo sitio (para la huella)
     */
    public function __construct(
        public readonly string $check,
        public readonly string $severity,
        public readonly array $vars = [],
        public readonly string $location = '',
        public readonly string $evidence = '',
        public readonly ?string $cwe = null,
        public readonly string $key = '',
    ) {
        if (!Severity::valid($severity)) {
            throw new \InvalidArgumentException("Gravedad no válida: $severity");
        }
    }

    /** Huella estable entre análisis: el mismo problema en el mismo sitio tiene la misma huella. */
    public function fingerprint(): string
    {
        // Sin números de línea: si el código se mueve, sigue siendo el mismo hallazgo
        $location = preg_replace('/:\d+$/', '', $this->location);
        return sha1($this->check . '|' . $location . '|' . $this->key);
    }

    public function category(): string
    {
        return strstr($this->check, '.', true) ?: $this->check;
    }
}

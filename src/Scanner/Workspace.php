<?php
declare(strict_types=1);

namespace Quasar\Scanner;

/**
 * Stellar · carpeta temporal donde se descomprime el .zip de código que se ha subido o se descarga un repositorio git.
 * Se borra al acabar.
 * Protegida contra zips maliciosos: nada fuera de la carpeta («zip slip»), sin enlaces y con límites de tamaño y de
 * número de ficheros («zip bomb»).
 */
final class Workspace
{
    private ?string $dir = null;
    /** @var list<string> carpetas creadas (todas se borran en cleanup) */
    private array $created = [];

    public function __construct(private readonly string $base, private readonly int $maxBytes = 314572800, private readonly int $maxEntries = 60000)
    {
    }

    public function extract(string $zipFile): string
    {
        if (!class_exists(\ZipArchive::class)) {
            throw new ScanException('errors.no_zip_ext');
        }
        $zip = new \ZipArchive();
        if ($zip->open($zipFile, \ZipArchive::RDONLY) !== true) {
            throw new ScanException('errors.bad_zip');
        }
        if ($zip->numFiles > $this->maxEntries) {
            throw new ScanException('errors.zip_too_big');
        }
        $total = 0;
        for ($i = 0; $i < $zip->numFiles; $i++) {
            $st = $zip->statIndex($i);
            $name = (string) ($st['name'] ?? '');
            $total += (int) ($st['size'] ?? 0);
            if ($name === '' || str_starts_with($name, '/') || str_contains($name, '\\') || preg_match('#(^|/)\.\.(/|$)#', $name) || preg_match('/^[a-z]:/i', $name)) {
                throw new ScanException('errors.bad_zip');
            }
            // Enlaces simbólicos (atributos de Unix): fuera
            if ($zip->getExternalAttributesIndex($i, $os, $attr) && $os === \ZipArchive::OPSYS_UNIX && (($attr >> 16) & 0170000) === 0120000) {
                throw new ScanException('errors.bad_zip');
            }
        }
        if ($total > $this->maxBytes) {
            throw new ScanException('errors.zip_too_big');
        }
        if (!is_dir($this->base) && !@mkdir($this->base, 0770, true)) {
            throw new \RuntimeException("Stellar: no se puede crear {$this->base}");
        }
        $this->dir = $this->base . '/zip-' . bin2hex(random_bytes(8));
        mkdir($this->dir, 0770);
        $this->created[] = $this->dir;
        if (!$zip->extractTo($this->dir)) {
            $zip->close();
            throw new ScanException('errors.bad_zip');
        }
        $zip->close();
        // Si todo está dentro de una sola carpeta (proyecto-main/…), se analiza esa
        $entries = array_values(array_diff(scandir($this->dir) ?: [], ['.', '..', '__MACOSX']));
        return count($entries) === 1 && is_dir($this->dir . '/' . $entries[0]) ? $this->dir . '/' . $entries[0] : $this->dir;
    }

    /** Carpeta temporal vacía (para un git clone). */
    public function emptyDir(): string
    {
        if (!is_dir($this->base) && !@mkdir($this->base, 0770, true)) {
            throw new \RuntimeException("Stellar: no se puede crear {$this->base}");
        }
        $this->dir = $this->base . '/git-' . bin2hex(random_bytes(8));
        mkdir($this->dir, 0770);
        $this->created[] = $this->dir;
        return $this->dir;
    }

    /** Bytes que ocupa la carpeta de trabajo. */
    public function size(): int
    {
        $total = 0;
        if ($this->dir !== null && is_dir($this->dir)) {
            foreach (new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($this->dir, \FilesystemIterator::SKIP_DOTS)) as $f) {
                $total += $f->isLink() ? 0 : $f->getSize();
            }
        }
        return $total;
    }

    public function maxBytes(): int
    {
        return $this->maxBytes;
    }

    public function cleanup(): void
    {
        foreach ($this->created as $dir) {
            if (!is_dir($dir)) {
                continue;
            }
            $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS), \RecursiveIteratorIterator::CHILD_FIRST);
            foreach ($it as $f) {
                $f->isDir() && !$f->isLink() ? @rmdir($f->getPathname()) : @unlink($f->getPathname());
            }
            @rmdir($dir);
        }
        $this->created = [];
        $this->dir = null;
    }

    public function __destruct()
    {
        $this->cleanup();
    }
}

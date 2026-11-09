<?php
declare(strict_types=1);

namespace Quasar\Scanner;

/**
 * Stellar · trae el código de un repositorio git (público o privado) a una carpeta temporal para analizarlo, y nada
 * más: no guarda copia (Workspace la borra al acabar).
 *
 * - Con `git` en el servidor: `git clone --depth 1` de la rama (sin historial, sin submódulos, sin LFS, sin enlaces
 *   simbólicos). Así se sabe qué ficheros están en el repositorio (un .env en git es más grave).
 * - Sin `git` (algunos hostings): si es de GitHub, descarga la rama en .zip con la API, con el mismo token.
 *
 * Seguridad: solo URL https:// de los hosts permitidos ('git_hosts' y los de 'git_tokens'; por defecto github.com,
 * gitlab.com y bitbucket.org), para que no sirva para llegar a la red interna. El token nunca va en la URL, en los
 * argumentos (se veria con `ps`) ni en .git/config: git lo recibe por variables de entorno como cabecera HTTP. Los
 * mensajes de error se limpian del token antes de guardarse.
 *
 * Configuración (config.local.php):
 *   'stellar' => [
 *       'git_tokens' => ['github.com' => 'github_pat_…'],   // repos privados (token de solo lectura)
 *       'git_hosts' => ['git.empresa.com'],                // otros hosts permitidos (además de los de git_tokens)
 *       'git_timeout' => 300,                              // segundos máximos para descargar
 *   ]
 */
final class GitSource
{
    private const DEFAULT_HOSTS = ['github.com', 'gitlab.com', 'bitbucket.org'];
    /** Usuario de la autenticación HTTP Basic que espera cada servicio junto al token. */
    private const TOKEN_USER = ['github.com' => 'x-access-token', 'gitlab.com' => 'oauth2', 'bitbucket.org' => 'x-token-auth'];

    public function __construct(private readonly array $opts = [])
    {
    }

    /**
     * Valida la URL del repositorio. Acepta https://host/propietario/repo(.git) y también host/propietario/repo.
     * @return array{url:string,host:string,path:string}
     */
    public function parse(string $url): array
    {
        $url = trim($url);
        if (!preg_match('#^https?://#i', $url)) {
            $url = 'https://' . $url;
        }
        $p = parse_url($url);
        $host = strtolower((string) ($p['host'] ?? ''));
        $path = trim((string) ($p['path'] ?? ''), '/');
        if ($p === false || strtolower((string) ($p['scheme'] ?? '')) !== 'https' || isset($p['user']) || isset($p['pass']) || isset($p['port'])
            || isset($p['query']) || !preg_match('#^[A-Za-z0-9_.\-]+(/[A-Za-z0-9_.\-]+)+$#', $path) || str_contains($path, '..')) {
            throw new ScanException('errors.repo_url', ['url' => $url]);
        }
        if (!in_array($host, $this->hosts(), true)) {
            throw new ScanException('errors.repo_host', ['host' => $host, 'hosts' => implode(', ', $this->hosts())]);
        }
        $path = (string) preg_replace('/\.git$/', '', $path);
        return ['url' => "https://$host/$path.git", 'host' => $host, 'path' => $path];
    }

    public static function validBranch(string $branch): bool
    {
        return $branch === '' || (bool) preg_match('#^(?!-)(?!.*\.\.)[A-Za-z0-9._/\-]{1,150}$#', $branch);
    }

    /**
     * Descarga el repositorio en la carpeta de trabajo.
     * @return array{dir:string,all_tracked:bool,meta:array{repo:string,branch:string,commit:string,method:string}}
     */
    public function fetch(string $url, string $branch, Workspace $ws): array
    {
        $repo = $this->parse($url);
        $branch = trim($branch);
        if (!self::validBranch($branch)) {
            throw new ScanException('errors.repo_branch', ['branch' => $branch]);
        }
        if ($this->hasGit()) {
            return $this->cloneRepo($repo, $branch, $ws);
        }
        if ($repo['host'] === 'github.com') {
            return $this->githubZip($repo, $branch, $ws);
        }
        throw new ScanException('errors.no_git');
    }

    // ------------------------------------------------------------------------------------------------ git clone

    private function cloneRepo(array $repo, string $branch, Workspace $ws): array
    {
        $dir = $ws->emptyDir();
        $cmd = ['git', 'clone', '--depth', '1', '--single-branch', '--no-tags', '--quiet'];
        if ($branch !== '') {
            array_push($cmd, '--branch', $branch);
        }
        array_push($cmd, '--', $repo['url'], $dir . '/repo');

        // Configuración solo para esta orden (sin la del usuario ni la del sistema)
        $config = [
            'core.symlinks' => 'false',          // los enlaces simbólicos quedan como ficheros de texto
            'protocol.allow' => 'never',          // solo https, también para lo que pudiera pedir el repositorio
            'protocol.https.allow' => 'always',
            'core.hooksPath' => '/dev/null',
        ];
        $token = $this->token($repo['host']);
        if ($token !== null) {
            $user = self::TOKEN_USER[$repo['host']] ?? 'x-access-token';
            $config['http.extraHeader'] = 'Authorization: Basic ' . base64_encode("$user:$token");
        }
        $env = [
            'PATH' => (string) (getenv('PATH') ?: '/usr/local/bin:/usr/bin:/bin'),
            'HOME' => $dir,                       // ni .gitconfig ni credenciales del usuario del servidor
            'GIT_CONFIG_NOSYSTEM' => '1',
            'GIT_TERMINAL_PROMPT' => '0',
            'GIT_ASKPASS' => 'echo',
            'GIT_LFS_SKIP_SMUDGE' => '1',
            'GIT_CONFIG_COUNT' => (string) count($config),
        ];
        $i = 0;
        foreach ($config as $k => $v) {
            $env["GIT_CONFIG_KEY_$i"] = $k;
            $env["GIT_CONFIG_VALUE_$i"] = $v;
            $i++;
        }
        [$code, $err] = $this->run($cmd, $env, (int) ($this->opts['git_timeout'] ?? 300));
        if ($code !== 0) {
            $err = $this->clean($err, $token);
            if (preg_match('/not found|Authentication failed|could not read Username|403|401|Repository not found/i', $err)) {
                throw new ScanException('errors.repo_access', ['repo' => $repo['path']]);
            }
            if (preg_match('/Remote branch .* not found|couldn\'t find remote ref/i', $err)) {
                throw new ScanException('errors.repo_branch', ['branch' => $branch]);
            }
            throw new ScanException('errors.repo_failed', ['error' => mb_substr($err, 0, 300)]);
        }
        if ($ws->size() > $ws->maxBytes()) {
            throw new ScanException('errors.repo_too_big');
        }
        [, $sha] = $this->run(['git', '-C', $dir . '/repo', 'rev-parse', '--short=10', 'HEAD'], $env, 20, true);
        [, $head] = $this->run(['git', '-C', $dir . '/repo', 'rev-parse', '--abbrev-ref', 'HEAD'], $env, 20, true);
        return [
            'dir' => $dir . '/repo',
            'all_tracked' => false,
            'meta' => ['repo' => $repo['host'] . '/' . $repo['path'], 'branch' => trim($head) ?: $branch, 'commit' => trim($sha), 'method' => 'git'],
        ];
    }

    // ------------------------------------------------------------------------------------------------ GitHub sin git

    private function githubZip(array $repo, string $branch, Workspace $ws): array
    {
        $file = $ws->emptyDir() . '/repo.zip';
        $fh = fopen($file, 'wb');
        $token = $this->token('github.com');
        $max = $ws->maxBytes();
        $written = 0;
        $ch = curl_init('https://api.github.com/repos/' . $repo['path'] . '/zipball' . ($branch !== '' ? '/' . rawurlencode($branch) : ''));
        curl_setopt_array($ch, [
            CURLOPT_FOLLOWLOCATION => true,       // a codeload.github.com (curl no reenvía Authorization a otro host)
            CURLOPT_MAXREDIRS => 3,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_TIMEOUT => (int) ($this->opts['git_timeout'] ?? 300),
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_USERAGENT => 'Stellar',
            CURLOPT_HTTPHEADER => array_merge(['Accept: application/vnd.github+json', 'X-GitHub-Api-Version: 2022-11-28'], $token !== null ? ["Authorization: Bearer $token"] : []),
            CURLOPT_WRITEFUNCTION => static function ($ch, string $chunk) use ($fh, &$written, $max): int {
                $written += strlen($chunk);
                return $written > $max ? 0 : (int) fwrite($fh, $chunk);
            },
        ]);
        $ok = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $error = curl_error($ch);
        fclose($fh);
        try {
            if ($written > $max) {
                throw new ScanException('errors.repo_too_big');
            }
            if ($status === 404 || $status === 401 || $status === 403) {
                throw new ScanException($branch !== '' && $status === 404 ? 'errors.repo_access_branch' : 'errors.repo_access', ['repo' => $repo['path'], 'branch' => $branch]);
            }
            if ($ok === false || $status !== 200) {
                throw new ScanException('errors.repo_failed', ['error' => $this->clean($error ?: "HTTP $status", $token)]);
            }
            $root = $ws->extract($file);
        } finally {
            @unlink($file);
        }
        // El zip de GitHub se llama propietario-repo-<commit>/
        $commit = preg_match('/-([0-9a-f]{7,40})$/', basename($root), $m) ? $m[1] : '';
        return [
            'dir' => $root,
            'all_tracked' => true,                // todo lo que trae el zip está en el repositorio
            'meta' => ['repo' => 'github.com/' . $repo['path'], 'branch' => $branch, 'commit' => $commit, 'method' => 'zip'],
        ];
    }

    // ------------------------------------------------------------------------------------------------ utilidades

    /** @return list<string> */
    private function hosts(): array
    {
        $hosts = array_merge(self::DEFAULT_HOSTS, (array) ($this->opts['git_hosts'] ?? []), array_keys((array) ($this->opts['git_tokens'] ?? [])));
        return array_values(array_unique(array_map('strtolower', array_map('strval', $hosts))));
    }

    private function token(string $host): ?string
    {
        $t = trim((string) (($this->opts['git_tokens'] ?? [])[$host] ?? ''));
        return $t !== '' ? $t : null;
    }

    private function hasGit(): bool
    {
        if (($this->opts['git_binary'] ?? true) === false || !function_exists('proc_open')) {
            return false;
        }
        [$code] = $this->run(['git', '--version'], ['PATH' => (string) (getenv('PATH') ?: '/usr/bin:/bin')], 10, true);
        return $code === 0;
    }

    /**
     * Ejecuta una orden sin shell (array), con entorno propio y tiempo máximo.
     * @return array{0:int,1:string} código de salida y stderr (o stdout con $stdout)
     */
    private function run(array $cmd, array $env, int $timeout, bool $stdout = false): array
    {
        $p = @proc_open($cmd, [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, null, $env);
        if (!is_resource($p)) {
            return [127, 'proc_open'];
        }
        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);
        $out = $err = '';
        $end = time() + $timeout;
        while (true) {
            $out .= (string) stream_get_contents($pipes[1]);
            $err .= (string) stream_get_contents($pipes[2]);
            $st = proc_get_status($p);
            if (!$st['running']) {
                $code = $st['exitcode'];
                break;
            }
            if (time() > $end) {
                proc_terminate($p, 9);
                $code = 124;
                $err .= "\ntimeout ($timeout s)";
                break;
            }
            usleep(100_000);
        }
        $out .= (string) stream_get_contents($pipes[1]);
        $err .= (string) stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        proc_close($p);
        return [(int) $code, $stdout ? $out : trim($err)];
    }

    private function clean(string $text, ?string $token): string
    {
        if ($token !== null) {
            $text = str_replace($token, '***', $text);
        }
        $text = (string) preg_replace('/Authorization:\s*\S+\s+\S+/i', 'Authorization: ***', $text);
        return Redactor::clean($text, 400);
    }
}

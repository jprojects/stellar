-- Stellar · tablas propias (las del núcleo están en schema.sql). Idempotente: lo ejecuta tools/stellar-migrate.php.

-- Qué se analiza: una web en producción o el código de una aplicación
CREATE TABLE IF NOT EXISTS targets (
  id             INT UNSIGNED NOT NULL AUTO_INCREMENT,
  name           VARCHAR(150) NOT NULL,
  kind           VARCHAR(10)  NOT NULL DEFAULT 'web',      -- web | code
  url            VARCHAR(500) NULL,                        -- web
  code_path      VARCHAR(500) NULL,                        -- código: carpeta del servidor (dentro de stellar.code_roots)
  code_zip       INT UNSIGNED NULL,                        -- código: id de media con un .zip
  authorized     TINYINT(1)   NOT NULL DEFAULT 0,          -- confirmación de que es nuestro o tenemos permiso
  owner          VARCHAR(150) NULL,                        -- cliente o responsable
  notes          TEXT         NULL,
  active         TINYINT(1)   NOT NULL DEFAULT 1,
  last_scan_id   INT UNSIGNED NULL,
  last_score     TINYINT UNSIGNED NULL,
  last_scan_at   DATETIME     NULL,
  created_at     DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at     DATETIME     NULL ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_targets_kind (kind)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Cada análisis de un objetivo
CREATE TABLE IF NOT EXISTS scans (
  id             INT UNSIGNED NOT NULL AUTO_INCREMENT,
  target_id      INT UNSIGNED NOT NULL,
  kind           VARCHAR(10)  NOT NULL,
  status         VARCHAR(10)  NOT NULL DEFAULT 'running',  -- running | done | failed
  score          TINYINT UNSIGNED NULL,
  critical       SMALLINT UNSIGNED NOT NULL DEFAULT 0,
  high           SMALLINT UNSIGNED NOT NULL DEFAULT 0,
  medium         SMALLINT UNSIGNED NOT NULL DEFAULT 0,
  low            SMALLINT UNSIGNED NOT NULL DEFAULT 0,
  info           SMALLINT UNSIGNED NOT NULL DEFAULT 0,
  new_count      SMALLINT UNSIGNED NOT NULL DEFAULT 0,     -- hallazgos que no estaban en el análisis anterior
  fixed_count    SMALLINT UNSIGNED NOT NULL DEFAULT 0,     -- los del anterior que ya no aparecen
  requests       INT UNSIGNED NOT NULL DEFAULT 0,
  duration       INT UNSIGNED NULL,                        -- segundos
  error          VARCHAR(500) NULL,
  notes          JSON         NULL,                        -- lo que no se ha podido comprobar
  meta           JSON         NULL,                        -- servidor, CMS, TLS, librerías, ficheros…
  locale         VARCHAR(5)   NOT NULL DEFAULT 'ca',
  user_id        INT UNSIGNED NULL,
  started_at     DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  finished_at    DATETIME     NULL,
  PRIMARY KEY (id),
  KEY idx_scans_target (target_id, id),
  CONSTRAINT fk_scans_target FOREIGN KEY (target_id) REFERENCES targets (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Hallazgos de cada análisis (los textos, en el idioma de quien lo lanzó)
CREATE TABLE IF NOT EXISTS findings (
  id             INT UNSIGNED NOT NULL AUTO_INCREMENT,
  scan_id        INT UNSIGNED NOT NULL,
  target_id      INT UNSIGNED NOT NULL,
  check_id       VARCHAR(60)  NOT NULL,
  category       VARCHAR(20)  NOT NULL,                    -- web | code
  severity       VARCHAR(10)  NOT NULL,                    -- critical | high | medium | low | info
  title          VARCHAR(255) NOT NULL,
  detail         TEXT         NULL,
  fix            TEXT         NULL,
  location       VARCHAR(700) NULL,
  evidence       TEXT         NULL,
  cwe            VARCHAR(20)  NULL,
  fingerprint    CHAR(40)     NOT NULL,
  status         VARCHAR(15)  NOT NULL DEFAULT 'open',     -- open | fixed | accepted | false_positive
  is_new         TINYINT(1)   NOT NULL DEFAULT 0,
  comment        TEXT         NULL,
  created_at     DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at     DATETIME     NULL ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_findings_scan (scan_id, severity),
  KEY idx_findings_target (target_id, fingerprint),
  CONSTRAINT fk_findings_scan FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

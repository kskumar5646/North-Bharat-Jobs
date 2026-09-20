PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS sources (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  role TEXT NOT NULL CHECK(role IN ('official','portal')),
  fallback_key TEXT,
  base_url TEXT NOT NULL,
  allowed_domains TEXT NOT NULL,
  adapter TEXT NOT NULL DEFAULT 'generic',
  enabled INTEGER NOT NULL DEFAULT 1,
  priority INTEGER NOT NULL DEFAULT 50,
  retry_day TEXT,
  retry_count INTEGER NOT NULL DEFAULT 0,
  next_retry_at TEXT,
  circuit_until TEXT,
  last_checked_at TEXT,
  last_success_at TEXT,
  last_error TEXT,
  last_error_code INTEGER,
  last_error_type TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  slug TEXT NOT NULL UNIQUE,
  notification_key TEXT,
  type TEXT NOT NULL,
  title TEXT NOT NULL,
  organization TEXT,
  category TEXT,
  location TEXT,
  description TEXT,
  eligibility TEXT,
  qualification TEXT,
  vacancies TEXT,
  age_limit TEXT,
  age_relaxation TEXT,
  fee TEXT,
  selection_process TEXT,
  salary TEXT,
  application_start TEXT,
  last_date TEXT,
  exam_date TEXT,
  how_to_apply TEXT,
  important_dates TEXT,
  official_url TEXT,
  apply_url TEXT,
  notification_url TEXT,
  source_url TEXT NOT NULL,
  source_name TEXT NOT NULL,
  source_id INTEGER,
  source_hash TEXT,
  canonical_url TEXT,
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','published','verification_required','rejected','archived')),
  verification_status TEXT NOT NULL DEFAULT 'unverified',
  confidence_score INTEGER NOT NULL DEFAULT 0,
  evidence_json TEXT,
  change_summary TEXT,
  last_verified_at TEXT,
  last_seen_at TEXT,
  published_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  archived_at TEXT,
  archive_reason TEXT,
  FOREIGN KEY(source_id) REFERENCES sources(id)
);

CREATE TABLE IF NOT EXISTS item_revisions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  item_id INTEGER NOT NULL,
  revision_no INTEGER NOT NULL,
  changed_fields_json TEXT NOT NULL,
  snapshot_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(item_id) REFERENCES items(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS verification_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  item_id INTEGER,
  source_id INTEGER,
  event_type TEXT NOT NULL,
  severity TEXT NOT NULL DEFAULT 'info',
  message TEXT NOT NULL,
  evidence_json TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(item_id) REFERENCES items(id) ON DELETE SET NULL,
  FOREIGN KEY(source_id) REFERENCES sources(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS monitor_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  source_count INTEGER NOT NULL DEFAULT 0,
  discovered INTEGER NOT NULL DEFAULT 0,
  published INTEGER NOT NULL DEFAULT 0,
  updated INTEGER NOT NULL DEFAULT 0,
  verification_required INTEGER NOT NULL DEFAULT 0,
  blocked INTEGER NOT NULL DEFAULT 0,
  errors INTEGER NOT NULL DEFAULT 0,
  archived INTEGER NOT NULL DEFAULT 0,
  details TEXT
);

CREATE TABLE IF NOT EXISTS notifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL,
  title TEXT NOT NULL,
  message TEXT NOT NULL,
  item_id INTEGER,
  read_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(item_id) REFERENCES items(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS admins (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_login_at TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  token_hash TEXT NOT NULL UNIQUE,
  admin_id INTEGER NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(admin_id) REFERENCES admins(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  admin_id INTEGER,
  action TEXT NOT NULL,
  target_type TEXT,
  target_id TEXT,
  metadata_json TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(admin_id) REFERENCES admins(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_items_public ON items(status, type, published_at DESC);
CREATE INDEX IF NOT EXISTS idx_items_last_date ON items(last_date);
CREATE INDEX IF NOT EXISTS idx_items_notification_key ON items(notification_key);
CREATE INDEX IF NOT EXISTS idx_items_canonical ON items(canonical_url);
CREATE INDEX IF NOT EXISTS idx_sources_due ON sources(enabled, role, next_retry_at, priority);
CREATE INDEX IF NOT EXISTS idx_events_created ON verification_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at DESC);

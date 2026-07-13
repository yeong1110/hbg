PRAGMA foreign_keys = ON;

CREATE TABLE cases (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_number TEXT NOT NULL UNIQUE,
  access_token_hash TEXT NOT NULL UNIQUE,
  submission_request_id TEXT NOT NULL UNIQUE,
  submitter_hash TEXT NOT NULL,
  content_fingerprint TEXT NOT NULL,
  title TEXT NOT NULL CHECK(length(title) BETWEEN 3 AND 80),
  reproduction_steps TEXT NOT NULL CHECK(length(reproduction_steps) BETWEEN 5 AND 1000),
  expected_result TEXT NOT NULL CHECK(length(expected_result) BETWEEN 2 AND 500),
  actual_result TEXT NOT NULL CHECK(length(actual_result) BETWEEN 2 AND 500),
  environment TEXT NOT NULL DEFAULT '' CHECK(length(environment) <= 120),
  severity TEXT CHECK(severity IN ('minor','annoying','serious','critical')),
  evidence_emoji TEXT,
  category TEXT CHECK(category IN ('communication','habit','work','relationship','body_mind','society','other')),
  public_review_consent INTEGER NOT NULL CHECK(public_review_consent = 1),
  consented_at TEXT NOT NULL,
  moderation_status TEXT NOT NULL DEFAULT 'pending' CHECK(moderation_status IN ('pending','approved','rejected')),
  visibility_status TEXT NOT NULL DEFAULT 'pending' CHECK(visibility_status IN ('pending','public','hidden')),
  lifecycle_status TEXT NOT NULL DEFAULT 'open' CHECK(lifecycle_status IN ('open','reviewing','closed')),
  resolution_code TEXT CHECK(resolution_code IN ('PATCHED','KNOWN_ISSUE','WORKS_AS_DESIGNED','WONT_FIX','CANNOT_REPRODUCE','USER_ERROR','ESCALATED_TO_UNIVERSE','DUPLICATE')),
  official_comment TEXT,
  moderation_note TEXT,
  duplicate_of_case_id INTEGER REFERENCES cases(id),
  reproduction_count INTEGER NOT NULL DEFAULT 0 CHECK(reproduction_count >= 0),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  published_at TEXT,
  resolved_at TEXT,
  CHECK((lifecycle_status = 'closed' AND resolution_code IS NOT NULL) OR (lifecycle_status <> 'closed' AND resolution_code IS NULL)),
  CHECK((moderation_status = 'pending' AND visibility_status = 'pending') OR (moderation_status = 'approved' AND visibility_status IN ('public','hidden')) OR (moderation_status = 'rejected' AND visibility_status = 'hidden'))
);

CREATE TABLE case_analyses (
  case_id INTEGER PRIMARY KEY REFERENCES cases(id) ON DELETE CASCADE,
  engine_version TEXT NOT NULL,
  department TEXT NOT NULL,
  initial_grade TEXT NOT NULL,
  workaround TEXT NOT NULL,
  expected_version TEXT NOT NULL,
  bureaucracy_waste_index INTEGER NOT NULL CHECK(bureaucracy_waste_index BETWEEN 0 AND 100),
  created_at TEXT NOT NULL
);

CREATE TABLE reproduction_reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  visitor_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE(case_id, visitor_hash)
);

CREATE TABLE timeline_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  event_type TEXT NOT NULL,
  event_key TEXT NOT NULL,
  is_public INTEGER NOT NULL DEFAULT 1,
  actor_type TEXT NOT NULL CHECK(actor_type IN ('system','admin')),
  metadata_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  UNIQUE(case_id, event_key)
);

CREATE TABLE patch_notes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  slug TEXT NOT NULL UNIQUE,
  title TEXT NOT NULL,
  introduction TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','published','hidden')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  published_at TEXT
);

CREATE TABLE patch_note_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  patch_note_id INTEGER NOT NULL REFERENCES patch_notes(id) ON DELETE CASCADE,
  case_id INTEGER NOT NULL UNIQUE REFERENCES cases(id) ON DELETE RESTRICT,
  section_code TEXT NOT NULL CHECK(section_code IN ('PATCHED','KNOWN_ISSUE','WORKS_AS_DESIGNED','WONT_FIX','CANNOT_REPRODUCE','ESCALATED_TO_UNIVERSE')),
  title_snapshot TEXT NOT NULL,
  editorial_note TEXT NOT NULL DEFAULT '',
  display_order INTEGER NOT NULL DEFAULT 0,
  UNIQUE(patch_note_id, section_code, display_order)
);

CREATE TABLE og_assets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id INTEGER UNIQUE REFERENCES cases(id) ON DELETE CASCADE,
  patch_note_id INTEGER UNIQUE REFERENCES patch_notes(id) ON DELETE CASCADE,
  mime_type TEXT NOT NULL CHECK(mime_type = 'image/jpeg'),
  byte_size INTEGER NOT NULL CHECK(byte_size BETWEEN 100 AND 350000),
  sha256 TEXT NOT NULL,
  data BLOB NOT NULL,
  created_at TEXT NOT NULL,
  CHECK((case_id IS NOT NULL AND patch_note_id IS NULL) OR (case_id IS NULL AND patch_note_id IS NOT NULL))
);

CREATE TABLE admin_audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  admin_actor_hash TEXT NOT NULL,
  action TEXT NOT NULL,
  target_type TEXT NOT NULL,
  target_id TEXT NOT NULL,
  state_json TEXT NOT NULL DEFAULT '{}',
  request_id TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX idx_cases_submitter_created ON cases(submitter_hash, created_at DESC);
CREATE INDEX idx_cases_fingerprint ON cases(submitter_hash, content_fingerprint, created_at DESC);
CREATE INDEX idx_cases_public ON cases(visibility_status, published_at DESC, id DESC);
CREATE INDEX idx_cases_lifecycle ON cases(visibility_status, lifecycle_status, published_at DESC);
CREATE INDEX idx_cases_resolution ON cases(visibility_status, resolution_code, published_at DESC);
CREATE INDEX idx_cases_moderation ON cases(moderation_status, created_at, id);
CREATE INDEX idx_reproduction_visitor_created ON reproduction_reports(visitor_hash, created_at DESC);
CREATE INDEX idx_timeline_case_created ON timeline_events(case_id, created_at, id);
CREATE INDEX idx_patch_status_published ON patch_notes(status, published_at DESC, id DESC);
CREATE INDEX idx_patch_items_order ON patch_note_items(patch_note_id, section_code, display_order);
CREATE INDEX idx_audit_created ON admin_audit_logs(created_at DESC, id DESC);

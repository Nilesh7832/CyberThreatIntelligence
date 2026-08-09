-- =============================================
-- Cyber Threat Intelligence Framework
-- Complete Database Schema
-- =============================================

-- 1. USERS TABLE
CREATE TABLE IF NOT EXISTS users (
                                     id          INTEGER PRIMARY KEY AUTOINCREMENT,
                                     username    TEXT    NOT NULL UNIQUE,
                                     email       TEXT    NOT NULL,
                                     role        TEXT    NOT NULL DEFAULT 'USER',
                                     created_at  TEXT    NOT NULL
);

-- 2. LOGIN LOGS TABLE
CREATE TABLE IF NOT EXISTS login_logs (
                                          id              INTEGER PRIMARY KEY AUTOINCREMENT,
                                          username        TEXT    NOT NULL,
                                          ip_address      TEXT    NOT NULL,
                                          login_time      TEXT    NOT NULL,
                                          success         INTEGER NOT NULL DEFAULT 0,
                                          failure_reason  TEXT,
                                          location        TEXT
);

-- 3. THREAT ALERTS TABLE
CREATE TABLE IF NOT EXISTS threat_alerts (
                                             id            INTEGER PRIMARY KEY AUTOINCREMENT,
                                             threat_type   TEXT    NOT NULL,
                                             source_ip     TEXT    NOT NULL,
                                             target_system TEXT,
                                             severity      TEXT    NOT NULL,
                                             detected_at   TEXT    NOT NULL,
                                             status        TEXT    NOT NULL DEFAULT 'OPEN',
                                             risk_score    REAL    NOT NULL DEFAULT 0.0
);

-- 4. RISK SCORES TABLE
CREATE TABLE IF NOT EXISTS risk_scores (
                                           id             INTEGER PRIMARY KEY AUTOINCREMENT,
                                           ip_address     TEXT    NOT NULL,
                                           total_score    REAL    NOT NULL,
                                           risk_level     TEXT    NOT NULL,
                                           fail_count     INTEGER NOT NULL DEFAULT 0,
                                           geo_risk       REAL    NOT NULL DEFAULT 0.0,
                                           time_risk      REAL    NOT NULL DEFAULT 0.0,
                                           speed_risk     REAL    NOT NULL DEFAULT 0.0,
                                           ml_prediction  TEXT,
                                           calculated_at  TEXT    NOT NULL
);

-- 5. AUDIT LOGS TABLE
CREATE TABLE IF NOT EXISTS audit_logs (
                                          id          INTEGER PRIMARY KEY AUTOINCREMENT,
                                          timestamp   TEXT    NOT NULL,
                                          actor       TEXT    NOT NULL,
                                          action      TEXT    NOT NULL,
                                          target      TEXT,
                                          details     TEXT,
                                          severity    TEXT    NOT NULL DEFAULT 'INFO'
);

-- 6. IP BLACKLIST TABLE
CREATE TABLE IF NOT EXISTS ip_blacklist (
                                            id          INTEGER PRIMARY KEY AUTOINCREMENT,
                                            ip_address  TEXT    NOT NULL UNIQUE,
                                            reason      TEXT    NOT NULL,
                                            blocked_at  TEXT    NOT NULL,
                                            blocked_by  TEXT    NOT NULL DEFAULT 'SYSTEM',
                                            is_active   INTEGER NOT NULL DEFAULT 1
);

-- ── Indexes for fast queries ──────────────────
CREATE INDEX IF NOT EXISTS idx_login_ip
    ON login_logs(ip_address);

CREATE INDEX IF NOT EXISTS idx_login_time
    ON login_logs(login_time);

CREATE INDEX IF NOT EXISTS idx_threat_severity
    ON threat_alerts(severity);

CREATE INDEX IF NOT EXISTS idx_threat_status
    ON threat_alerts(status);

CREATE INDEX IF NOT EXISTS idx_risk_ip
    ON risk_scores(ip_address);

CREATE INDEX IF NOT EXISTS idx_audit_actor
    ON audit_logs(actor);

CREATE INDEX IF NOT EXISTS idx_blacklist_ip
    ON ip_blacklist(ip_address);
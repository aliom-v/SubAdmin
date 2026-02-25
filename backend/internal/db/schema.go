package db

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

func Open(path string) (*sql.DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create db dir: %w", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	db.SetMaxOpenConns(1)
	db.SetConnMaxLifetime(5 * time.Minute)

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}
	return db, nil
}

func Init(ctx context.Context, db *sql.DB, defaultAdmin, defaultPassword string, defaultCacheMode bool, defaultCacheInterval int) error {
	schema := []string{
		`PRAGMA journal_mode=WAL;`,
		`CREATE TABLE IF NOT EXISTS admins (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS upstreams (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			url TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1,
			refresh_interval INTEGER NOT NULL DEFAULT 60,
			last_sync_at DATETIME,
			last_status TEXT NOT NULL DEFAULT '',
			cached_content TEXT NOT NULL DEFAULT '',
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS manual_nodes (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			raw_uri TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1,
			group_name TEXT NOT NULL DEFAULT 'default',
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS settings (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS snapshots (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			kind TEXT NOT NULL,
			content TEXT NOT NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			note TEXT NOT NULL DEFAULT ''
		);`,
		`CREATE TABLE IF NOT EXISTS sync_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			upstream_id INTEGER NOT NULL DEFAULT 0,
			upstream_name TEXT NOT NULL DEFAULT '',
			trigger_source TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'info',
			node_count INTEGER NOT NULL DEFAULT 0,
			duration_ms INTEGER NOT NULL DEFAULT 0,
			detail TEXT NOT NULL DEFAULT '',
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE INDEX IF NOT EXISTS idx_sync_logs_created_at ON sync_logs(created_at DESC);`,
		`CREATE TABLE IF NOT EXISTS system_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			level TEXT NOT NULL DEFAULT 'info',
			category TEXT NOT NULL DEFAULT 'system',
			action TEXT NOT NULL DEFAULT '',
			detail TEXT NOT NULL DEFAULT '',
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE INDEX IF NOT EXISTS idx_system_logs_created_at ON system_logs(created_at DESC);`,
		`CREATE TABLE IF NOT EXISTS auth_tokens (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			token_id TEXT NOT NULL UNIQUE,
			admin_id INTEGER NOT NULL,
			name TEXT NOT NULL DEFAULT '',
			scope TEXT NOT NULL DEFAULT 'full',
			enabled INTEGER NOT NULL DEFAULT 1,
			last_used_at DATETIME,
			expires_at DATETIME NOT NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE INDEX IF NOT EXISTS idx_auth_tokens_admin_id ON auth_tokens(admin_id);`,
		`CREATE INDEX IF NOT EXISTS idx_auth_tokens_expires_at ON auth_tokens(expires_at);`,
	}

	for _, stmt := range schema {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("execute schema: %w", err)
		}
	}

	if err := ensureAdmin(ctx, db, defaultAdmin, defaultPassword); err != nil {
		return err
	}

	if err := ensureSetting(ctx, db, "cache_mode", strconv.FormatBool(defaultCacheMode)); err != nil {
		return err
	}
	if err := ensureSetting(ctx, db, "cache_interval", strconv.Itoa(defaultCacheInterval)); err != nil {
		return err
	}
	if err := ensureSetting(ctx, db, "output_template", "default"); err != nil {
		return err
	}
	if err := ensureSetting(ctx, db, "auto_backup_enabled", "false"); err != nil {
		return err
	}
	if err := ensureSetting(ctx, db, "auto_backup_interval_hours", "24"); err != nil {
		return err
	}
	if err := ensureSetting(ctx, db, "auto_backup_keep", "7"); err != nil {
		return err
	}
	if err := ensureSetting(ctx, db, "auto_backup_last_at", ""); err != nil {
		return err
	}
	return nil
}

func ensureAdmin(ctx context.Context, db *sql.DB, username, password string) error {
	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(1) FROM admins`).Scan(&count); err != nil {
		return fmt.Errorf("check admin exists: %w", err)
	}
	if count > 0 {
		return nil
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash default password: %w", err)
	}

	if _, err := db.ExecContext(
		ctx,
		`INSERT INTO admins(username, password_hash, created_at) VALUES(?, ?, CURRENT_TIMESTAMP)`,
		username,
		string(hash),
	); err != nil {
		return fmt.Errorf("insert default admin: %w", err)
	}
	return nil
}

func ensureSetting(ctx context.Context, db *sql.DB, key, value string) error {
	if _, err := db.ExecContext(ctx, `INSERT OR IGNORE INTO settings(key, value) VALUES(?, ?)`, key, value); err != nil {
		return fmt.Errorf("insert setting %s: %w", key, err)
	}
	return nil
}

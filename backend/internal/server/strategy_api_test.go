package server

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"subadmin/backend/internal/config"
	backenddb "subadmin/backend/internal/db"
	"subadmin/backend/internal/sublink"
)

type strategyAPITestEnv struct {
	db            *sql.DB
	server        *Server
	apiServer     *httptest.Server
	sublinkServer *httptest.Server
	token         string
}

func newStrategyAPITestEnv(t *testing.T, cacheMode bool) *strategyAPITestEnv {
	t.Helper()

	fakeSublink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sub" {
			http.NotFound(w, r)
			return
		}
		target := strings.TrimSpace(r.URL.Query().Get("target"))
		sourceURL := strings.TrimSpace(r.URL.Query().Get("url"))
		if target == "" || sourceURL == "" {
			http.Error(w, "missing target or url", http.StatusBadRequest)
			return
		}
		_, _ = io.WriteString(w, "converted-"+target)
	}))

	rootDir := t.TempDir()
	cfg := &config.Config{
		ListenAddr:             ":0",
		DataDir:                rootDir,
		DBPath:                 filepath.Join(rootDir, "subadmin.db"),
		CacheDir:               filepath.Join(rootDir, "cache"),
		JWTSecret:              "test-secret-1234567890",
		TokenTTL:               24 * time.Hour,
		AuthCookieName:         "subadmin_token",
		AuthCookieSameSite:     "lax",
		LoginProtectionEnabled: false,
		OutputETagEnabled:      true,
		OutputCacheControl:     "no-cache",
		SyncMaxConcurrency:     1,
		SyncRetryMaxAttempts:   1,
		SyncRetryBaseDelay:     time.Millisecond,
		SyncRetryMaxDelay:      time.Millisecond,
		AdminUsername:          "admin",
		AdminPassword:          "admin123",
		SublinkURL:             fakeSublink.URL,
		SublinkSourceBaseURL:   "http://127.0.0.1",
		APITimeout:             5 * time.Second,
		HTTPTimeout:            2 * time.Second,
		DefaultCacheMode:       cacheMode,
		DefaultCacheInterval:   10,
		SchedulerTickInterval:  time.Hour,
		SchedulerJobTimeout:    time.Minute,
	}

	database, err := backenddb.Open(cfg.DBPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := backenddb.Init(context.Background(), database, cfg.AdminUsername, cfg.AdminPassword, cfg.DefaultCacheMode, cfg.DefaultCacheInterval); err != nil {
		t.Fatalf("init db: %v", err)
	}

	s, err := New(cfg, database, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	s.sublink = sublink.New(fakeSublink.URL, cfg.HTTPTimeout)

	apiServer := httptest.NewServer(s.Handler())
	s.cfg.SublinkSourceBaseURL = apiServer.URL

	env := &strategyAPITestEnv{
		db:            database,
		server:        s,
		apiServer:     apiServer,
		sublinkServer: fakeSublink,
	}
	env.token = env.login(t)

	t.Cleanup(func() {
		apiServer.Close()
		fakeSublink.Close()
		_ = database.Close()
	})

	return env
}

func (e *strategyAPITestEnv) login(t *testing.T) string {
	t.Helper()
	resp, body := e.request(t, http.MethodPost, "/api/login", "", map[string]any{
		"username": "admin",
		"password": "admin123",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d, body = %s", resp.StatusCode, string(body))
	}
	var payload struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	if payload.Token == "" {
		t.Fatalf("login token is empty")
	}
	return payload.Token
}

func (e *strategyAPITestEnv) request(t *testing.T, method, path, token string, body any) (*http.Response, []byte) {
	t.Helper()

	var reader io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal request body: %v", err)
		}
		reader = bytes.NewReader(payload)
	}

	req, err := http.NewRequest(method, e.apiServer.URL+path, reader)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request %s %s: %v", method, path, err)
	}
	data, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	return resp, data
}

func (e *strategyAPITestEnv) insertUpstream(t *testing.T, name, cachedContent string) int {
	t.Helper()
	result, err := e.db.ExecContext(
		context.Background(),
		`INSERT INTO upstreams(name, url, enabled, refresh_interval, last_status, cached_content, created_at) VALUES(?, ?, 1, 60, ?, ?, CURRENT_TIMESTAMP)`,
		name,
		"http://example.com/sub",
		"manual raw import",
		cachedContent,
	)
	if err != nil {
		t.Fatalf("insert upstream: %v", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read upstream id: %v", err)
	}
	return int(id)
}

func (e *strategyAPITestEnv) insertManualNode(t *testing.T, name, rawURI string) int {
	t.Helper()
	result, err := e.db.ExecContext(
		context.Background(),
		`INSERT INTO manual_nodes(name, raw_uri, enabled, group_name, created_at, updated_at) VALUES(?, ?, 1, 'default', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
		name,
		rawURI,
	)
	if err != nil {
		t.Fatalf("insert manual node: %v", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read manual node id: %v", err)
	}
	return int(id)
}

func (e *strategyAPITestEnv) metrics(t *testing.T) string {
	t.Helper()
	resp, body := e.request(t, http.MethodGet, "/metrics", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("metrics status = %d, body = %s", resp.StatusCode, string(body))
	}
	return string(body)
}

func (e *strategyAPITestEnv) snapshotCount(t *testing.T, kind string) int {
	t.Helper()
	var count int
	if err := e.db.QueryRowContext(context.Background(), `SELECT COUNT(1) FROM snapshots WHERE kind = ?`, kind).Scan(&count); err != nil {
		t.Fatalf("count snapshots: %v", err)
	}
	return count
}

func TestStrategyAPIGetDefaultConfig(t *testing.T) {
	env := newStrategyAPITestEnv(t, false)
	upstreamID := env.insertUpstream(t, "airport-a", "ss://YWVzLTI1Ni1nY206cGFzc0BleGFtcGxlLmNvbTo0NDM=#JP-01")

	resp, body := env.request(t, http.MethodGet, "/api/strategy", env.token, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get strategy status = %d, body = %s", resp.StatusCode, string(body))
	}

	var config StrategyConfig
	if err := json.Unmarshal(body, &config); err != nil {
		t.Fatalf("decode get strategy response: %v", err)
	}
	if config.StrategyMode != strategyModeMergeDedupe {
		t.Fatalf("strategy mode = %s, want %s", config.StrategyMode, strategyModeMergeDedupe)
	}
	if config.ManualNodesPriority != defaultManualNodesPriority {
		t.Fatalf("manual nodes priority = %d, want %d", config.ManualNodesPriority, defaultManualNodesPriority)
	}
	if config.RenameSuffixFormat != defaultStrategyRenameSuffix {
		t.Fatalf("rename suffix = %s, want %s", config.RenameSuffixFormat, defaultStrategyRenameSuffix)
	}
	if len(config.Upstreams) != 1 {
		t.Fatalf("upstreams len = %d, want 1", len(config.Upstreams))
	}
	if config.Upstreams[0].ID != upstreamID {
		t.Fatalf("upstream id = %d, want %d", config.Upstreams[0].ID, upstreamID)
	}
	if config.Upstreams[0].Priority != defaultUpstreamPriority(0) {
		t.Fatalf("upstream priority = %d, want %d", config.Upstreams[0].Priority, defaultUpstreamPriority(0))
	}
}

func TestStrategyAPIRejectsInvalidMode(t *testing.T) {
	env := newStrategyAPITestEnv(t, false)
	resp, body := env.request(t, http.MethodPut, "/api/strategy", env.token, map[string]any{
		"strategy_mode": "not-a-valid-mode",
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("put invalid strategy status = %d, body = %s", resp.StatusCode, string(body))
	}
	if !strings.Contains(string(body), "invalid strategy_mode") {
		t.Fatalf("unexpected error body: %s", string(body))
	}
}

func TestStrategyAPIPersistsUpdateAndRecordsMetrics(t *testing.T) {
	env := newStrategyAPITestEnv(t, false)
	upstreamID := env.insertUpstream(t, "airport-a", "vless://uuid@example.com:443?encryption=none#SG-01")
	env.insertManualNode(t, "manual-sg", "trojan://password@example.net:443#SG-01")

	payload := map[string]any{
		"strategy_mode":          strategyModePriorityOverride,
		"manual_nodes_priority":  0,
		"rename_suffix_format":   defaultStrategyRenameSuffix,
		"upstreams": []map[string]any{{
			"id":       upstreamID,
			"priority": 10,
		}},
	}

	resp, body := env.request(t, http.MethodPost, "/api/strategy/preview", env.token, payload)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("preview strategy status = %d, body = %s", resp.StatusCode, string(body))
	}
	var preview StrategyPreview
	if err := json.Unmarshal(body, &preview); err != nil {
		t.Fatalf("decode preview response: %v", err)
	}
	if preview.Summary.DroppedNodes != 1 {
		t.Fatalf("preview dropped nodes = %d, want 1", preview.Summary.DroppedNodes)
	}
	if len(preview.Conflicts) != 1 || preview.Conflicts[0].WinnerSource != defaultManualStrategySourceName {
		t.Fatalf("preview conflicts = %#v, want winner %s", preview.Conflicts, defaultManualStrategySourceName)
	}

	resp, body = env.request(t, http.MethodPut, "/api/strategy", env.token, payload)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("put strategy status = %d, body = %s", resp.StatusCode, string(body))
	}

	resp, body = env.request(t, http.MethodGet, "/api/strategy", env.token, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get updated strategy status = %d, body = %s", resp.StatusCode, string(body))
	}
	var config StrategyConfig
	if err := json.Unmarshal(body, &config); err != nil {
		t.Fatalf("decode updated strategy response: %v", err)
	}
	if config.StrategyMode != strategyModePriorityOverride {
		t.Fatalf("strategy mode = %s, want %s", config.StrategyMode, strategyModePriorityOverride)
	}
	if len(config.Upstreams) != 1 || config.Upstreams[0].Priority != 10 {
		t.Fatalf("updated upstream priorities = %#v, want priority 10", config.Upstreams)
	}

	metrics := env.metrics(t)
	for _, line := range []string{
		`subadmin_strategy_preview_total{strategy_mode="priority_override"} 1`,
		`subadmin_strategy_apply_total{strategy_mode="priority_override"} 1`,
		`subadmin_strategy_conflicts_total{operation="preview",strategy_mode="priority_override"} 1`,
		`subadmin_strategy_conflicts_total{operation="apply",strategy_mode="priority_override"} 1`,
		`subadmin_strategy_dropped_nodes_total{operation="preview",strategy_mode="priority_override"} 1`,
		`subadmin_strategy_dropped_nodes_total{operation="apply",strategy_mode="priority_override"} 1`,
	} {
		if !strings.Contains(metrics, line) {
			t.Fatalf("metrics missing line %q\nmetrics:\n%s", line, metrics)
		}
	}
}

func TestStrategyAPIUpdateRefreshesCacheInCacheMode(t *testing.T) {
	env := newStrategyAPITestEnv(t, true)
	upstreamID := env.insertUpstream(t, "airport-a", "ss://YWVzLTI1Ni1nY206cGFzc0BleGFtcGxlLmNvbTo0NDM=#JP-01")

	resp, body := env.request(t, http.MethodPut, "/api/strategy", env.token, map[string]any{
		"strategy_mode": strategyModeMergeDedupe,
		"upstreams": []map[string]any{{
			"id":       upstreamID,
			"priority": 10,
		}},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("put strategy in cache mode status = %d, body = %s", resp.StatusCode, string(body))
	}

	clashCache, err := env.server.readCache("clash")
	if err != nil {
		t.Fatalf("read clash cache: %v", err)
	}
	if clashCache != "converted-clash" {
		t.Fatalf("clash cache = %q, want %q", clashCache, "converted-clash")
	}

	singboxCache, err := env.server.readCache("singbox")
	if err != nil {
		t.Fatalf("read singbox cache: %v", err)
	}
	if singboxCache != "converted-singbox" {
		t.Fatalf("singbox cache = %q, want %q", singboxCache, "converted-singbox")
	}

	if got := env.snapshotCount(t, "clash"); got != 1 {
		t.Fatalf("clash snapshot count = %d, want 1", got)
	}
	if got := env.snapshotCount(t, "singbox"); got != 1 {
		t.Fatalf("singbox snapshot count = %d, want 1", got)
	}

	metrics := env.metrics(t)
	if !strings.Contains(metrics, fmt.Sprintf(`subadmin_strategy_apply_total{strategy_mode="%s"} 1`, strategyModeMergeDedupe)) {
		t.Fatalf("metrics missing apply total for cache mode update\nmetrics:\n%s", metrics)
	}
}

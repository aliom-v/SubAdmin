package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"subadmin/backend/internal/config"
	"subadmin/backend/internal/sublink"
)

type contextKey string

const (
	contextKeyAdmin           contextKey = "admin"
	defaultLogLimit                      = 100
	maxLogLimit                          = 500
	maxRawContentBytes                   = 2 * 1024 * 1024
	maxRawPreviewNodes                   = 30
	defaultAutoBackupHours               = 24
	defaultAutoBackupKeep                = 7
	defaultTokenTTLHours                 = 24 * 30
	sublinkSourceTTL                     = 2 * time.Minute
	maxSublinkSourceBytes                = 8 * 1024 * 1024
	defaultAuthCookieName                = "subadmin_token"
	defaultLoginRateWindow               = 1 * time.Minute
	defaultLoginRateMaxIP                = 30
	defaultLoginRateMaxUser              = 10
	defaultLoginLockThreshold            = 5
	defaultLoginLockDuration             = 5 * time.Minute
	defaultOutputCacheControl            = "no-cache"
	defaultSyncMaxConcurrency            = 3
	defaultSyncRetryAttempts             = 3
	defaultSyncRetryBaseDelay            = 500 * time.Millisecond
	defaultSyncRetryMaxDelay             = 5 * time.Second
)

type sublinkSourceEntry struct {
	content   string
	expiresAt time.Time
}

type loginAttemptWindow struct {
	windowStart time.Time
	count       int
}

type syncJobResult struct {
	id  int
	err error
}

type upstreamHTTPStatusError struct {
	StatusCode int
}

func (e *upstreamHTTPStatusError) Error() string {
	return fmt.Sprintf("upstream status %d", e.StatusCode)
}

type retryableSyncError struct {
	err error
}

func (e *retryableSyncError) Error() string {
	return e.err.Error()
}

func (e *retryableSyncError) Unwrap() error {
	return e.err
}

type AdminClaims struct {
	UserID   int    `json:"uid"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

type AdminInfo struct {
	ID        int    `json:"id"`
	Username  string `json:"username"`
	TokenID   string `json:"token_id,omitempty"`
	TokenName string `json:"token_name,omitempty"`
}

type Upstream struct {
	ID              int        `json:"id"`
	Name            string     `json:"name"`
	URL             string     `json:"url"`
	Enabled         bool       `json:"enabled"`
	RefreshInterval int        `json:"refresh_interval"`
	LastSyncAt      *time.Time `json:"last_sync_at,omitempty"`
	LastStatus      string     `json:"last_status"`
	CreatedAt       time.Time  `json:"created_at"`
}

type ManualNode struct {
	ID        int       `json:"id"`
	Name      string    `json:"name"`
	RawURI    string    `json:"raw_uri"`
	Enabled   bool      `json:"enabled"`
	GroupName string    `json:"group_name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Settings struct {
	CacheMode               bool   `json:"cache_mode"`
	CacheInterval           int    `json:"cache_interval"`
	OutputTemplate          string `json:"output_template"`
	AutoBackupEnabled       bool   `json:"auto_backup_enabled"`
	AutoBackupIntervalHours int    `json:"auto_backup_interval_hours"`
	AutoBackupKeep          int    `json:"auto_backup_keep"`
}

type BackupPayload struct {
	Admins      []BackupAdmin     `json:"admins"`
	AuthTokens  []BackupAuthToken `json:"auth_tokens"`
	Upstreams   []BackupUpstream  `json:"upstreams"`
	ManualNodes []BackupNode      `json:"manual_nodes"`
	Settings    []BackupSetting   `json:"settings"`
	Snapshots   []BackupSnapshot  `json:"snapshots"`
}

type BackupAdmin struct {
	ID           int       `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"password_hash"`
	CreatedAt    time.Time `json:"created_at"`
}

type BackupUpstream struct {
	ID              int        `json:"id"`
	Name            string     `json:"name"`
	URL             string     `json:"url"`
	Enabled         bool       `json:"enabled"`
	RefreshInterval int        `json:"refresh_interval"`
	LastSyncAt      *time.Time `json:"last_sync_at,omitempty"`
	LastStatus      string     `json:"last_status"`
	CachedContent   string     `json:"cached_content"`
	CreatedAt       time.Time  `json:"created_at"`
}

type BackupNode struct {
	ID        int       `json:"id"`
	Name      string    `json:"name"`
	RawURI    string    `json:"raw_uri"`
	Enabled   bool      `json:"enabled"`
	GroupName string    `json:"group_name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type BackupSetting struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type BackupSnapshot struct {
	ID        int       `json:"id"`
	Kind      string    `json:"kind"`
	Content   string    `json:"content"`
	CreatedAt time.Time `json:"created_at"`
	Note      string    `json:"note"`
}

type BackupAuthToken struct {
	ID         int        `json:"id"`
	TokenID    string     `json:"token_id"`
	AdminID    int        `json:"admin_id"`
	Name       string     `json:"name"`
	Scope      string     `json:"scope"`
	Enabled    bool       `json:"enabled"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	ExpiresAt  time.Time  `json:"expires_at"`
	CreatedAt  time.Time  `json:"created_at"`
}

type SyncLog struct {
	ID            int       `json:"id"`
	UpstreamID    int       `json:"upstream_id"`
	UpstreamName  string    `json:"upstream_name"`
	TriggerSource string    `json:"trigger_source"`
	Status        string    `json:"status"`
	NodeCount     int       `json:"node_count"`
	DurationMs    int64     `json:"duration_ms"`
	Detail        string    `json:"detail"`
	CreatedAt     time.Time `json:"created_at"`
}

type SystemLog struct {
	ID        int       `json:"id"`
	Level     string    `json:"level"`
	Category  string    `json:"category"`
	Action    string    `json:"action"`
	Detail    string    `json:"detail"`
	CreatedAt time.Time `json:"created_at"`
}

type UpstreamRawContent struct {
	UpstreamID int    `json:"upstream_id"`
	Name       string `json:"name"`
	Content    string `json:"content"`
	NodeCount  int    `json:"node_count"`
	LastStatus string `json:"last_status"`
}

type UpstreamRawPreview struct {
	NodeCount         int      `json:"node_count"`
	PreviewNodes      []string `json:"preview_nodes"`
	Truncated         bool     `json:"truncated"`
	NormalizedContent string   `json:"normalized_content"`
}

type AuthToken struct {
	ID         int        `json:"id"`
	Name       string     `json:"name"`
	Scope      string     `json:"scope"`
	Enabled    bool       `json:"enabled"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	ExpiresAt  time.Time  `json:"expires_at"`
	CreatedAt  time.Time  `json:"created_at"`
	IsCurrent  bool       `json:"is_current"`
}

type SnapshotRecord struct {
	ID            int       `json:"id"`
	Kind          string    `json:"kind"`
	Note          string    `json:"note"`
	ContentLength int       `json:"content_length"`
	CreatedAt     time.Time `json:"created_at"`
}

type Server struct {
	cfg             *config.Config
	db              *sql.DB
	jwtKey          []byte
	logger          *log.Logger
	metrics         *serverMetrics
	router          http.Handler
	sublink         *sublink.Client
	httpClient      *http.Client
	cacheMu         sync.Mutex
	lastCacheRun    time.Time
	sublinkSourceMu sync.Mutex
	sublinkSources  map[string]sublinkSourceEntry
	authCookieName  string
	loginMu         sync.Mutex
	loginIPWindows  map[string]loginAttemptWindow
	loginUserWindow map[string]loginAttemptWindow
	loginFailures   map[string]int
	loginLocks      map[string]time.Time
}

func New(cfg *config.Config, db *sql.DB, logger *log.Logger) (*Server, error) {
	if err := os.MkdirAll(cfg.CacheDir, 0o755); err != nil {
		return nil, fmt.Errorf("create cache dir: %w", err)
	}

	authCookieName := strings.TrimSpace(cfg.AuthCookieName)
	if authCookieName == "" {
		authCookieName = defaultAuthCookieName
	}

	s := &Server{
		cfg:            cfg,
		db:             db,
		jwtKey:         []byte(cfg.JWTSecret),
		logger:         logger,
		metrics:        newServerMetrics(),
		sublink:        sublink.New(cfg.SublinkURL, cfg.HTTPTimeout),
		authCookieName: authCookieName,
		httpClient: &http.Client{
			Timeout: cfg.HTTPTimeout,
		},
		sublinkSources:  make(map[string]sublinkSourceEntry),
		loginIPWindows:  make(map[string]loginAttemptWindow),
		loginUserWindow: make(map[string]loginAttemptWindow),
		loginFailures:   make(map[string]int),
		loginLocks:      make(map[string]time.Time),
	}
	s.router = s.routes()
	return s, nil
}

func (s *Server) Handler() http.Handler {
	return s.router
}

func (s *Server) routes() http.Handler {
	apiTimeout := s.cfg.APITimeout
	if apiTimeout <= 0 {
		apiTimeout = 30 * time.Second
	}

	r := chi.NewRouter()
	r.Use(chimw.RequestID)
	r.Use(chimw.RealIP)
	r.Use(chimw.Recoverer)
	r.Use(s.metricsMiddleware)
	r.Use(chimw.Timeout(apiTimeout))

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	r.Get("/metrics", s.handleMetrics)

	r.Get("/internal/subsource/{token}", s.handleSublinkSource)
	r.Get("/clash", s.handleOutput("clash"))
	r.Get("/singbox", s.handleOutput("singbox"))

	r.Route("/api", func(api chi.Router) {
		api.Post("/login", s.handleLogin)
		api.Post("/logout", s.handleLogout)

		api.Group(func(private chi.Router) {
			private.Use(s.authMiddleware)

			private.Get("/me", s.handleMe)
			private.Put("/password", s.handleChangePassword)
			private.Get("/tokens", s.handleListTokens)
			private.Post("/tokens", s.handleCreateToken)
			private.Delete("/tokens/{id}", s.handleRevokeToken)

			private.Get("/upstreams", s.handleListUpstreams)
			private.Post("/upstreams", s.handleCreateUpstream)
			private.Put("/upstreams/{id}", s.handleUpdateUpstream)
			private.Delete("/upstreams/{id}", s.handleDeleteUpstream)
			private.Post("/upstreams/{id}/sync", s.handleSyncUpstream)
			private.Get("/upstreams/{id}/raw", s.handleGetUpstreamRawContent)
			private.Post("/upstreams/{id}/raw/preview", s.handlePreviewUpstreamRawContent)
			private.Put("/upstreams/{id}/raw", s.handleUpdateUpstreamRawContent)
			private.Post("/sync", s.handleSyncAll)

			private.Get("/nodes", s.handleListNodes)
			private.Post("/nodes", s.handleCreateNode)
			private.Put("/nodes/{id}", s.handleUpdateNode)
			private.Delete("/nodes/{id}", s.handleDeleteNode)

			private.Get("/settings", s.handleGetSettings)
			private.Put("/settings", s.handleUpdateSettings)
			private.Get("/strategy", s.handleGetStrategy)
			private.Put("/strategy", s.handleUpdateStrategy)
			private.Post("/strategy/preview", s.handlePreviewStrategy)

			private.Get("/backup/export", s.handleExportBackup)
			private.Get("/backup/sqlite", s.handleExportSQLiteBackup)
			private.Post("/backup/import", s.handleImportBackup)
			private.Get("/snapshots", s.handleListSnapshots)
			private.Post("/snapshots/{id}/rollback", s.handleRollbackSnapshot)

			private.Get("/logs/sync", s.handleListSyncLogs)
			private.Get("/logs/system", s.handleListSystemLogs)
		})
	})

	return r
}

func (s *Server) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	if s.metrics == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = w.Write([]byte(s.metrics.renderPrometheus()))
}

func (s *Server) metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.metrics == nil {
			next.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		recorder := &statusCaptureWriter{ResponseWriter: w}
		next.ServeHTTP(recorder, r)
		route := "unknown"
		if rctx := chi.RouteContext(r.Context()); rctx != nil {
			pattern := strings.TrimSpace(rctx.RoutePattern())
			if pattern != "" {
				route = pattern
			}
		}
		s.metrics.observeHTTPRequest(r.Method, route, recorder.Status(), time.Since(start))
	})
}

func (s *Server) StartScheduler(ctx context.Context) {
	jobTimeout := s.cfg.SchedulerJobTimeout
	if jobTimeout <= 0 {
		jobTimeout = 60 * time.Second
	}

	ticker := time.NewTicker(s.cfg.SchedulerTickInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			tickCtx, cancel := context.WithTimeout(ctx, jobTimeout)
			s.runSchedulerTick(tickCtx)
			cancel()
		}
	}
}

func (s *Server) runSchedulerTick(ctx context.Context) {
	if err := s.syncDueUpstreams(ctx); err != nil {
		s.logger.Printf("scheduler sync error: %v", err)
		s.writeSystemLog(ctx, "error", "scheduler", "sync_due_upstreams", err.Error())
	}

	settings, err := s.getSettings(ctx)
	if err != nil {
		s.logger.Printf("scheduler settings error: %v", err)
		s.writeSystemLog(ctx, "error", "scheduler", "load_settings", err.Error())
		return
	}

	if settings.CacheMode && time.Since(s.lastCacheRun) >= time.Duration(settings.CacheInterval)*time.Minute {
		if _, err := s.refreshCache(ctx); err != nil {
			s.logger.Printf("scheduler refresh cache error: %v", err)
			s.writeSystemLog(ctx, "error", "scheduler", "refresh_cache", err.Error())
		} else {
			s.writeSystemLog(ctx, "info", "scheduler", "refresh_cache", fmt.Sprintf("cache refreshed, interval=%d", settings.CacheInterval))
			s.lastCacheRun = time.Now()
		}
	}

	if err := s.runAutoBackupIfDue(ctx, settings); err != nil {
		s.logger.Printf("scheduler auto backup error: %v", err)
		s.writeSystemLog(ctx, "error", "backup", "auto_backup", err.Error())
	}
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := s.extractTokenFromRequest(r)
		if token == "" {
			writeError(w, http.StatusUnauthorized, "missing auth token")
			return
		}

		claims, err := s.parseAndValidateToken(token)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid auth token")
			return
		}
		tokenName, err := s.validateTokenSession(r.Context(), claims.UserID, claims.ID)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "token revoked or expired")
			return
		}
		_, _ = s.db.ExecContext(r.Context(), `UPDATE auth_tokens SET last_used_at = CURRENT_TIMESTAMP WHERE token_id = ?`, claims.ID)

		ctx := context.WithValue(r.Context(), contextKeyAdmin, &AdminInfo{
			ID:        claims.UserID,
			Username:  claims.Username,
			TokenID:   claims.ID,
			TokenName: tokenName,
		})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func bearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return ""
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

func (s *Server) extractTokenFromRequest(r *http.Request) string {
	token := bearerToken(r)
	if token != "" {
		return token
	}
	cookie, err := r.Cookie(s.authCookieName)
	if err == nil {
		return strings.TrimSpace(cookie.Value)
	}
	return ""
}

func (s *Server) parseAndValidateToken(token string) (*AdminClaims, error) {
	claims := &AdminClaims{}
	parsed, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return s.jwtKey, nil
	})
	if err != nil || !parsed.Valid {
		return nil, errors.New("token invalid")
	}
	if claims.UserID <= 0 || strings.TrimSpace(claims.ID) == "" {
		return nil, errors.New("token claims invalid")
	}
	return claims, nil
}

func (s *Server) validateTokenSession(ctx context.Context, adminID int, tokenID string) (string, error) {
	var name string
	var enabledInt int
	var expiresAt time.Time
	err := s.db.QueryRowContext(
		ctx,
		`SELECT name, enabled, expires_at FROM auth_tokens WHERE token_id = ? AND admin_id = ?`,
		strings.TrimSpace(tokenID),
		adminID,
	).Scan(&name, &enabledInt, &expiresAt)
	if err != nil {
		return "", err
	}
	if enabledInt != 1 {
		return "", errors.New("token disabled")
	}
	if time.Now().After(expiresAt) {
		return "", errors.New("token expired")
	}
	return name, nil
}

func adminFromContext(ctx context.Context) (*AdminInfo, bool) {
	admin, ok := ctx.Value(contextKeyAdmin).(*AdminInfo)
	return admin, ok
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	type request struct {
		Username   string `json:"username"`
		Password   string `json:"password"`
		TokenName  string `json:"token_name"`
		TokenHours int    `json:"token_hours"`
	}
	var req request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "username and password are required")
		return
	}
	clientIP := requestClientIP(r)
	if err := s.checkLoginAllowed(clientIP, req.Username); err != nil {
		writeError(w, http.StatusTooManyRequests, err.Error())
		return
	}

	var id int
	var username string
	var passwordHash string
	query := `SELECT id, username, password_hash FROM admins WHERE username = ?`
	if err := s.db.QueryRowContext(r.Context(), query, req.Username).Scan(&id, &username, &passwordHash); err != nil {
		locked, retryAfter := s.recordLoginFailure(clientIP, req.Username)
		if locked {
			writeError(w, http.StatusTooManyRequests, fmt.Sprintf("login temporarily locked, retry after %d seconds", retryAfter))
			return
		}
		writeError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.Password)); err != nil {
		locked, retryAfter := s.recordLoginFailure(clientIP, req.Username)
		if locked {
			writeError(w, http.StatusTooManyRequests, fmt.Sprintf("login temporarily locked, retry after %d seconds", retryAfter))
			return
		}
		writeError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}
	s.recordLoginSuccess(clientIP, req.Username)

	tokenID, err := generateTokenID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create token id")
		return
	}
	tokenHours := req.TokenHours
	if tokenHours <= 0 {
		tokenHours = int(s.cfg.TokenTTL / time.Hour)
	}
	if tokenHours <= 0 {
		tokenHours = defaultTokenTTLHours
	}
	exp := time.Now().Add(time.Duration(tokenHours) * time.Hour)
	tokenName := strings.TrimSpace(req.TokenName)
	if tokenName == "" {
		tokenName = "web-login"
	}
	claims := AdminClaims{
		UserID:   id,
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(exp),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   strconv.Itoa(id),
			ID:        tokenID,
		},
	}
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := jwtToken.SignedString(s.jwtKey)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create token")
		return
	}
	if _, err := s.db.ExecContext(
		r.Context(),
		`INSERT INTO auth_tokens(token_id, admin_id, name, scope, enabled, expires_at, created_at, last_used_at) VALUES(?, ?, ?, 'full', 1, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
		tokenID,
		id,
		tokenName,
		exp,
	); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to persist token")
		return
	}

	http.SetCookie(w, s.buildAuthCookie(tokenString, exp, false))

	writeJSON(w, http.StatusOK, map[string]any{
		"token": tokenString,
		"admin": map[string]any{
			"id":         id,
			"username":   username,
			"token_id":   tokenID,
			"token_name": tokenName,
		},
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	token := s.extractTokenFromRequest(r)
	if token != "" {
		if claims, err := s.parseAndValidateToken(token); err == nil {
			_, _ = s.db.ExecContext(r.Context(), `UPDATE auth_tokens SET enabled = 0 WHERE token_id = ?`, claims.ID)
		}
	}
	http.SetCookie(w, s.buildAuthCookie("", time.Unix(0, 0), true))
	writeJSON(w, http.StatusOK, map[string]string{"message": "ok"})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	admin, ok := adminFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	writeJSON(w, http.StatusOK, admin)
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	admin, ok := adminFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	type request struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	var req request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.NewPassword) < 6 {
		writeError(w, http.StatusBadRequest, "new password must be at least 6 characters")
		return
	}

	var currentHash string
	if err := s.db.QueryRowContext(r.Context(), `SELECT password_hash FROM admins WHERE id = ?`, admin.ID).Scan(&currentHash); err != nil {
		writeError(w, http.StatusUnauthorized, "admin not found")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(currentHash), []byte(req.OldPassword)); err != nil {
		writeError(w, http.StatusUnauthorized, "old password is incorrect")
		return
	}

	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to hash password")
		return
	}
	if _, err := s.db.ExecContext(r.Context(), `UPDATE admins SET password_hash = ? WHERE id = ?`, string(newHash), admin.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update password")
		return
	}
	_, _ = s.db.ExecContext(r.Context(), `UPDATE auth_tokens SET enabled = 0 WHERE admin_id = ? AND token_id <> ?`, admin.ID, admin.TokenID)

	writeJSON(w, http.StatusOK, map[string]string{"message": "password updated"})
}

func (s *Server) handleListTokens(w http.ResponseWriter, r *http.Request) {
	admin, ok := adminFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	rows, err := s.db.QueryContext(
		r.Context(),
		`SELECT id, token_id, name, scope, enabled, last_used_at, expires_at, created_at
		FROM auth_tokens
		WHERE admin_id = ?
		ORDER BY id DESC`,
		admin.ID,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query tokens")
		return
	}
	defer rows.Close()

	items := make([]AuthToken, 0)
	for rows.Next() {
		var item AuthToken
		var tokenID string
		var enabledInt int
		var lastUsed sql.NullTime
		if err := rows.Scan(&item.ID, &tokenID, &item.Name, &item.Scope, &enabledInt, &lastUsed, &item.ExpiresAt, &item.CreatedAt); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to scan tokens")
			return
		}
		item.Enabled = enabledInt == 1
		if lastUsed.Valid {
			item.LastUsedAt = &lastUsed.Time
		}
		item.IsCurrent = strings.TrimSpace(tokenID) != "" && tokenID == admin.TokenID
		items = append(items, item)
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	admin, ok := adminFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	type request struct {
		Name  string `json:"name"`
		Hours int    `json:"hours"`
	}
	var req request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	tokenName := strings.TrimSpace(req.Name)
	if tokenName == "" {
		tokenName = "api-token"
	}
	tokenHours := req.Hours
	if tokenHours <= 0 {
		tokenHours = defaultTokenTTLHours
	}
	expiresAt := time.Now().Add(time.Duration(tokenHours) * time.Hour)
	tokenID, err := generateTokenID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create token id")
		return
	}

	claims := AdminClaims{
		UserID:   admin.ID,
		Username: admin.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   strconv.Itoa(admin.ID),
			ID:        tokenID,
		},
	}
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := jwtToken.SignedString(s.jwtKey)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to sign token")
		return
	}
	result, err := s.db.ExecContext(
		r.Context(),
		`INSERT INTO auth_tokens(token_id, admin_id, name, scope, enabled, expires_at, created_at, last_used_at) VALUES(?, ?, ?, 'full', 1, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
		tokenID,
		admin.ID,
		tokenName,
		expiresAt,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to persist token")
		return
	}
	insertID, _ := result.LastInsertId()
	s.writeSystemLog(r.Context(), "info", "auth", "create_token", fmt.Sprintf("admin_id=%d token_id=%s token_name=%s", admin.ID, tokenID, tokenName))

	writeJSON(w, http.StatusCreated, map[string]any{
		"token": tokenString,
		"item": AuthToken{
			ID:        int(insertID),
			Name:      tokenName,
			Scope:     "full",
			Enabled:   true,
			ExpiresAt: expiresAt,
			CreatedAt: time.Now(),
			IsCurrent: false,
		},
	})
}

func (s *Server) handleRevokeToken(w http.ResponseWriter, r *http.Request) {
	admin, ok := adminFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	id, err := parseIDParam(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid token id")
		return
	}

	var tokenID string
	var tokenName string
	if err := s.db.QueryRowContext(r.Context(), `SELECT token_id, name FROM auth_tokens WHERE id = ? AND admin_id = ?`, id, admin.ID).Scan(&tokenID, &tokenName); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "token not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to query token")
		return
	}
	if _, err := s.db.ExecContext(r.Context(), `UPDATE auth_tokens SET enabled = 0 WHERE id = ? AND admin_id = ?`, id, admin.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to revoke token")
		return
	}
	s.writeSystemLog(r.Context(), "info", "auth", "revoke_token", fmt.Sprintf("admin_id=%d token_id=%s token_name=%s", admin.ID, tokenID, tokenName))
	writeJSON(w, http.StatusOK, map[string]string{"message": "token revoked"})
}

func (s *Server) handleListUpstreams(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.QueryContext(r.Context(), `
		SELECT id, name, url, enabled, refresh_interval, last_sync_at, last_status, created_at
		FROM upstreams
		ORDER BY id DESC`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query upstreams")
		return
	}
	defer rows.Close()

	items := make([]Upstream, 0)
	for rows.Next() {
		var item Upstream
		var enabledInt int
		var lastSync sql.NullTime
		if err := rows.Scan(
			&item.ID,
			&item.Name,
			&item.URL,
			&enabledInt,
			&item.RefreshInterval,
			&lastSync,
			&item.LastStatus,
			&item.CreatedAt,
		); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to scan upstream")
			return
		}
		item.Enabled = enabledInt == 1
		if lastSync.Valid {
			item.LastSyncAt = &lastSync.Time
		}
		items = append(items, item)
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) handleCreateUpstream(w http.ResponseWriter, r *http.Request) {
	type request struct {
		Name            string `json:"name"`
		URL             string `json:"url"`
		Enabled         *bool  `json:"enabled"`
		RefreshInterval int    `json:"refresh_interval"`
	}
	var req request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if strings.TrimSpace(req.Name) == "" || strings.TrimSpace(req.URL) == "" {
		writeError(w, http.StatusBadRequest, "name and url are required")
		return
	}
	if req.RefreshInterval <= 0 {
		req.RefreshInterval = 60
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	result, err := s.db.ExecContext(
		r.Context(),
		`INSERT INTO upstreams(name, url, enabled, refresh_interval, created_at) VALUES(?, ?, ?, ?, CURRENT_TIMESTAMP)`,
		strings.TrimSpace(req.Name),
		strings.TrimSpace(req.URL),
		boolToInt(enabled),
		req.RefreshInterval,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create upstream")
		return
	}
	id, _ := result.LastInsertId()
	writeJSON(w, http.StatusCreated, map[string]any{"id": id})
}

func (s *Server) handleUpdateUpstream(w http.ResponseWriter, r *http.Request) {
	id, err := parseIDParam(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid upstream id")
		return
	}

	type request struct {
		Name            string `json:"name"`
		URL             string `json:"url"`
		Enabled         *bool  `json:"enabled"`
		RefreshInterval int    `json:"refresh_interval"`
	}
	var req request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if strings.TrimSpace(req.Name) == "" || strings.TrimSpace(req.URL) == "" {
		writeError(w, http.StatusBadRequest, "name and url are required")
		return
	}
	if req.RefreshInterval <= 0 {
		req.RefreshInterval = 60
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	result, err := s.db.ExecContext(
		r.Context(),
		`UPDATE upstreams SET name = ?, url = ?, enabled = ?, refresh_interval = ? WHERE id = ?`,
		strings.TrimSpace(req.Name),
		strings.TrimSpace(req.URL),
		boolToInt(enabled),
		req.RefreshInterval,
		id,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update upstream")
		return
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		writeError(w, http.StatusNotFound, "upstream not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "updated"})
}

func (s *Server) handleDeleteUpstream(w http.ResponseWriter, r *http.Request) {
	id, err := parseIDParam(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid upstream id")
		return
	}
	result, err := s.db.ExecContext(r.Context(), `DELETE FROM upstreams WHERE id = ?`, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to delete upstream")
		return
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		writeError(w, http.StatusNotFound, "upstream not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "deleted"})
}

func (s *Server) handleSyncUpstream(w http.ResponseWriter, r *http.Request) {
	id, err := parseIDParam(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid upstream id")
		return
	}
	if err := s.syncUpstream(r.Context(), id, "manual"); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("sync failed: %v", err))
		return
	}
	settings, _ := s.getSettings(r.Context())
	if settings != nil && settings.CacheMode {
		_, _ = s.refreshCache(r.Context())
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "synced"})
}

func (s *Server) handleSyncAll(w http.ResponseWriter, r *http.Request) {
	if err := s.syncAllUpstreams(r.Context(), "manual"); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("sync failed: %v", err))
		return
	}
	settings, _ := s.getSettings(r.Context())
	if settings != nil && settings.CacheMode {
		_, _ = s.refreshCache(r.Context())
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "all synced"})
}

func (s *Server) handleGetUpstreamRawContent(w http.ResponseWriter, r *http.Request) {
	id, err := parseIDParam(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid upstream id")
		return
	}

	var payload UpstreamRawContent
	payload.UpstreamID = id
	if err := s.db.QueryRowContext(
		r.Context(),
		`SELECT name, cached_content, last_status FROM upstreams WHERE id = ?`,
		id,
	).Scan(&payload.Name, &payload.Content, &payload.LastStatus); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "upstream not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to query upstream content")
		return
	}

	payload.NodeCount = len(splitNodes(payload.Content))
	writeJSON(w, http.StatusOK, payload)
}

func (s *Server) handlePreviewUpstreamRawContent(w http.ResponseWriter, r *http.Request) {
	id, err := parseIDParam(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid upstream id")
		return
	}
	var exists int
	if err := s.db.QueryRowContext(r.Context(), `SELECT COUNT(1) FROM upstreams WHERE id = ?`, id).Scan(&exists); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to check upstream")
		return
	}
	if exists == 0 {
		writeError(w, http.StatusNotFound, "upstream not found")
		return
	}

	type request struct {
		Content string `json:"content"`
	}
	var req request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	nodes, normalized, err := parseRawSubscriptionContent(req.Content)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	previewNodes := nodes
	truncated := false
	if len(previewNodes) > maxRawPreviewNodes {
		previewNodes = previewNodes[:maxRawPreviewNodes]
		truncated = true
	}
	writeJSON(w, http.StatusOK, UpstreamRawPreview{
		NodeCount:         len(nodes),
		PreviewNodes:      previewNodes,
		Truncated:         truncated,
		NormalizedContent: normalized,
	})
}

func (s *Server) handleUpdateUpstreamRawContent(w http.ResponseWriter, r *http.Request) {
	id, err := parseIDParam(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid upstream id")
		return
	}

	type request struct {
		Content string `json:"content"`
	}
	var req request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	nodes, normalized, err := parseRawSubscriptionContent(req.Content)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var name string
	if err := s.db.QueryRowContext(r.Context(), `SELECT name FROM upstreams WHERE id = ?`, id).Scan(&name); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "upstream not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to query upstream")
		return
	}

	status := fmt.Sprintf("manual raw import (%d nodes)", len(nodes))
	result, err := s.db.ExecContext(
		r.Context(),
		`UPDATE upstreams SET cached_content = ?, last_sync_at = CURRENT_TIMESTAMP, last_status = ? WHERE id = ?`,
		normalized,
		status,
		id,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update upstream raw content")
		return
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		writeError(w, http.StatusNotFound, "upstream not found")
		return
	}

	s.writeSyncLog(r.Context(), id, name, "manual_raw", "ok", len(nodes), 0, status)
	s.writeSystemLog(
		r.Context(),
		"info",
		"upstream",
		"raw_import",
		fmt.Sprintf("upstream_id=%d upstream_name=%s node_count=%d", id, name, len(nodes)),
	)
	settings, _ := s.getSettings(r.Context())
	if settings != nil && settings.CacheMode {
		_, _ = s.refreshCache(r.Context())
	}

	writeJSON(w, http.StatusOK, UpstreamRawContent{
		UpstreamID: id,
		Name:       name,
		Content:    normalized,
		NodeCount:  len(nodes),
		LastStatus: status,
	})
}

func (s *Server) handleListNodes(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.QueryContext(r.Context(), `
		SELECT id, name, raw_uri, enabled, group_name, created_at, updated_at
		FROM manual_nodes
		ORDER BY id DESC`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query nodes")
		return
	}
	defer rows.Close()

	items := make([]ManualNode, 0)
	for rows.Next() {
		var item ManualNode
		var enabledInt int
		if err := rows.Scan(
			&item.ID,
			&item.Name,
			&item.RawURI,
			&enabledInt,
			&item.GroupName,
			&item.CreatedAt,
			&item.UpdatedAt,
		); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to scan node")
			return
		}
		item.Enabled = enabledInt == 1
		items = append(items, item)
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) handleCreateNode(w http.ResponseWriter, r *http.Request) {
	type request struct {
		Name      string `json:"name"`
		RawURI    string `json:"raw_uri"`
		Enabled   *bool  `json:"enabled"`
		GroupName string `json:"group_name"`
	}
	var req request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if strings.TrimSpace(req.Name) == "" || strings.TrimSpace(req.RawURI) == "" {
		writeError(w, http.StatusBadRequest, "name and raw_uri are required")
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	group := strings.TrimSpace(req.GroupName)
	if group == "" {
		group = "default"
	}

	result, err := s.db.ExecContext(
		r.Context(),
		`INSERT INTO manual_nodes(name, raw_uri, enabled, group_name, created_at, updated_at) VALUES(?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
		strings.TrimSpace(req.Name),
		strings.TrimSpace(req.RawURI),
		boolToInt(enabled),
		group,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create node")
		return
	}
	id, _ := result.LastInsertId()
	writeJSON(w, http.StatusCreated, map[string]any{"id": id})
}

func (s *Server) handleUpdateNode(w http.ResponseWriter, r *http.Request) {
	id, err := parseIDParam(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid node id")
		return
	}

	type request struct {
		Name      string `json:"name"`
		RawURI    string `json:"raw_uri"`
		Enabled   *bool  `json:"enabled"`
		GroupName string `json:"group_name"`
	}
	var req request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if strings.TrimSpace(req.Name) == "" || strings.TrimSpace(req.RawURI) == "" {
		writeError(w, http.StatusBadRequest, "name and raw_uri are required")
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	group := strings.TrimSpace(req.GroupName)
	if group == "" {
		group = "default"
	}

	result, err := s.db.ExecContext(
		r.Context(),
		`UPDATE manual_nodes SET name = ?, raw_uri = ?, enabled = ?, group_name = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		strings.TrimSpace(req.Name),
		strings.TrimSpace(req.RawURI),
		boolToInt(enabled),
		group,
		id,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update node")
		return
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		writeError(w, http.StatusNotFound, "node not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "updated"})
}

func (s *Server) handleDeleteNode(w http.ResponseWriter, r *http.Request) {
	id, err := parseIDParam(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid node id")
		return
	}
	result, err := s.db.ExecContext(r.Context(), `DELETE FROM manual_nodes WHERE id = ?`, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to delete node")
		return
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		writeError(w, http.StatusNotFound, "node not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "deleted"})
}

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	settings, err := s.getSettings(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get settings")
		return
	}
	writeJSON(w, http.StatusOK, settings)
}

func (s *Server) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	type request struct {
		CacheMode               *bool  `json:"cache_mode"`
		CacheInterval           *int   `json:"cache_interval"`
		OutputTemplate          string `json:"output_template"`
		AutoBackupEnabled       *bool  `json:"auto_backup_enabled"`
		AutoBackupIntervalHours *int   `json:"auto_backup_interval_hours"`
		AutoBackupKeep          *int   `json:"auto_backup_keep"`
	}
	var req request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	current, err := s.getSettings(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get settings")
		return
	}

	if req.CacheMode != nil {
		current.CacheMode = *req.CacheMode
	}
	if req.CacheInterval != nil && *req.CacheInterval > 0 {
		current.CacheInterval = *req.CacheInterval
	}
	if strings.TrimSpace(req.OutputTemplate) != "" {
		current.OutputTemplate = strings.TrimSpace(req.OutputTemplate)
	}
	if req.AutoBackupEnabled != nil {
		current.AutoBackupEnabled = *req.AutoBackupEnabled
	}
	if req.AutoBackupIntervalHours != nil && *req.AutoBackupIntervalHours > 0 {
		current.AutoBackupIntervalHours = *req.AutoBackupIntervalHours
	}
	if req.AutoBackupKeep != nil && *req.AutoBackupKeep > 0 {
		current.AutoBackupKeep = *req.AutoBackupKeep
	}

	if err := s.setSetting(r.Context(), "cache_mode", strconv.FormatBool(current.CacheMode)); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save cache mode")
		return
	}
	if err := s.setSetting(r.Context(), "cache_interval", strconv.Itoa(current.CacheInterval)); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save cache interval")
		return
	}
	if err := s.setSetting(r.Context(), "output_template", current.OutputTemplate); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save output template")
		return
	}
	if err := s.setSetting(r.Context(), "auto_backup_enabled", strconv.FormatBool(current.AutoBackupEnabled)); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save auto backup enabled")
		return
	}
	if err := s.setSetting(r.Context(), "auto_backup_interval_hours", strconv.Itoa(current.AutoBackupIntervalHours)); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save auto backup interval")
		return
	}
	if err := s.setSetting(r.Context(), "auto_backup_keep", strconv.Itoa(current.AutoBackupKeep)); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save auto backup keep")
		return
	}
	s.writeSystemLog(
		r.Context(),
		"info",
		"settings",
		"update",
		fmt.Sprintf(
			"cache_mode=%t cache_interval=%d output_template=%s auto_backup_enabled=%t auto_backup_interval_hours=%d auto_backup_keep=%d",
			current.CacheMode,
			current.CacheInterval,
			current.OutputTemplate,
			current.AutoBackupEnabled,
			current.AutoBackupIntervalHours,
			current.AutoBackupKeep,
		),
	)
	if current.CacheMode {
		_, _ = s.refreshCache(r.Context())
	}
	writeJSON(w, http.StatusOK, current)
}

func (s *Server) handleListSyncLogs(w http.ResponseWriter, r *http.Request) {
	limit := parseLimitQuery(r.URL.Query().Get("limit"))
	rows, err := s.db.QueryContext(
		r.Context(),
		`SELECT id, upstream_id, upstream_name, trigger_source, status, node_count, duration_ms, detail, created_at
		FROM sync_logs
		ORDER BY id DESC
		LIMIT ?`,
		limit,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query sync logs")
		return
	}
	defer rows.Close()

	items := make([]SyncLog, 0, limit)
	for rows.Next() {
		var item SyncLog
		if err := rows.Scan(
			&item.ID,
			&item.UpstreamID,
			&item.UpstreamName,
			&item.TriggerSource,
			&item.Status,
			&item.NodeCount,
			&item.DurationMs,
			&item.Detail,
			&item.CreatedAt,
		); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to scan sync logs")
			return
		}
		items = append(items, item)
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) handleListSystemLogs(w http.ResponseWriter, r *http.Request) {
	limit := parseLimitQuery(r.URL.Query().Get("limit"))
	rows, err := s.db.QueryContext(
		r.Context(),
		`SELECT id, level, category, action, detail, created_at
		FROM system_logs
		ORDER BY id DESC
		LIMIT ?`,
		limit,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query system logs")
		return
	}
	defer rows.Close()

	items := make([]SystemLog, 0, limit)
	for rows.Next() {
		var item SystemLog
		if err := rows.Scan(
			&item.ID,
			&item.Level,
			&item.Category,
			&item.Action,
			&item.Detail,
			&item.CreatedAt,
		); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to scan system logs")
			return
		}
		items = append(items, item)
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) handleListSnapshots(w http.ResponseWriter, r *http.Request) {
	limit := parseLimitQuery(r.URL.Query().Get("limit"))
	kind := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("kind")))
	if kind != "" && kind != "clash" && kind != "singbox" {
		writeError(w, http.StatusBadRequest, "invalid snapshot kind")
		return
	}

	var rows *sql.Rows
	var err error
	if kind == "" {
		rows, err = s.db.QueryContext(
			r.Context(),
			`SELECT id, kind, note, length(content), created_at
			FROM snapshots
			ORDER BY id DESC
			LIMIT ?`,
			limit,
		)
	} else {
		rows, err = s.db.QueryContext(
			r.Context(),
			`SELECT id, kind, note, length(content), created_at
			FROM snapshots
			WHERE kind = ?
			ORDER BY id DESC
			LIMIT ?`,
			kind,
			limit,
		)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query snapshots")
		return
	}
	defer rows.Close()

	items := make([]SnapshotRecord, 0, limit)
	for rows.Next() {
		var item SnapshotRecord
		if err := rows.Scan(&item.ID, &item.Kind, &item.Note, &item.ContentLength, &item.CreatedAt); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to scan snapshots")
			return
		}
		items = append(items, item)
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) handleRollbackSnapshot(w http.ResponseWriter, r *http.Request) {
	id, err := parseIDParam(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid snapshot id")
		return
	}
	var kind string
	var content string
	if err := s.db.QueryRowContext(r.Context(), `SELECT kind, content FROM snapshots WHERE id = ?`, id).Scan(&kind, &content); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "snapshot not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to query snapshot")
		return
	}
	kind = strings.TrimSpace(strings.ToLower(kind))
	if kind != "clash" && kind != "singbox" {
		writeError(w, http.StatusBadRequest, "snapshot kind is not rollbackable")
		return
	}
	if err := os.WriteFile(s.cacheFile(kind), []byte(content), 0o644); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to write rollback cache")
		return
	}
	if _, err := s.db.ExecContext(
		r.Context(),
		`INSERT INTO snapshots(kind, content, note, created_at) VALUES(?, ?, ?, CURRENT_TIMESTAMP)`,
		kind,
		content,
		fmt.Sprintf("rollback from #%d", id),
	); err != nil {
		s.logger.Printf("insert rollback snapshot failed: %v", err)
	}
	s.lastCacheRun = time.Now()
	s.writeSystemLog(r.Context(), "info", "snapshot", "rollback", fmt.Sprintf("snapshot_id=%d kind=%s", id, kind))
	writeJSON(w, http.StatusOK, map[string]string{"message": "rollback completed"})
}

func (s *Server) handleOutput(target string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		settings, err := s.getSettings(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to read settings")
			return
		}

		if settings.CacheMode {
			content, lastModified, err := s.readCacheWithModTime(target)
			if err == nil && strings.TrimSpace(content) != "" {
				s.writeOutput(w, r, target, content, lastModified)
				return
			}

			content, lastModified, err = s.ensureOutputCache(r.Context(), target)
			if err != nil {
				writeError(w, http.StatusBadGateway, fmt.Sprintf("refresh cache failed: %v", err))
				return
			}
			s.writeOutput(w, r, target, content, lastModified)
			return
		}

		nodes, err := s.collectNodesRealtime(r.Context())
		if err != nil {
			writeError(w, http.StatusBadGateway, fmt.Sprintf("collect nodes failed: %v", err))
			return
		}
		content, err := s.convertNodes(r.Context(), target, nodes)
		if err != nil {
			writeError(w, http.StatusBadGateway, fmt.Sprintf("convert failed: %v", err))
			return
		}
		s.writeOutput(w, r, target, content, time.Now())
	}
}

func (s *Server) handleSublinkSource(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(chi.URLParam(r, "token"))
	if token == "" {
		writeError(w, http.StatusNotFound, "source not found")
		return
	}

	content, ok := s.readSublinkSource(token)
	if !ok {
		writeError(w, http.StatusNotFound, "source not found")
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(base64.StdEncoding.EncodeToString([]byte(content))))
}

func (s *Server) convertNodes(ctx context.Context, target string, nodes []string) (string, error) {
	if len(nodes) == 0 {
		return "", errors.New("no nodes available for conversion")
	}

	payload := strings.Join(nodes, "\n")
	if len(payload) > maxSublinkSourceBytes {
		return "", fmt.Errorf("node payload too large (%d bytes)", len(payload))
	}

	sourceBase := strings.TrimSpace(s.cfg.SublinkSourceBaseURL)
	if sourceBase == "" {
		return "", errors.New("sublink source base url is empty")
	}

	token, err := s.registerSublinkSource(payload)
	if err != nil {
		return "", err
	}
	defer s.removeSublinkSource(token)

	sourceURL := strings.TrimRight(sourceBase, "/") + "/internal/subsource/" + token
	return s.sublink.ConvertFromURL(ctx, target, sourceURL)
}

func (s *Server) registerSublinkSource(content string) (string, error) {
	token, err := generateTokenID()
	if err != nil {
		return "", fmt.Errorf("generate sublink source token: %w", err)
	}

	now := time.Now()
	s.sublinkSourceMu.Lock()
	s.cleanupExpiredSublinkSourcesLocked(now)
	s.sublinkSources[token] = sublinkSourceEntry{
		content:   content,
		expiresAt: now.Add(sublinkSourceTTL),
	}
	s.sublinkSourceMu.Unlock()

	return token, nil
}

func (s *Server) readSublinkSource(token string) (string, bool) {
	now := time.Now()
	s.sublinkSourceMu.Lock()
	defer s.sublinkSourceMu.Unlock()

	s.cleanupExpiredSublinkSourcesLocked(now)
	entry, ok := s.sublinkSources[token]
	if !ok {
		return "", false
	}
	if now.After(entry.expiresAt) {
		delete(s.sublinkSources, token)
		return "", false
	}
	return entry.content, true
}

func (s *Server) removeSublinkSource(token string) {
	token = strings.TrimSpace(token)
	if token == "" {
		return
	}
	s.sublinkSourceMu.Lock()
	delete(s.sublinkSources, token)
	s.sublinkSourceMu.Unlock()
}

func (s *Server) cleanupExpiredSublinkSourcesLocked(now time.Time) {
	for token, entry := range s.sublinkSources {
		if now.After(entry.expiresAt) {
			delete(s.sublinkSources, token)
		}
	}
}

func (s *Server) refreshCache(ctx context.Context) (map[string]string, error) {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	return s.refreshCacheLocked(ctx)
}

func (s *Server) refreshCacheLocked(ctx context.Context) (map[string]string, error) {
	nodes, err := s.collectNodesFromStore(ctx)
	if err != nil {
		return nil, err
	}

	result := make(map[string]string, 2)
	for _, target := range []string{"clash", "singbox"} {
		converted, err := s.convertNodes(ctx, target, nodes)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(s.cacheFile(target), []byte(converted), 0o644); err != nil {
			return nil, fmt.Errorf("write %s cache: %w", target, err)
		}
		if _, err := s.db.ExecContext(
			ctx,
			`INSERT INTO snapshots(kind, content, note, created_at) VALUES(?, ?, ?, CURRENT_TIMESTAMP)`,
			target,
			converted,
			"cache refresh",
		); err != nil {
			s.logger.Printf("insert snapshot failed: %v", err)
		}
		result[target] = converted
	}

	s.lastCacheRun = time.Now()
	return result, nil
}

func (s *Server) ensureOutputCache(ctx context.Context, target string) (string, time.Time, error) {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()

	content, lastModified, err := s.readCacheWithModTime(target)
	if err == nil && strings.TrimSpace(content) != "" {
		return content, lastModified, nil
	}

	result, err := s.refreshCacheLocked(ctx)
	if err != nil {
		return "", time.Time{}, err
	}

	content = result[target]
	lastModified = s.lastCacheRun
	if lastModified.IsZero() {
		lastModified = time.Now()
	}
	return content, lastModified, nil
}

func (s *Server) collectNodesFromStore(ctx context.Context) ([]string, error) {
	config, err := s.getStrategyConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("load strategy config: %w", err)
	}
	sources, err := s.collectStrategySourcesFromStore(ctx, config)
	if err != nil {
		return nil, err
	}
	return applyNodeStrategy(sources, config).Nodes, nil
}

func (s *Server) collectNodesRealtime(ctx context.Context) ([]string, error) {
	config, err := s.getStrategyConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("load strategy config: %w", err)
	}
	sources, err := s.collectStrategySourcesRealtime(ctx, config)
	if err != nil {
		return nil, err
	}
	return applyNodeStrategy(sources, config).Nodes, nil
}

func (s *Server) syncDueUpstreams(ctx context.Context) error {
	dueIDs, err := s.listDueUpstreamIDs(ctx)
	if err != nil {
		return err
	}
	if len(dueIDs) == 0 {
		return nil
	}

	okCount, errs := s.syncUpstreamBatch(ctx, dueIDs, "scheduler")
	if len(errs) > 0 {
		return fmt.Errorf("due sync partial failure: success=%d failed=%d: %s", okCount, len(errs), strings.Join(errs, "; "))
	}
	return nil
}

func (s *Server) syncAllUpstreams(ctx context.Context, triggerSource string) error {
	start := time.Now()
	concurrency := s.syncMaxConcurrency()
	maxAttempts := s.syncRetryMaxAttempts()
	s.writeSystemLogWithMeta(
		ctx,
		"info",
		"sync",
		"sync_all_start",
		"start",
		0,
		fmt.Sprintf("trigger=%s concurrency=%d retry_attempts=%d", triggerSource, concurrency, maxAttempts),
	)

	ids, err := s.listEnabledUpstreamIDs(ctx)
	if err != nil {
		if s.metrics != nil {
			s.metrics.observeSyncBatch(triggerSource, "fail", time.Since(start))
		}
		return err
	}
	if len(ids) == 0 {
		duration := time.Since(start)
		if s.metrics != nil {
			s.metrics.observeSyncBatch(triggerSource, "ok", duration)
		}
		s.writeSystemLogWithMeta(
			ctx,
			"info",
			"sync",
			"sync_all_finish",
			"ok",
			duration.Milliseconds(),
			fmt.Sprintf("trigger=%s success=0 failed=0 duration_ms=%d concurrency=%d retry_attempts=%d", triggerSource, duration.Milliseconds(), concurrency, maxAttempts),
		)
		return nil
	}

	okCount, errs := s.syncUpstreamBatch(ctx, ids, triggerSource)
	if len(errs) > 0 {
		duration := time.Since(start)
		if s.metrics != nil {
			s.metrics.observeSyncBatch(triggerSource, "fail", duration)
		}
		s.writeSystemLogWithMeta(
			ctx,
			"error",
			"sync",
			"sync_all_finish",
			"fail",
			duration.Milliseconds(),
			fmt.Sprintf("trigger=%s success=%d failed=%d duration_ms=%d concurrency=%d retry_attempts=%d", triggerSource, okCount, len(errs), duration.Milliseconds(), concurrency, maxAttempts),
		)
		return errors.New(strings.Join(errs, "; "))
	}
	duration := time.Since(start)
	if s.metrics != nil {
		s.metrics.observeSyncBatch(triggerSource, "ok", duration)
	}
	s.writeSystemLogWithMeta(
		ctx,
		"info",
		"sync",
		"sync_all_finish",
		"ok",
		duration.Milliseconds(),
		fmt.Sprintf("trigger=%s success=%d failed=%d duration_ms=%d concurrency=%d retry_attempts=%d", triggerSource, okCount, 0, duration.Milliseconds(), concurrency, maxAttempts),
	)
	return nil
}

func (s *Server) listEnabledUpstreamIDs(ctx context.Context) ([]int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM upstreams WHERE enabled = 1`)
	if err != nil {
		return nil, fmt.Errorf("query enabled upstreams: %w", err)
	}
	defer rows.Close()

	ids := make([]int, 0)
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan enabled upstream id: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate enabled upstreams: %w", err)
	}
	return ids, nil
}

func (s *Server) listDueUpstreamIDs(ctx context.Context) ([]int, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, refresh_interval, last_sync_at
		FROM upstreams
		WHERE enabled = 1`)
	if err != nil {
		return nil, fmt.Errorf("query due upstreams: %w", err)
	}
	defer rows.Close()

	dueIDs := make([]int, 0)
	now := time.Now()
	for rows.Next() {
		var id int
		var interval int
		var lastSync sql.NullTime
		if err := rows.Scan(&id, &interval, &lastSync); err != nil {
			return nil, fmt.Errorf("scan upstream due row: %w", err)
		}
		if interval <= 0 {
			interval = 60
		}
		if lastSync.Valid && now.Sub(lastSync.Time) < time.Duration(interval)*time.Minute {
			continue
		}
		dueIDs = append(dueIDs, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate due upstreams: %w", err)
	}
	return dueIDs, nil
}

func (s *Server) syncUpstreamBatch(ctx context.Context, ids []int, triggerSource string) (int, []string) {
	if len(ids) == 0 {
		return 0, nil
	}

	workerCount := s.syncMaxConcurrency()
	if workerCount > len(ids) {
		workerCount = len(ids)
	}

	jobs := make(chan int)
	results := make(chan syncJobResult, len(ids))
	var wg sync.WaitGroup

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range jobs {
				results <- syncJobResult{
					id:  id,
					err: s.syncUpstream(ctx, id, triggerSource),
				}
			}
		}()
	}

	for _, id := range ids {
		jobs <- id
	}
	close(jobs)
	wg.Wait()
	close(results)

	okCount := 0
	errs := make([]string, 0)
	for result := range results {
		if result.err != nil {
			errs = append(errs, fmt.Sprintf("%d:%v", result.id, result.err))
			continue
		}
		okCount++
	}
	sort.Strings(errs)
	return okCount, errs
}

func (s *Server) syncUpstream(ctx context.Context, id int, triggerSource string) error {
	start := time.Now()

	var name string
	var url string
	var enabledInt int
	if err := s.db.QueryRowContext(ctx, `SELECT name, url, enabled FROM upstreams WHERE id = ?`, id).Scan(&name, &url, &enabledInt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			duration := time.Since(start)
			s.writeSyncLog(ctx, id, "", triggerSource, "fail", 0, duration.Milliseconds(), "upstream not found")
			if s.metrics != nil {
				s.metrics.observeSyncUpstream(triggerSource, "fail", "not_found", 0, duration)
			}
			return fmt.Errorf("upstream %d not found", id)
		}
		duration := time.Since(start)
		s.writeSyncLog(ctx, id, "", triggerSource, "fail", 0, duration.Milliseconds(), fmt.Sprintf("query upstream failed: %v", err))
		if s.metrics != nil {
			s.metrics.observeSyncUpstream(triggerSource, "fail", "db_query_error", 0, duration)
		}
		return fmt.Errorf("query upstream %d: %w", id, err)
	}
	if enabledInt != 1 {
		duration := time.Since(start)
		s.writeSyncLog(ctx, id, name, triggerSource, "skipped", 0, duration.Milliseconds(), "upstream disabled")
		if s.metrics != nil {
			s.metrics.observeSyncUpstream(triggerSource, "skipped", "disabled", 0, duration)
		}
		return nil
	}

	maxAttempts := s.syncRetryMaxAttempts()
	retryCount := 0
	lastErr := error(nil)
	lastNodeCount := 0

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		nodes, err := s.fetchUpstreamNodes(ctx, url)
		if err == nil {
			lastNodeCount = len(nodes)
			status := fmt.Sprintf("ok (%d nodes)", len(nodes))
			if _, saveErr := s.db.ExecContext(
				ctx,
				`UPDATE upstreams SET last_sync_at = CURRENT_TIMESTAMP, last_status = ?, cached_content = ? WHERE id = ?`,
				status,
				strings.Join(nodes, "\n"),
				id,
			); saveErr != nil {
				lastErr = fmt.Errorf("update upstream cache: %w", saveErr)
				break
			}
			durationMs := time.Since(start).Milliseconds()
			detail := fmt.Sprintf("ok retry_count=%d", retryCount)
			s.writeSyncLog(ctx, id, name, triggerSource, "ok", len(nodes), durationMs, detail)
			if s.metrics != nil {
				s.metrics.observeSyncUpstream(triggerSource, "ok", "none", retryCount, time.Duration(durationMs)*time.Millisecond)
			}
			return nil
		}

		lastErr = err
		if attempt >= maxAttempts || !s.isRetryableSyncError(err) {
			break
		}

		retryCount++
		delay := s.syncRetryDelay(retryCount)
		errorClass := s.classifySyncError(err)
		s.writeSystemLogWithMeta(
			ctx,
			"warning",
			"sync",
			"sync_upstream_retry",
			"retry",
			time.Since(start).Milliseconds(),
			fmt.Sprintf("upstream_id=%d upstream_name=%s trigger=%s retry=%d max_retry=%d delay_ms=%d class=%s detail=%s", id, name, triggerSource, retryCount, maxAttempts-1, delay.Milliseconds(), errorClass, err.Error()),
		)
		if waitErr := waitContext(ctx, delay); waitErr != nil {
			lastErr = waitErr
			break
		}
	}

	if lastErr == nil {
		lastErr = errors.New("unknown sync error")
	}
	status := fmt.Sprintf("sync failed: %v", lastErr)
	_, _ = s.db.ExecContext(ctx, `UPDATE upstreams SET last_sync_at = CURRENT_TIMESTAMP, last_status = ? WHERE id = ?`, status, id)
	durationMs := time.Since(start).Milliseconds()
	errorClass := s.classifySyncError(lastErr)
	detail := fmt.Sprintf("class=%s retry_count=%d detail=%s", errorClass, retryCount, lastErr.Error())
	s.writeSyncLog(ctx, id, name, triggerSource, "fail", lastNodeCount, durationMs, detail)
	s.writeSystemLogWithMeta(
		ctx,
		"error",
		"sync",
		"sync_upstream",
		"fail",
		durationMs,
		fmt.Sprintf("upstream_id=%d upstream_name=%s trigger=%s duration_ms=%d retry_count=%d class=%s detail=%s", id, name, triggerSource, durationMs, retryCount, errorClass, lastErr.Error()),
	)
	if s.metrics != nil {
		s.metrics.observeSyncUpstream(triggerSource, "fail", errorClass, retryCount, time.Duration(durationMs)*time.Millisecond)
	}
	return lastErr
}

func (s *Server) fetchUpstreamNodes(ctx context.Context, url string) ([]string, error) {
	url = strings.TrimSpace(url)
	if url == "" {
		return nil, errors.New("empty upstream url")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		wrappedErr := fmt.Errorf("fetch upstream: %w", err)
		if errors.Is(err, context.Canceled) {
			return nil, wrappedErr
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, &retryableSyncError{err: wrappedErr}
		}
		var netErr net.Error
		if errors.As(err, &netErr) {
			return nil, &retryableSyncError{err: wrappedErr}
		}
		return nil, wrappedErr
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		statusErr := &upstreamHTTPStatusError{StatusCode: resp.StatusCode}
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= http.StatusInternalServerError {
			return nil, &retryableSyncError{err: statusErr}
		}
		return nil, statusErr
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, &retryableSyncError{err: fmt.Errorf("read upstream: %w", err)}
	}

	parsed := parseSubscription(body)
	if len(parsed) == 0 {
		return nil, errors.New("subscription contains no nodes")
	}
	return parsed, nil
}

func parseSubscription(body []byte) []string {
	raw := strings.TrimSpace(string(body))
	if raw == "" {
		return nil
	}

	decoded := tryDecodeBase64(raw)
	if decoded != "" {
		lines := splitNodes(decoded)
		if len(lines) > 0 {
			return dedupeNodes(lines)
		}
	}

	return dedupeNodes(splitNodes(raw))
}

func parseRawSubscriptionContent(content string) ([]string, string, error) {
	content = strings.TrimSpace(content)
	if content == "" {
		return nil, "", errors.New("content is empty")
	}
	if len(content) > maxRawContentBytes {
		return nil, "", fmt.Errorf("content too large (max %d bytes)", maxRawContentBytes)
	}

	nodes := parseSubscription([]byte(content))
	if len(nodes) == 0 {
		return nil, "", errors.New("content contains no nodes")
	}
	normalized := strings.Join(nodes, "\n")
	return nodes, normalized, nil
}

func tryDecodeBase64(raw string) string {
	clean := strings.ReplaceAll(raw, "\n", "")
	clean = strings.ReplaceAll(clean, "\r", "")
	clean = strings.TrimSpace(clean)
	if clean == "" {
		return ""
	}
	decoded, err := base64.StdEncoding.DecodeString(clean)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(clean)
		if err != nil {
			return ""
		}
	}
	text := strings.TrimSpace(string(decoded))
	if !strings.Contains(text, "://") {
		return ""
	}
	return text
}

func splitNodes(text string) []string {
	normalized := strings.ReplaceAll(text, "\r", "")
	lines := strings.Split(normalized, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !isNodeURI(line) {
			continue
		}
		out = append(out, line)
	}
	return out
}

func isNodeURI(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	return strings.HasPrefix(lower, "vmess://") ||
		strings.HasPrefix(lower, "vless://") ||
		strings.HasPrefix(lower, "trojan://") ||
		strings.HasPrefix(lower, "ss://") ||
		strings.HasPrefix(lower, "ssr://") ||
		strings.HasPrefix(lower, "hysteria://") ||
		strings.HasPrefix(lower, "hysteria2://") ||
		strings.HasPrefix(lower, "hy2://") ||
		strings.HasPrefix(lower, "tuic://") ||
		strings.HasPrefix(lower, "snell://") ||
		strings.HasPrefix(lower, "wireguard://")
}

func dedupeNodes(nodes []string) []string {
	seen := make(map[string]struct{}, len(nodes))
	result := make([]string, 0, len(nodes))
	for _, item := range nodes {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		result = append(result, item)
	}
	sort.Strings(result)
	return result
}

func (s *Server) getSettings(ctx context.Context) (*Settings, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key, value FROM settings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	settings := &Settings{
		CacheMode:               s.cfg.DefaultCacheMode,
		CacheInterval:           s.cfg.DefaultCacheInterval,
		OutputTemplate:          "default",
		AutoBackupEnabled:       false,
		AutoBackupIntervalHours: defaultAutoBackupHours,
		AutoBackupKeep:          defaultAutoBackupKeep,
	}

	for rows.Next() {
		var key string
		var value string
		if err := rows.Scan(&key, &value); err != nil {
			return nil, err
		}
		switch key {
		case "cache_mode":
			parsed, err := strconv.ParseBool(value)
			if err == nil {
				settings.CacheMode = parsed
			}
		case "cache_interval":
			parsed, err := strconv.Atoi(value)
			if err == nil && parsed > 0 {
				settings.CacheInterval = parsed
			}
		case "output_template":
			if strings.TrimSpace(value) != "" {
				settings.OutputTemplate = strings.TrimSpace(value)
			}
		case "auto_backup_enabled":
			parsed, err := strconv.ParseBool(value)
			if err == nil {
				settings.AutoBackupEnabled = parsed
			}
		case "auto_backup_interval_hours":
			parsed, err := strconv.Atoi(value)
			if err == nil && parsed > 0 {
				settings.AutoBackupIntervalHours = parsed
			}
		case "auto_backup_keep":
			parsed, err := strconv.Atoi(value)
			if err == nil && parsed > 0 {
				settings.AutoBackupKeep = parsed
			}
		}
	}

	if settings.CacheInterval <= 0 {
		settings.CacheInterval = 10
	}
	if settings.AutoBackupIntervalHours <= 0 {
		settings.AutoBackupIntervalHours = defaultAutoBackupHours
	}
	if settings.AutoBackupKeep <= 0 {
		settings.AutoBackupKeep = defaultAutoBackupKeep
	}
	return settings, nil
}

func (s *Server) setSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

func (s *Server) handleExportBackup(w http.ResponseWriter, r *http.Request) {
	payload, err := s.collectBackupPayload(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("collect backup payload failed: %v", err))
		return
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=backup-%d.json", time.Now().Unix()))
	s.writeSystemLog(
		r.Context(),
		"info",
		"backup",
		"export",
		fmt.Sprintf(
			"admins=%d auth_tokens=%d upstreams=%d manual_nodes=%d settings=%d snapshots=%d",
			len(payload.Admins),
			len(payload.AuthTokens),
			len(payload.Upstreams),
			len(payload.ManualNodes),
			len(payload.Settings),
			len(payload.Snapshots),
		),
	)
	writeJSON(w, http.StatusOK, payload)
}

func (s *Server) handleExportSQLiteBackup(w http.ResponseWriter, r *http.Request) {
	tempDir := filepath.Join(s.cfg.CacheDir, "tmp")
	if err := os.MkdirAll(tempDir, 0o755); err != nil {
		writeError(w, http.StatusInternalServerError, "create temp dir failed")
		return
	}

	tempFile := filepath.Join(tempDir, fmt.Sprintf("subadmin-sqlite-export-%d.db", time.Now().UnixNano()))
	if err := s.createSQLiteSnapshot(r.Context(), tempFile); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("export sqlite failed: %v", err))
		return
	}
	defer os.Remove(tempFile)

	data, err := os.ReadFile(tempFile)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read sqlite export failed")
		return
	}

	filename := fmt.Sprintf("subadmin-%d.db", time.Now().Unix())
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)

	s.writeSystemLog(r.Context(), "info", "backup", "export_sqlite", fmt.Sprintf("file=%s size=%d", filename, len(data)))
}

func (s *Server) collectBackupPayload(ctx context.Context) (*BackupPayload, error) {
	payload := &BackupPayload{}

	adminsRows, err := s.db.QueryContext(ctx, `SELECT id, username, password_hash, created_at FROM admins ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("query admins failed: %w", err)
	}
	for adminsRows.Next() {
		var row BackupAdmin
		if err := adminsRows.Scan(&row.ID, &row.Username, &row.PasswordHash, &row.CreatedAt); err != nil {
			adminsRows.Close()
			return nil, fmt.Errorf("scan admins failed: %w", err)
		}
		payload.Admins = append(payload.Admins, row)
	}
	adminsRows.Close()

	tokenRows, err := s.db.QueryContext(ctx, `SELECT id, token_id, admin_id, name, scope, enabled, last_used_at, expires_at, created_at FROM auth_tokens ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("query auth tokens failed: %w", err)
	}
	for tokenRows.Next() {
		var row BackupAuthToken
		var enabledInt int
		var lastUsed sql.NullTime
		if err := tokenRows.Scan(&row.ID, &row.TokenID, &row.AdminID, &row.Name, &row.Scope, &enabledInt, &lastUsed, &row.ExpiresAt, &row.CreatedAt); err != nil {
			tokenRows.Close()
			return nil, fmt.Errorf("scan auth tokens failed: %w", err)
		}
		row.Enabled = enabledInt == 1
		if lastUsed.Valid {
			row.LastUsedAt = &lastUsed.Time
		}
		payload.AuthTokens = append(payload.AuthTokens, row)
	}
	tokenRows.Close()

	upstreamRows, err := s.db.QueryContext(ctx, `SELECT id, name, url, enabled, refresh_interval, last_sync_at, last_status, cached_content, created_at FROM upstreams ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("query upstreams failed: %w", err)
	}
	for upstreamRows.Next() {
		var row BackupUpstream
		var enabledInt int
		var lastSync sql.NullTime
		if err := upstreamRows.Scan(&row.ID, &row.Name, &row.URL, &enabledInt, &row.RefreshInterval, &lastSync, &row.LastStatus, &row.CachedContent, &row.CreatedAt); err != nil {
			upstreamRows.Close()
			return nil, fmt.Errorf("scan upstreams failed: %w", err)
		}
		row.Enabled = enabledInt == 1
		if lastSync.Valid {
			row.LastSyncAt = &lastSync.Time
		}
		payload.Upstreams = append(payload.Upstreams, row)
	}
	upstreamRows.Close()

	nodeRows, err := s.db.QueryContext(ctx, `SELECT id, name, raw_uri, enabled, group_name, created_at, updated_at FROM manual_nodes ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("query nodes failed: %w", err)
	}
	for nodeRows.Next() {
		var row BackupNode
		var enabledInt int
		if err := nodeRows.Scan(&row.ID, &row.Name, &row.RawURI, &enabledInt, &row.GroupName, &row.CreatedAt, &row.UpdatedAt); err != nil {
			nodeRows.Close()
			return nil, fmt.Errorf("scan nodes failed: %w", err)
		}
		row.Enabled = enabledInt == 1
		payload.ManualNodes = append(payload.ManualNodes, row)
	}
	nodeRows.Close()

	settingRows, err := s.db.QueryContext(ctx, `SELECT key, value FROM settings ORDER BY key`)
	if err != nil {
		return nil, fmt.Errorf("query settings failed: %w", err)
	}
	for settingRows.Next() {
		var row BackupSetting
		if err := settingRows.Scan(&row.Key, &row.Value); err != nil {
			settingRows.Close()
			return nil, fmt.Errorf("scan settings failed: %w", err)
		}
		payload.Settings = append(payload.Settings, row)
	}
	settingRows.Close()

	snapshotRows, err := s.db.QueryContext(ctx, `SELECT id, kind, content, created_at, note FROM snapshots ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("query snapshots failed: %w", err)
	}
	for snapshotRows.Next() {
		var row BackupSnapshot
		if err := snapshotRows.Scan(&row.ID, &row.Kind, &row.Content, &row.CreatedAt, &row.Note); err != nil {
			snapshotRows.Close()
			return nil, fmt.Errorf("scan snapshots failed: %w", err)
		}
		payload.Snapshots = append(payload.Snapshots, row)
	}
	snapshotRows.Close()

	return payload, nil
}

func (s *Server) handleImportBackup(w http.ResponseWriter, r *http.Request) {
	var payload BackupPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid backup payload")
		return
	}

	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "start transaction failed")
		return
	}
	defer tx.Rollback()

	clearStatements := []string{
		`DELETE FROM admins`,
		`DELETE FROM auth_tokens`,
		`DELETE FROM upstreams`,
		`DELETE FROM manual_nodes`,
		`DELETE FROM settings`,
		`DELETE FROM snapshots`,
	}
	for _, stmt := range clearStatements {
		if _, err := tx.ExecContext(r.Context(), stmt); err != nil {
			writeError(w, http.StatusInternalServerError, "clear tables failed")
			return
		}
	}

	for _, row := range payload.Admins {
		if _, err := tx.ExecContext(
			r.Context(),
			`INSERT INTO admins(id, username, password_hash, created_at) VALUES(?, ?, ?, ?)`,
			row.ID,
			row.Username,
			row.PasswordHash,
			row.CreatedAt,
		); err != nil {
			writeError(w, http.StatusInternalServerError, "restore admins failed")
			return
		}
	}

	for _, row := range payload.AuthTokens {
		lastUsed := any(nil)
		if row.LastUsedAt != nil {
			lastUsed = *row.LastUsedAt
		}
		if _, err := tx.ExecContext(
			r.Context(),
			`INSERT INTO auth_tokens(id, token_id, admin_id, name, scope, enabled, last_used_at, expires_at, created_at)
			VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			row.ID,
			row.TokenID,
			row.AdminID,
			row.Name,
			row.Scope,
			boolToInt(row.Enabled),
			lastUsed,
			row.ExpiresAt,
			row.CreatedAt,
		); err != nil {
			writeError(w, http.StatusInternalServerError, "restore auth tokens failed")
			return
		}
	}

	for _, row := range payload.Upstreams {
		if _, err := tx.ExecContext(
			r.Context(),
			`INSERT INTO upstreams(id, name, url, enabled, refresh_interval, last_sync_at, last_status, cached_content, created_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			row.ID,
			row.Name,
			row.URL,
			boolToInt(row.Enabled),
			row.RefreshInterval,
			row.LastSyncAt,
			row.LastStatus,
			row.CachedContent,
			row.CreatedAt,
		); err != nil {
			writeError(w, http.StatusInternalServerError, "restore upstreams failed")
			return
		}
	}

	for _, row := range payload.ManualNodes {
		if _, err := tx.ExecContext(
			r.Context(),
			`INSERT INTO manual_nodes(id, name, raw_uri, enabled, group_name, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?, ?)`,
			row.ID,
			row.Name,
			row.RawURI,
			boolToInt(row.Enabled),
			row.GroupName,
			row.CreatedAt,
			row.UpdatedAt,
		); err != nil {
			writeError(w, http.StatusInternalServerError, "restore nodes failed")
			return
		}
	}

	for _, row := range payload.Settings {
		if _, err := tx.ExecContext(r.Context(), `INSERT INTO settings(key, value) VALUES(?, ?)`, row.Key, row.Value); err != nil {
			writeError(w, http.StatusInternalServerError, "restore settings failed")
			return
		}
	}

	for _, row := range payload.Snapshots {
		if _, err := tx.ExecContext(
			r.Context(),
			`INSERT INTO snapshots(id, kind, content, created_at, note) VALUES(?, ?, ?, ?, ?)`,
			row.ID,
			row.Kind,
			row.Content,
			row.CreatedAt,
			row.Note,
		); err != nil {
			writeError(w, http.StatusInternalServerError, "restore snapshots failed")
			return
		}
	}

	if err := tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, "commit restore failed")
		return
	}

	s.writeSystemLog(
		r.Context(),
		"info",
		"backup",
		"import",
		fmt.Sprintf(
			"admins=%d auth_tokens=%d upstreams=%d manual_nodes=%d settings=%d snapshots=%d",
			len(payload.Admins),
			len(payload.AuthTokens),
			len(payload.Upstreams),
			len(payload.ManualNodes),
			len(payload.Settings),
			len(payload.Snapshots),
		),
	)
	writeJSON(w, http.StatusOK, map[string]string{"message": "backup imported"})
}

func (s *Server) writeSyncLog(ctx context.Context, upstreamID int, upstreamName, triggerSource, status string, nodeCount int, durationMs int64, detail string) {
	_, err := s.db.ExecContext(
		ctx,
		`INSERT INTO sync_logs(upstream_id, upstream_name, trigger_source, status, node_count, duration_ms, detail, created_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
		upstreamID,
		strings.TrimSpace(upstreamName),
		strings.TrimSpace(triggerSource),
		strings.TrimSpace(status),
		nodeCount,
		durationMs,
		strings.TrimSpace(detail),
	)
	if err != nil {
		s.logger.Printf("write sync log failed: %v", err)
	}
}

func (s *Server) writeSystemLog(ctx context.Context, level, category, action, detail string) {
	s.writeSystemLogWithMeta(ctx, level, category, action, level, 0, detail)
}

func (s *Server) writeSystemLogWithMeta(ctx context.Context, level, category, action, result string, durationMs int64, detail string) {
	encoded := s.formatSystemLogDetail(ctx, category, action, result, durationMs, detail)
	_, err := s.db.ExecContext(
		ctx,
		`INSERT INTO system_logs(level, category, action, detail, created_at)
		VALUES(?, ?, ?, ?, CURRENT_TIMESTAMP)`,
		strings.TrimSpace(level),
		strings.TrimSpace(category),
		strings.TrimSpace(action),
		encoded,
	)
	if err != nil {
		s.logger.Printf("write system log failed: %v", err)
		return
	}
	s.logger.Printf("system_log %s", encoded)
}

func (s *Server) formatSystemLogDetail(ctx context.Context, category, action, result string, durationMs int64, detail string) string {
	payload := map[string]any{
		"request_id":  strings.TrimSpace(chimw.GetReqID(ctx)),
		"module":      strings.TrimSpace(category),
		"action":      strings.TrimSpace(action),
		"result":      strings.TrimSpace(result),
		"duration_ms": durationMs,
		"detail":      strings.TrimSpace(detail),
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return strings.TrimSpace(detail)
	}
	return string(raw)
}

func (s *Server) runAutoBackupIfDue(ctx context.Context, settings *Settings) error {
	if settings == nil || !settings.AutoBackupEnabled {
		return nil
	}

	lastRaw, err := s.getSettingValue(ctx, "auto_backup_last_at")
	if err != nil {
		return fmt.Errorf("read auto backup last time: %w", err)
	}
	if strings.TrimSpace(lastRaw) != "" {
		lastAt, parseErr := time.Parse(time.RFC3339, strings.TrimSpace(lastRaw))
		if parseErr == nil {
			interval := time.Duration(settings.AutoBackupIntervalHours) * time.Hour
			if interval <= 0 {
				interval = defaultAutoBackupHours * time.Hour
			}
			if time.Since(lastAt) < interval {
				return nil
			}
		}
	}

	if err := s.performAutoBackup(ctx, settings.AutoBackupKeep); err != nil {
		return err
	}
	return s.setSetting(ctx, "auto_backup_last_at", time.Now().UTC().Format(time.RFC3339))
}

func (s *Server) performAutoBackup(ctx context.Context, keep int) error {
	payload, err := s.collectBackupPayload(ctx)
	if err != nil {
		return fmt.Errorf("collect backup payload: %w", err)
	}

	dir := s.backupDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create backup dir: %w", err)
	}

	timestamp := time.Now().UTC().Format("20060102-150405")
	jsonPath := filepath.Join(dir, fmt.Sprintf("backup-%s.json", timestamp))
	jsonBody, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal backup payload: %w", err)
	}
	if err := os.WriteFile(jsonPath, jsonBody, 0o600); err != nil {
		return fmt.Errorf("write backup json: %w", err)
	}

	sqlitePath := filepath.Join(dir, fmt.Sprintf("backup-%s.db", timestamp))
	if err := s.createSQLiteSnapshot(ctx, sqlitePath); err != nil {
		return fmt.Errorf("write backup sqlite: %w", err)
	}

	if keep <= 0 {
		keep = defaultAutoBackupKeep
	}
	if err := cleanupBackupFiles(dir, ".json", keep); err != nil {
		s.logger.Printf("cleanup json backups failed: %v", err)
	}
	if err := cleanupBackupFiles(dir, ".db", keep); err != nil {
		s.logger.Printf("cleanup sqlite backups failed: %v", err)
	}

	s.writeSystemLog(ctx, "info", "backup", "auto_backup", fmt.Sprintf("json=%s sqlite=%s keep=%d", filepath.Base(jsonPath), filepath.Base(sqlitePath), keep))
	return nil
}

func (s *Server) createSQLiteSnapshot(ctx context.Context, destPath string) error {
	destPath = strings.TrimSpace(destPath)
	if destPath == "" {
		return errors.New("empty sqlite snapshot destination")
	}
	if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		return fmt.Errorf("create sqlite snapshot dir: %w", err)
	}
	if err := os.Remove(destPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove old sqlite snapshot: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `PRAGMA wal_checkpoint(FULL)`); err != nil {
		s.logger.Printf("sqlite checkpoint failed before snapshot: %v", err)
	}
	query := fmt.Sprintf("VACUUM INTO '%s'", strings.ReplaceAll(destPath, "'", "''"))
	if _, err := s.db.ExecContext(ctx, query); err != nil {
		return fmt.Errorf("vacuum into snapshot: %w", err)
	}
	return nil
}

func (s *Server) getSettingValue(ctx context.Context, key string) (string, error) {
	var value string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return value, nil
}

func (s *Server) backupDir() string {
	return filepath.Join(s.cfg.DataDir, "backups")
}

func cleanupBackupFiles(dir, suffix string, keep int) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	type fileMeta struct {
		path string
		time time.Time
	}
	files := make([]fileMeta, 0)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasPrefix(name, "backup-") || !strings.HasSuffix(strings.ToLower(name), strings.ToLower(suffix)) {
			continue
		}
		info, infoErr := entry.Info()
		if infoErr != nil {
			continue
		}
		files = append(files, fileMeta{
			path: filepath.Join(dir, name),
			time: info.ModTime(),
		})
	}
	sort.Slice(files, func(i, j int) bool {
		return files[i].time.After(files[j].time)
	})
	if keep < 0 {
		keep = 0
	}
	for idx := keep; idx < len(files); idx++ {
		_ = os.Remove(files[idx].path)
	}
	return nil
}

func generateTokenID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func (s *Server) readCache(target string) (string, error) {
	content, err := os.ReadFile(s.cacheFile(target))
	if err != nil {
		return "", err
	}
	return string(content), nil
}

func (s *Server) readCacheWithModTime(target string) (string, time.Time, error) {
	content, err := os.ReadFile(s.cacheFile(target))
	if err != nil {
		return "", time.Time{}, err
	}
	info, err := os.Stat(s.cacheFile(target))
	if err != nil {
		return string(content), time.Time{}, nil
	}
	return string(content), info.ModTime(), nil
}

func (s *Server) cacheFile(target string) string {
	filename := target + ".txt"
	if target == "clash" {
		filename = "clash.yaml"
	}
	if target == "singbox" {
		filename = "singbox.json"
	}
	return filepath.Join(s.cfg.CacheDir, filename)
}

func (s *Server) writeOutput(w http.ResponseWriter, r *http.Request, target, content string, lastModified time.Time) {
	if target == "clash" {
		w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	} else {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
	}

	if s.cfg.OutputETagEnabled {
		etag := buildOutputETag(content)
		w.Header().Set("ETag", etag)
		w.Header().Set("Cache-Control", s.outputCacheControl())
		if !lastModified.IsZero() {
			w.Header().Set("Last-Modified", lastModified.UTC().Format(http.TimeFormat))
		}
		if etagMatches(r.Header.Get("If-None-Match"), etag) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(content))
}

func (s *Server) buildAuthCookie(tokenValue string, expiresAt time.Time, clear bool) *http.Cookie {
	cookie := &http.Cookie{
		Name:     s.authCookieName,
		Value:    tokenValue,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.AuthCookieSecure,
		SameSite: parseCookieSameSite(s.cfg.AuthCookieSameSite),
	}
	if domain := strings.TrimSpace(s.cfg.AuthCookieDomain); domain != "" {
		cookie.Domain = domain
	}
	if clear {
		cookie.Expires = time.Unix(0, 0)
		cookie.MaxAge = -1
		return cookie
	}
	cookie.Expires = expiresAt
	return cookie
}

func parseCookieSameSite(raw string) http.SameSite {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteLaxMode
	}
}

func requestClientIP(r *http.Request) string {
	remote := strings.TrimSpace(r.RemoteAddr)
	if remote == "" {
		return "unknown"
	}
	host, _, err := net.SplitHostPort(remote)
	if err == nil && strings.TrimSpace(host) != "" {
		return strings.TrimSpace(host)
	}
	return remote
}

func normalizeLoginKey(raw string) string {
	normalized := strings.ToLower(strings.TrimSpace(raw))
	if normalized == "" {
		return "unknown"
	}
	return normalized
}

func joinLoginKey(ip, username string) string {
	return normalizeLoginKey(ip) + "|" + normalizeLoginKey(username)
}

func (s *Server) checkLoginAllowed(clientIP, username string) error {
	if !s.cfg.LoginProtectionEnabled {
		return nil
	}

	now := time.Now()
	window := s.loginRateWindow()
	maxIP := s.loginRateMaxIP()
	maxUser := s.loginRateMaxUser()
	keyIP := normalizeLoginKey(clientIP)
	keyUser := normalizeLoginKey(username)
	pairKey := joinLoginKey(clientIP, username)

	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	s.cleanupLoginStateLocked(now, window)

	if lockedUntil, ok := s.loginLocks[pairKey]; ok && now.Before(lockedUntil) {
		return fmt.Errorf("login temporarily locked, retry after %d seconds", secondsUntil(lockedUntil, now))
	}

	if maxIP > 0 {
		count, resetIn := bumpLoginWindowLocked(s.loginIPWindows, keyIP, now, window)
		if count > maxIP {
			return fmt.Errorf("too many login attempts from this IP, retry after %d seconds", secondsFromDuration(resetIn))
		}
	}
	if maxUser > 0 {
		count, resetIn := bumpLoginWindowLocked(s.loginUserWindow, keyUser, now, window)
		if count > maxUser {
			return fmt.Errorf("too many login attempts for this username, retry after %d seconds", secondsFromDuration(resetIn))
		}
	}

	return nil
}

func (s *Server) recordLoginFailure(clientIP, username string) (bool, int) {
	if !s.cfg.LoginProtectionEnabled {
		return false, 0
	}

	threshold := s.loginLockThreshold()
	if threshold <= 0 {
		return false, 0
	}

	now := time.Now()
	pairKey := joinLoginKey(clientIP, username)
	lockDuration := s.loginLockDuration()

	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	s.cleanupLoginStateLocked(now, s.loginRateWindow())

	failedCount := s.loginFailures[pairKey] + 1
	if failedCount >= threshold {
		lockUntil := now.Add(lockDuration)
		s.loginLocks[pairKey] = lockUntil
		delete(s.loginFailures, pairKey)
		return true, secondsUntil(lockUntil, now)
	}
	s.loginFailures[pairKey] = failedCount
	return false, 0
}

func (s *Server) recordLoginSuccess(clientIP, username string) {
	if !s.cfg.LoginProtectionEnabled {
		return
	}
	pairKey := joinLoginKey(clientIP, username)

	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	delete(s.loginFailures, pairKey)
	delete(s.loginLocks, pairKey)
}

func (s *Server) cleanupLoginStateLocked(now time.Time, window time.Duration) {
	for key, value := range s.loginIPWindows {
		if now.Sub(value.windowStart) >= window {
			delete(s.loginIPWindows, key)
		}
	}
	for key, value := range s.loginUserWindow {
		if now.Sub(value.windowStart) >= window {
			delete(s.loginUserWindow, key)
		}
	}
	for key, value := range s.loginLocks {
		if !now.Before(value) {
			delete(s.loginLocks, key)
		}
	}
}

func bumpLoginWindowLocked(windows map[string]loginAttemptWindow, key string, now time.Time, window time.Duration) (int, time.Duration) {
	entry, ok := windows[key]
	if !ok || now.Sub(entry.windowStart) >= window {
		entry = loginAttemptWindow{
			windowStart: now,
			count:       0,
		}
	}
	entry.count++
	windows[key] = entry
	resetIn := window - now.Sub(entry.windowStart)
	if resetIn < 0 {
		resetIn = 0
	}
	return entry.count, resetIn
}

func (s *Server) loginRateWindow() time.Duration {
	if s.cfg.LoginRateWindow <= 0 {
		return defaultLoginRateWindow
	}
	return s.cfg.LoginRateWindow
}

func (s *Server) loginRateMaxIP() int {
	if s.cfg.LoginRateMaxIP <= 0 {
		return defaultLoginRateMaxIP
	}
	return s.cfg.LoginRateMaxIP
}

func (s *Server) loginRateMaxUser() int {
	if s.cfg.LoginRateMaxUsername <= 0 {
		return defaultLoginRateMaxUser
	}
	return s.cfg.LoginRateMaxUsername
}

func (s *Server) loginLockThreshold() int {
	if s.cfg.LoginLockThreshold <= 0 {
		return defaultLoginLockThreshold
	}
	return s.cfg.LoginLockThreshold
}

func (s *Server) loginLockDuration() time.Duration {
	if s.cfg.LoginLockDuration <= 0 {
		return defaultLoginLockDuration
	}
	return s.cfg.LoginLockDuration
}

func (s *Server) outputCacheControl() string {
	value := strings.TrimSpace(s.cfg.OutputCacheControl)
	if value == "" {
		return defaultOutputCacheControl
	}
	return value
}

func (s *Server) syncMaxConcurrency() int {
	if s.cfg.SyncMaxConcurrency <= 0 {
		return defaultSyncMaxConcurrency
	}
	return s.cfg.SyncMaxConcurrency
}

func (s *Server) syncRetryMaxAttempts() int {
	if s.cfg.SyncRetryMaxAttempts <= 0 {
		return defaultSyncRetryAttempts
	}
	return s.cfg.SyncRetryMaxAttempts
}

func (s *Server) syncRetryBaseDelay() time.Duration {
	if s.cfg.SyncRetryBaseDelay <= 0 {
		return defaultSyncRetryBaseDelay
	}
	return s.cfg.SyncRetryBaseDelay
}

func (s *Server) syncRetryMaxDelay() time.Duration {
	if s.cfg.SyncRetryMaxDelay <= 0 {
		return defaultSyncRetryMaxDelay
	}
	return s.cfg.SyncRetryMaxDelay
}

func (s *Server) syncRetryDelay(retryCount int) time.Duration {
	delay := s.syncRetryBaseDelay()
	if retryCount <= 1 {
		return delay
	}
	maxDelay := s.syncRetryMaxDelay()
	for i := 1; i < retryCount; i++ {
		if delay >= maxDelay/2 {
			return maxDelay
		}
		delay *= 2
	}
	if delay > maxDelay {
		return maxDelay
	}
	return delay
}

func waitContext(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (s *Server) isRetryableSyncError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var retryableErr *retryableSyncError
	if errors.As(err, &retryableErr) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr)
}

func (s *Server) classifySyncError(err error) string {
	if err == nil {
		return "none"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	var statusErr *upstreamHTTPStatusError
	if errors.As(err, &statusErr) {
		switch {
		case statusErr.StatusCode == http.StatusTooManyRequests:
			return "upstream_rate_limited"
		case statusErr.StatusCode >= http.StatusInternalServerError:
			return "upstream_5xx"
		case statusErr.StatusCode >= http.StatusBadRequest:
			return "upstream_4xx"
		default:
			return "upstream_http_error"
		}
	}
	raw := strings.ToLower(err.Error())
	switch {
	case strings.Contains(raw, "subscription contains no nodes"):
		return "subscription_no_nodes"
	case strings.Contains(raw, "empty upstream url"):
		return "invalid_upstream_url"
	case strings.Contains(raw, "update upstream cache"):
		return "db_write_error"
	case strings.Contains(raw, "fetch upstream"):
		return "upstream_fetch_error"
	case strings.Contains(raw, "read upstream"):
		return "upstream_read_error"
	}
	if s.isRetryableSyncError(err) {
		return "transient_error"
	}
	return "unknown_error"
}

func buildOutputETag(content string) string {
	sum := sha256.Sum256([]byte(content))
	return fmt.Sprintf(`"%x"`, sum[:])
}

func etagMatches(ifNoneMatch, currentETag string) bool {
	header := strings.TrimSpace(ifNoneMatch)
	if header == "" {
		return false
	}
	if header == "*" {
		return true
	}
	normalizedCurrent := normalizeETag(currentETag)
	for _, token := range strings.Split(header, ",") {
		if normalizeETag(token) == normalizedCurrent {
			return true
		}
	}
	return false
}

func normalizeETag(value string) string {
	normalized := strings.TrimSpace(value)
	normalized = strings.TrimPrefix(normalized, "W/")
	normalized = strings.TrimPrefix(normalized, "w/")
	return strings.TrimSpace(normalized)
}

func secondsFromDuration(value time.Duration) int {
	seconds := int(math.Ceil(value.Seconds()))
	if seconds < 1 {
		return 1
	}
	return seconds
}

func secondsUntil(until, now time.Time) int {
	return secondsFromDuration(until.Sub(now))
}

func parseIDParam(r *http.Request, key string) (int, error) {
	value := chi.URLParam(r, key)
	id, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || id <= 0 {
		return 0, errors.New("invalid id")
	}
	return id, nil
}

func parseLimitQuery(value string) int {
	limit := defaultLogLimit
	if strings.TrimSpace(value) != "" {
		parsed, err := strconv.Atoi(strings.TrimSpace(value))
		if err == nil && parsed > 0 {
			limit = parsed
		}
	}
	if limit > maxLogLimit {
		return maxLogLimit
	}
	return limit
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if payload == nil {
		return
	}
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

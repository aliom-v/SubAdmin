package config

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ListenAddr             string
	DataDir                string
	DBPath                 string
	CacheDir               string
	JWTSecret              string
	TokenTTL               time.Duration
	AuthCookieName         string
	AuthCookieSecure       bool
	AuthCookieSameSite     string
	AuthCookieDomain       string
	LoginProtectionEnabled bool
	LoginRateWindow        time.Duration
	LoginRateMaxIP         int
	LoginRateMaxUsername   int
	LoginLockThreshold     int
	LoginLockDuration      time.Duration
	OutputETagEnabled      bool
	OutputCacheControl     string
	SyncMaxConcurrency     int
	SyncRetryMaxAttempts   int
	SyncRetryBaseDelay     time.Duration
	SyncRetryMaxDelay      time.Duration
	AdminUsername          string
	AdminPassword          string
	SublinkURL             string
	SublinkSourceBaseURL   string
	APITimeout             time.Duration
	HTTPTimeout            time.Duration
	DefaultCacheMode       bool
	DefaultCacheInterval   int
	SchedulerTickInterval  time.Duration
	SchedulerJobTimeout    time.Duration
}

func Load() *Config {
	dataDir := getenv("DATA_DIR", "/data")
	dbPath := getenv("DB_PATH", filepath.Join(dataDir, "subadmin.db"))
	cacheDir := getenv("CACHE_DIR", filepath.Join(dataDir, "cache"))

	return &Config{
		ListenAddr:             getenv("LISTEN_ADDR", ":8080"),
		DataDir:                dataDir,
		DBPath:                 dbPath,
		CacheDir:               cacheDir,
		JWTSecret:              getenv("JWT_SECRET", "change-this-in-production"),
		TokenTTL:               time.Duration(getint("TOKEN_TTL_HOURS", 24)) * time.Hour,
		AuthCookieName:         getenv("AUTH_COOKIE_NAME", "subadmin_token"),
		AuthCookieSecure:       getbool("AUTH_COOKIE_SECURE", false),
		AuthCookieSameSite:     getenv("AUTH_COOKIE_SAMESITE", "lax"),
		AuthCookieDomain:       getenv("AUTH_COOKIE_DOMAIN", ""),
		LoginProtectionEnabled: getbool("LOGIN_PROTECTION_ENABLED", true),
		LoginRateWindow:        time.Duration(getint("LOGIN_RATE_WINDOW_SECONDS", 60)) * time.Second,
		LoginRateMaxIP:         getint("LOGIN_RATE_MAX_IP", 30),
		LoginRateMaxUsername:   getint("LOGIN_RATE_MAX_USERNAME", 10),
		LoginLockThreshold:     getint("LOGIN_LOCK_THRESHOLD", 5),
		LoginLockDuration:      time.Duration(getint("LOGIN_LOCK_SECONDS", 300)) * time.Second,
		OutputETagEnabled:      getbool("OUTPUT_ETAG_ENABLED", true),
		OutputCacheControl:     getenv("OUTPUT_CACHE_CONTROL", "no-cache"),
		SyncMaxConcurrency:     getint("SYNC_MAX_CONCURRENCY", 3),
		SyncRetryMaxAttempts:   getint("SYNC_RETRY_MAX_ATTEMPTS", 3),
		SyncRetryBaseDelay:     time.Duration(getint("SYNC_RETRY_BASE_DELAY_MS", 500)) * time.Millisecond,
		SyncRetryMaxDelay:      time.Duration(getint("SYNC_RETRY_MAX_DELAY_MS", 5000)) * time.Millisecond,
		AdminUsername:          getenv("ADMIN_USERNAME", "admin"),
		AdminPassword:          getenv("ADMIN_PASSWORD", "admin123"),
		SublinkURL:             strings.TrimRight(getenv("SUBLINK_URL", "http://sublink:25500"), "/"),
		SublinkSourceBaseURL:   strings.TrimRight(getenv("SUBLINK_SOURCE_BASE_URL", "http://api:8080"), "/"),
		APITimeout:             time.Duration(getint("API_TIMEOUT_SECONDS", 300)) * time.Second,
		HTTPTimeout:            time.Duration(getint("HTTP_TIMEOUT_SECONDS", 20)) * time.Second,
		DefaultCacheMode:       getbool("DEFAULT_CACHE_MODE", true),
		DefaultCacheInterval:   getint("DEFAULT_CACHE_INTERVAL_MINUTES", 10),
		SchedulerTickInterval:  time.Duration(getint("SCHEDULER_TICK_SECONDS", 30)) * time.Second,
		SchedulerJobTimeout:    time.Duration(getint("SCHEDULER_JOB_TIMEOUT_SECONDS", 300)) * time.Second,
	}
}

func getenv(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func getint(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func getbool(key string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

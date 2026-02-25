package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"subadmin/backend/internal/config"
	"subadmin/backend/internal/db"
	"subadmin/backend/internal/server"
)

func main() {
	logger := log.New(os.Stdout, "[subadmin-api] ", log.LstdFlags|log.Lshortfile)
	cfg := config.Load()
	warnWeakCredentials(logger, cfg)

	database, err := db.Open(cfg.DBPath)
	if err != nil {
		logger.Fatalf("open db failed: %v", err)
	}
	defer database.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	if err := db.Init(ctx, database, cfg.AdminUsername, cfg.AdminPassword, cfg.DefaultCacheMode, cfg.DefaultCacheInterval); err != nil {
		cancel()
		logger.Fatalf("init db failed: %v", err)
	}
	cancel()

	apiServer, err := server.New(cfg, database, logger)
	if err != nil {
		logger.Fatalf("init server failed: %v", err)
	}

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           apiServer.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	schedulerCtx, schedulerCancel := context.WithCancel(context.Background())
	defer schedulerCancel()
	go apiServer.StartScheduler(schedulerCtx)

	go func() {
		logger.Printf("server listening on %s", cfg.ListenAddr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatalf("listen failed: %v", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	schedulerCancel()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Printf("shutdown error: %v", err)
	}
}

func warnWeakCredentials(logger *log.Logger, cfg *config.Config) {
	if isWeakJWTSecret(cfg.JWTSecret) {
		logger.Printf("WARNING: weak JWT secret detected. Set JWT_SECRET to a random string (>= 16 chars) before production.")
	}
	if isWeakAdminPassword(cfg.AdminPassword) {
		logger.Printf("WARNING: weak admin password detected. Set ADMIN_PASSWORD to a strong password before production.")
	}
}

func isWeakJWTSecret(secret string) bool {
	value := strings.TrimSpace(secret)
	if value == "" {
		return true
	}
	lower := strings.ToLower(value)
	if lower == "change-this-in-production" || lower == "changeme" || lower == "secret" {
		return true
	}
	return len(value) < 16
}

func isWeakAdminPassword(password string) bool {
	value := strings.TrimSpace(password)
	if value == "" {
		return true
	}
	lower := strings.ToLower(value)
	common := map[string]struct{}{
		"admin123": {},
		"admin":    {},
		"password": {},
		"123456":   {},
		"12345678": {},
		"qwerty":   {},
		"changeme": {},
	}
	if _, exists := common[lower]; exists {
		return true
	}
	return len(value) < 10
}

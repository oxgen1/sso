package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/oxgen1/sso/internal/config"
	"github.com/oxgen1/sso/internal/idp"
)

// serve runs the IdP until SIGINT or SIGTERM.
func serve(args []string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return serveUntil(ctx, args, os.Stderr)
}

// serveUntil runs the IdP until ctx is done. Logs are JSON for journald:
// audit records have "log":"audit", the rest "log":"diag".
func serveUntil(ctx context.Context, args []string, logOut io.Writer) error {
	if len(args) != 1 {
		return errors.New("serve: need one FILE")
	}
	cfg, err := config.Load(args[0])
	if err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(logOut, nil))
	h, err := idp.New(cfg, log, time.Now)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Addr:              cfg.Listen.String(),
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       time.Minute,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelError),
	}
	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return err
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	log.Info("listening", "log", "diag", "addr", ln.Addr().String(), "rp_id", cfg.RPID, "users", len(cfg.Users))
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return srv.Shutdown(shutdown)
}

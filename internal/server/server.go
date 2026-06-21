// Package server 实现 certsign HTTP 服务端.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"certsign/internal/config"
	"certsign/internal/session"
	"certsign/internal/signtool"
)

// Server 是 certsign HTTP 服务器.
type Server struct {
	cfg    config.ServerConfig
	sm     *session.Manager
	logger *slog.Logger
}

func New(cfg config.ServerConfig, sm *session.Manager, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	return &Server{cfg: cfg, sm: sm, logger: logger}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/sign", s.handleSign)
	mux.HandleFunc("/healthz", s.handleHealthz)
	return s.withLogging(mux)
}

// Run 启动 HTTP 服务, 阻塞直到 ctx 取消, 优雅关闭后清理会话.
func (s *Server) Run(ctx context.Context) error {
	const shutdownTimeout = 10 * time.Minute
	srv := &http.Server{
		Addr:              s.cfg.Bind,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		s.logger.Info("服务启动", "bind", s.cfg.Bind)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case <-ctx.Done():
	case err := <-errCh:
		return err
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		s.logger.Error("优雅关闭失败", "err", err)
	}
	closeCtx, closeCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer closeCancel()
	if err := s.sm.Shutdown(closeCtx); err != nil {
		s.logger.Error("会话关闭失败", "err", err)
	}
	return nil
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// Flush 委托给底层 ResponseWriter, 使 handleSign 中的 http.Flusher 断言成功.
func (s *statusWriter) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *Server) withLogging(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: 200}
		h.ServeHTTP(sw, r)
		s.logger.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", sw.status,
			"remote", r.RemoteAddr,
			"elapsed_ms", time.Since(start).Milliseconds(),
		)
	})
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleSign(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if !s.checkAuth(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	// 先占队列, 满则 503 (不进入 ndjson 流).
	release, err := s.sm.Reserve()
	if err != nil {
		s.logger.Warn("签名请求被拒: 队列满")
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "overloaded"})
		return
	}
	defer release()

	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid multipart: " + err.Error()})
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing file field"})
		return
	}
	defer file.Close()

	stageDir, err := os.MkdirTemp("", "certsign-upload-*")
	if err != nil {
		s.logger.Error("创建上传临时目录失败", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	defer os.RemoveAll(stageDir)

	name := filepath.Base(header.Filename)
	if name == "" || name == "." || strings.ContainsAny(name, `/\`) {
		name = "input"
	}
	stagedPath := filepath.Join(stageDir, name)
	out, err := os.Create(stagedPath)
	if err != nil {
		s.logger.Error("创建暂存文件失败", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	size, err := io.Copy(out, file)
	out.Close()
	if err != nil {
		s.logger.Error("暂存上传文件失败", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}

	s.logger.Info("文件上传完成", "filename", name, "size", size, "remote", r.RemoteAddr)

	// 进入 ndjson 流 (首条 Write 隐式触发 200).
	flusher, _ := w.(http.Flusher)
	nw := &ndjsonWriter{w: w, flusher: flusher}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	nw.event(map[string]any{
		"type":     "status",
		"phase":    "uploaded",
		"size":     size,
		"filename": name,
	})

	logCb := func(e signtool.LogEvent) {
		nw.event(map[string]any{
			"type":   "log",
			"stream": e.Stream,
			"line":   e.Line,
		})
	}
	statusCb := func(e session.Event) {
		nw.event(map[string]any{
			"type":  "status",
			"phase": e.Phase,
			"msg":   e.Msg,
		})
	}

	signStart := time.Now()
	res, signErr := s.sm.Sign(r.Context(), stagedPath, logCb, statusCb)
	signElapsed := time.Since(signStart).Milliseconds()
	if signErr != nil {
		s.writeSignError(nw, signErr)
		s.logger.Error("签名失败", "err", signErr, "remote", r.RemoteAddr)
		return
	}
	if res.ExitCode != 0 {
		nw.event(map[string]any{
			"type":        "error",
			"phase":       "signtool",
			"exit_code":   res.ExitCode,
			"stderr_tail": res.StderrTail,
		})
		s.logger.Error("signtool 执行失败",
			"exit_code", res.ExitCode,
			"stderr_tail", res.StderrTail,
			"remote", r.RemoteAddr,
		)
		os.RemoveAll(res.TmpDir)
		return
	}

	// 发送 done 事件 + 签名后原始字节.
	artifact, err := os.Open(res.SignedFile)
	if err != nil {
		nw.event(map[string]any{"type": "error", "phase": "internal", "msg": "open signed file: " + err.Error()})
		os.RemoveAll(res.TmpDir)
		return
	}
	fi, _ := artifact.Stat()

	s.logger.Info("签名完成",
		"filename", name,
		"signed_size", fi.Size(),
		"elapsed_ms", signElapsed,
		"remote", r.RemoteAddr,
	)

	s.logger.Info("开始传输签名文件",
		"filename", name,
		"size", fi.Size(),
		"remote", r.RemoteAddr,
	)

	nw.event(map[string]any{"type": "done", "bytes": fi.Size()})
	if _, err := io.Copy(w, artifact); err != nil {
		// 客户端可能在中途断开, 无需继续发送.
		s.logger.Warn("文件流传输中断", "err", err)
	}
	artifact.Close()
	if flusher != nil {
		flusher.Flush()
	}
	os.RemoveAll(res.TmpDir)
}

// writeSignError 将 Sign 错误映射为 ndjson error 事件.
func (s *Server) writeSignError(nw *ndjsonWriter, err error) {
	phase := "internal"
	msg := err.Error()
	switch {
	case errors.Is(err, session.ErrOverloaded):
		phase = "internal"
	case isLoginError(err):
		phase = "login"
	case errors.Is(err, context.DeadlineExceeded):
		phase = "internal"
		msg = "timeout"
	}
	nw.event(map[string]any{
		"type":  "error",
		"phase": phase,
		"msg":   msg,
	})
}

func isLoginError(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "autologin") || strings.Contains(msg, "re-login") || strings.Contains(msg, "session:")
}

func (s *Server) checkAuth(r *http.Request) bool {
	got := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(got) <= len(prefix) || !strings.EqualFold(got[:len(prefix)], prefix) {
		return false
	}
	return strings.TrimSpace(got[len(prefix):]) == s.cfg.Token
}

type ndjsonWriter struct {
	w       http.ResponseWriter
	flusher http.Flusher
}

func (nw *ndjsonWriter) event(v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	nw.w.Write(b)
	nw.w.Write([]byte("\n"))
	if nw.flusher != nil {
		nw.flusher.Flush()
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(body)
}

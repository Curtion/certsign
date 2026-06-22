// Package simplysign 管理 Certum SimplySignDesktop.exe.
// Autologin 启动 /autologin 进程, 在 SettleTimeout 窗口内观察存活: 进程退出=失败, 存活到窗口结束=成功.
// 用后台 goroutine reap, 不再轮询进程表; 登录成功永驻不退出.
package simplysign

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"time"

	"certsign/internal/config"
)

// DefaultSettleTimeout 是判定登录成功的默认 settle 窗口.
const DefaultSettleTimeout = 20 * time.Second

// Manager 管理 SimplySign 会话的启动和关闭.
type Manager struct {
	exe           string
	email         string
	SettleTimeout time.Duration
	logger        *slog.Logger
}

func New(cfg config.SimplySignConfig, logger *slog.Logger) *Manager {
	m := &Manager{
		exe:           cfg.Exe,
		email:         cfg.Email,
		SettleTimeout: DefaultSettleTimeout,
		logger:        logger,
	}
	if m.logger == nil {
		m.logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	if cfg.SettleTimeout > 0 {
		m.SettleTimeout = cfg.SettleTimeout
	}
	return m
}

// Autologin 启动 SimplySignDesktop /autologin, 在 settle 窗口内判断登录成败.
// alive=true 表示进程存活到窗口结束 (登录成功); alive=false 表示进程退出 (失败).
// 用 exec.Command 而非 CommandContext, 避免成功路径的进程被 ctx 误杀.
func (m *Manager) Autologin(ctx context.Context, otp string) (alive bool, err error) {
	m.logger.Info("启动 SimplySign autologin")
	cmd := exec.Command(m.exe, "/autologin", m.email, otp)
	if err := cmd.Start(); err != nil {
		return false, fmt.Errorf("simplysign: 启动 autologin 失败: %w", err)
	}

	// 后台 reap, 不阻塞主流程.
	waitCh := make(chan error, 1)
	go func() {
		waitCh <- cmd.Wait()
	}()

	settle := time.NewTimer(m.SettleTimeout)
	defer settle.Stop()

	select {
	case <-waitCh:
		m.logger.Debug("autologin 进程退出")
		return false, nil
	case <-settle.C:
		m.logger.Info("autologin settle 通过")
		return true, nil
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		<-waitCh
		m.logger.Warn("autologin 上下文取消", "err", ctx.Err())
		return false, ctx.Err()
	}
}

// Close 启动 SimplySignDesktop /close 销毁云证书会话. 阻塞至命令返回.
func (m *Manager) Close(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, m.exe, "/close")
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("simplysign: 启动 /close 失败: %w", err)
	}
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("simplysign: /close 失败: %w", err)
	}
	return nil
}

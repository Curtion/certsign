package simplysign

import (
	"context"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"certsign/internal/config"
	"certsign/internal/testutil"
)

// newManager 构建使用 fake 二进制的 Manager, settle 已缩短.
func newManager(t *testing.T, settle time.Duration) *Manager {
	t.Helper()
	fakes := testutil.BuildFakes(t)
	m := New(config.SimplySignConfig{
		Exe:   fakes.Simplysign,
		Email: "user@example.com",
	})
	m.SettleTimeout = settle
	t.Cleanup(func() {
		_ = exec.Command("taskkill", "/IM", filepath.Base(fakes.Simplysign), "/F").Run()
	})
	return m
}

// TestAutologin_Alive: 进程常驻不退出 → settle 结束判成功.
func TestAutologin_Alive(t *testing.T) {
	testutil.Env(t,
		"FAKESIMPLYSIGN_MODE", "alive",
		"FAKESIMPLYSIGN_ALIVE_MS", "5000",
	)
	m := newManager(t, 300*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	alive, err := m.Autologin(ctx, "123456")
	if err != nil {
		t.Fatalf("Autologin: %v", err)
	}
	if !alive {
		t.Error("expected alive=true when trigger process stays alive past settle window")
	}
}

// TestAutologin_OtpFail: 进程在 settle 内退出 → 判失败.
func TestAutologin_OtpFail(t *testing.T) {
	testutil.Env(t,
		"FAKESIMPLYSIGN_MODE", "delayed",
		"FAKESIMPLYSIGN_DELAY_MS", "100",
	)
	m := newManager(t, 500*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	alive, err := m.Autologin(ctx, "wrong-otp")
	if err != nil {
		t.Fatalf("Autologin: %v", err)
	}
	if alive {
		t.Error("expected alive=false when trigger process exits within settle window (OTP error)")
	}
}

// TestAutologin_TriggerFail: 立即非 0 退出 → 立即判失败.
func TestAutologin_TriggerFail(t *testing.T) {
	testutil.Env(t, "FAKESIMPLYSIGN_MODE", "exit_nonzero")
	m := newManager(t, 500*time.Millisecond)

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	alive, err := m.Autologin(ctx, "123456")
	if err != nil {
		t.Fatalf("Autologin: %v", err)
	}
	if alive {
		t.Error("expected alive=false when trigger exits non-zero immediately")
	}
	if elapsed := time.Since(start); elapsed > 300*time.Millisecond {
		t.Errorf("expected fast fail on non-zero exit, took %v", elapsed)
	}
}

// TestAutologin_Boundary: 进程延迟退出跨过 settle 边界.
func TestAutologin_Boundary(t *testing.T) {
	testutil.Env(t,
		"FAKESIMPLYSIGN_MODE", "delayed",
		"FAKESIMPLYSIGN_DELAY_MS", "400",
	)
	m := newManager(t, 300*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	alive, err := m.Autologin(ctx, "123456")
	if err != nil {
		t.Fatalf("Autologin: %v", err)
	}
	if !alive {
		t.Error("expected alive=true when settle timer fires before process exits")
	}
}

func TestClose(t *testing.T) {
	m := newManager(t, 500*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := m.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestAutologin_ContextCancelled: settle 内 ctx 取消 → 返回 err 并清理进程.
func TestAutologin_ContextCancelled(t *testing.T) {
	testutil.Env(t,
		"FAKESIMPLYSIGN_MODE", "alive",
		"FAKESIMPLYSIGN_ALIVE_MS", "5000",
	)
	m := newManager(t, 5*time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()

	_, err := m.Autologin(ctx, "123456")
	if err == nil {
		t.Error("expected context cancellation error")
	}
}

package session

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"certsign/internal/signtool"
	"certsign/internal/totp"
)

// ---------- fake ----------

type fakeResult struct {
	exitCode int
	stderr   string
	err      error
	delay    time.Duration
}

type fakeSigner struct {
	mu            sync.Mutex
	script        []fakeResult
	calls         int32
	tmpDirs       []string
	overlap       int32
	curConcurrent int32
	releaseCh     chan struct{}
}

func (f *fakeSigner) Sign(ctx context.Context, src string, emit func(signtool.LogEvent)) (*signtool.Result, error) {
	cur := atomic.AddInt32(&f.curConcurrent, 1)
	if cur > 1 {
		atomic.StoreInt32(&f.overlap, cur)
	}
	defer atomic.AddInt32(&f.curConcurrent, -1)

	idx := int(atomic.AddInt32(&f.calls, 1)) - 1
	f.mu.Lock()
	var r fakeResult
	if idx < len(f.script) {
		r = f.script[idx]
	}
	f.mu.Unlock()

	if r.delay > 0 {
		select {
		case <-time.After(r.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if f.releaseCh != nil {
		<-f.releaseCh
	}

	if emit != nil {
		emit(signtool.LogEvent{Stream: "stdout", Line: "fake signer line"})
	}
	if r.err != nil {
		return nil, r.err
	}

	tmpDir, err := os.MkdirTemp("", "fakesigner-*")
	if err != nil {
		return nil, err
	}
	dst := filepath.Join(tmpDir, filepath.Base(src))
	if err := copyContents(src, dst); err != nil {
		os.RemoveAll(tmpDir)
		return nil, err
	}
	if err := os.WriteFile(dst, append(readFile(dst), []byte("SIGNED")...), 0o644); err != nil {
		os.RemoveAll(tmpDir)
		return nil, err
	}
	f.mu.Lock()
	f.tmpDirs = append(f.tmpDirs, tmpDir)
	f.mu.Unlock()

	if r.exitCode != 0 {
		os.RemoveAll(tmpDir)
		return &signtool.Result{ExitCode: r.exitCode, StderrTail: r.stderr}, nil
	}
	return &signtool.Result{ExitCode: 0, SignedFile: dst, TmpDir: tmpDir}, nil
}

func (f *fakeSigner) callCount() int { return int(atomic.LoadInt32(&f.calls)) }

type fakeSimply struct {
	mu               sync.Mutex
	aliveOTP         map[string]bool
	autologinN       int32
	closeN           int32
	autologinErr     error
	autologinCtxDone int32
}

func (f *fakeSimply) Autologin(ctx context.Context, otp string) (bool, error) {
	atomic.AddInt32(&f.autologinN, 1)
	if ctx.Err() != nil {
		atomic.StoreInt32(&f.autologinCtxDone, 1)
	}
	f.mu.Lock()
	alive := f.aliveOTP[otp]
	err := f.autologinErr
	f.mu.Unlock()
	return alive, err
}

func (f *fakeSimply) Close(ctx context.Context) error {
	atomic.AddInt32(&f.closeN, 1)
	return nil
}

// ---------- 辅助函数 ----------

func testSecret() []byte { return []byte("12345678901234567890123456789012") }

func newManager(s SimplySignClient, signer Signer) *Manager {
	return New(s, signer, totp.Config{Secret: testSecret(), Digits: 6, Period: 30}, context.Background(), nil)
}

func writeFile(t *testing.T, body string) string {
	t.Helper()
	d := t.TempDir()
	p := filepath.Join(d, "in.bin")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func copyContents(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

func readFile(p string) []byte {
	b, _ := os.ReadFile(p)
	return b
}

func otpFor(t int64) string {
	return totp.Generate(testSecret(), uint64(t/30), 6)
}

func TestSign_HappyPath_LogsInOnce(t *testing.T) {
	signer := &fakeSigner{script: []fakeResult{{}}}
	t0 := time.Now().Unix()
	simply := &fakeSimply{aliveOTP: map[string]bool{otpFor(t0): true}}
	m := newManager(simply, signer)
	src := writeFile(t, "hello")

	release, err := m.Reserve()
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	defer release()
	res, err := m.Sign(context.Background(), src, nil, nil)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	defer os.RemoveAll(res.TmpDir)

	if res.ExitCode != 0 || res.SignedFile == "" {
		t.Fatalf("bad result: %+v", res)
	}
	if m.State() != LoggedIn {
		t.Errorf("state: %s, want LoggedIn", m.State())
	}
	if signer.callCount() != 1 {
		t.Errorf("signer calls: %d", signer.callCount())
	}
	if got := atomic.LoadInt32(&simply.autologinN); got != 1 {
		t.Errorf("autologin calls: %d, want 1", got)
	}
}

func TestSign_ThreeValueTOTP_SecondCounterWorks(t *testing.T) {
	signer := &fakeSigner{script: []fakeResult{{}}}
	t0 := time.Now().Unix()
	simply := &fakeSimply{aliveOTP: map[string]bool{otpFor(t0 - 30): true}}
	m := newManager(simply, signer)
	src := writeFile(t, "hello")

	release, err := m.Reserve()
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	defer release()
	res, err := m.Sign(context.Background(), src, nil, nil)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	defer os.RemoveAll(res.TmpDir)
	if m.State() != LoggedIn {
		t.Errorf("state: %s", m.State())
	}
	if got := atomic.LoadInt32(&simply.autologinN); got < 2 {
		t.Errorf("autologin calls: %d, want >=2", got)
	}
}

func TestSign_AllThreeFail_ReturnsError(t *testing.T) {
	signer := &fakeSigner{script: []fakeResult{{}}}
	simply := &fakeSimply{aliveOTP: map[string]bool{}}
	m := newManager(simply, signer)
	src := writeFile(t, "hello")

	release, _ := m.Reserve()
	defer release()
	_, err := m.Sign(context.Background(), src, nil, nil)
	if err == nil {
		t.Fatal("expected login error")
	}
	if m.State() != Uninit {
		t.Errorf("state: %s, want Uninit", m.State())
	}
	if signer.callCount() != 0 {
		t.Errorf("signer should not run on login failure: %d", signer.callCount())
	}
	if got := atomic.LoadInt32(&simply.autologinN); got != 3 {
		t.Errorf("autologin calls: %d, want 3", got)
	}
}

func TestSign_AnyFailure_TriggersReloginAndRetry(t *testing.T) {
	signer := &fakeSigner{script: []fakeResult{
		{exitCode: 1, stderr: "SignTool Error: No certificates were found that met all the given criteria."},
		{}, // 重试成功
	}}
	t0 := time.Now().Unix()
	simply := &fakeSimply{aliveOTP: map[string]bool{otpFor(t0): true}}
	m := newManager(simply, signer)
	src := writeFile(t, "hello")

	release, _ := m.Reserve()
	defer release()
	res, err := m.Sign(context.Background(), src, nil, nil)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	defer os.RemoveAll(res.TmpDir)

	if res.ExitCode != 0 {
		t.Fatalf("retry should succeed: %+v", res)
	}
	if signer.callCount() != 2 {
		t.Errorf("signer calls: %d, want 2", signer.callCount())
	}
	if got := atomic.LoadInt32(&simply.closeN); got != 1 {
		t.Errorf("close calls: %d, want 1", got)
	}
	if m.State() != LoggedIn {
		t.Errorf("state: %s, want LoggedIn", m.State())
	}
}

func TestSign_AnyFailure_NonCertErrorAlsoRelogins(t *testing.T) {
	// 非证书/会话类错误 (如文件占用) 也应触发重登, 因为重登无害, 且避免漏判会话失效.
	signer := &fakeSigner{script: []fakeResult{
		{exitCode: 1, stderr: "some unrelated error"},
		{}, // 重试成功
	}}
	t0 := time.Now().Unix()
	simply := &fakeSimply{aliveOTP: map[string]bool{otpFor(t0): true}}
	m := newManager(simply, signer)
	src := writeFile(t, "hello")

	release, _ := m.Reserve()
	defer release()
	res, err := m.Sign(context.Background(), src, nil, nil)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	defer os.RemoveAll(res.TmpDir)
	if res.ExitCode != 0 {
		t.Errorf("retry should succeed: %+v", res)
	}
	if signer.callCount() != 2 {
		t.Errorf("signer calls: %d, want 2", signer.callCount())
	}
	if got := atomic.LoadInt32(&simply.closeN); got != 1 {
		t.Errorf("close calls: %d, want 1", got)
	}
}

func TestSign_RetryStillFails_ReturnsSecondResult(t *testing.T) {
	// 重登后第二次签名仍失败: 透传第二次结果, 不再继续重登.
	signer := &fakeSigner{script: []fakeResult{
		{exitCode: 1, stderr: "first failure"},
		{exitCode: 2, stderr: "second failure"},
	}}
	t0 := time.Now().Unix()
	simply := &fakeSimply{aliveOTP: map[string]bool{otpFor(t0): true}}
	m := newManager(simply, signer)
	src := writeFile(t, "hello")

	release, _ := m.Reserve()
	defer release()
	res, err := m.Sign(context.Background(), src, nil, nil)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if res.ExitCode != 2 || res.StderrTail != "second failure" {
		t.Errorf("want second failure result, got %+v", res)
	}
	if signer.callCount() != 2 {
		t.Errorf("signer calls: %d, want 2 (只重试一次)", signer.callCount())
	}
	if got := atomic.LoadInt32(&simply.closeN); got != 1 {
		t.Errorf("close calls: %d, want 1", got)
	}
}

func TestEnsureLoggedIn_SingleflightDedup(t *testing.T) {
	signer := &fakeSigner{}
	t0 := time.Now().Unix()
	simply := &fakeSimply{aliveOTP: map[string]bool{otpFor(t0): true}}
	m := newManager(simply, signer)

	const n = 50
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_ = m.ensureLoggedIn(context.Background(), nil, false)
		}()
	}
	close(start)
	wg.Wait()

	if got := atomic.LoadInt32(&simply.autologinN); got != 1 {
		t.Errorf("autologin calls: %d, want 1 (dedup)", got)
	}
	if m.State() != LoggedIn {
		t.Errorf("state: %s", m.State())
	}
}

func TestSign_SerializesSigning(t *testing.T) {
	signer := &fakeSigner{
		script: []fakeResult{{delay: 50 * time.Millisecond}, {delay: 50 * time.Millisecond}},
	}
	t0 := time.Now().Unix()
	simply := &fakeSimply{aliveOTP: map[string]bool{otpFor(t0): true}}
	m := newManager(simply, signer)
	src := writeFile(t, "hello")

	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			release, _ := m.Reserve()
			defer release()
			res, err := m.Sign(context.Background(), src, nil, nil)
			if err == nil {
				os.RemoveAll(res.TmpDir)
			}
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt32(&signer.overlap); got > 1 {
		t.Errorf("signer ran concurrently: max overlap %d, want <=1", got)
	}
}

func TestReserve_QueueLimitRejects(t *testing.T) {
	signer := &fakeSigner{}
	t0 := time.Now().Unix()
	simply := &fakeSimply{aliveOTP: map[string]bool{otpFor(t0): true}}
	m := newManager(simply, signer)

	const total = 1 + MaxQueue + 2 // 1 active + MaxQueue waiting + 2 overflow
	releases := make([]func(), 0, 1+MaxQueue)
	var mu sync.Mutex
	var overloaded int32
	var wg sync.WaitGroup
	for i := 0; i < total; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rel, err := m.Reserve()
			if errors.Is(err, ErrOverloaded) {
				atomic.AddInt32(&overloaded, 1)
				return
			}
			mu.Lock()
			releases = append(releases, rel)
			mu.Unlock()
		}()
	}
	wg.Wait()

	for _, r := range releases {
		r()
	}

	if got := atomic.LoadInt32(&overloaded); got != 2 {
		t.Errorf("overloaded: %d, want 2", got)
	}
}

// TestSign_RequestCancelDoesNotAbortLogin 验证客户端断开不终止登录, 取消的请求快速失败.
func TestSign_RequestCancelDoesNotAbortLogin(t *testing.T) {
	signer := &fakeSigner{}
	t0 := time.Now().Unix()
	simply := &fakeSimply{aliveOTP: map[string]bool{otpFor(t0): true}}
	m := newManager(simply, signer)
	src := writeFile(t, "hello")

	const n = 10
	var wg sync.WaitGroup
	start := make(chan struct{})

	var cancelledErr, successCount int32
	srcPath := src
	for i := 0; i < n; i++ {
		cancelled := i%2 != 0
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			<-start

			ctx, cancel := context.WithCancel(context.Background())
			if cancelled {
				cancel()
			} else {
				defer cancel()
			}

			release, err := m.Reserve()
			if err != nil {
				return
			}
			defer release()

			res, err := m.Sign(ctx, srcPath, nil, nil)
			if cancelled {
				if err != nil {
					atomic.AddInt32(&cancelledErr, 1)
				}
				return
			}
			if err == nil {
				atomic.AddInt32(&successCount, 1)
				os.RemoveAll(res.TmpDir)
			}
		}(i)
	}
	close(start)
	wg.Wait()

	if got := atomic.LoadInt32(&simply.autologinN); got != 1 {
		t.Errorf("autologin calls: %d, want 1 (dedup, not aborted by request cancel)", got)
	}
	if got := atomic.LoadInt32(&simply.autologinCtxDone); got != 0 {
		t.Error("autologinCtxDone != 0: Autologin ctx was cancelled, but should receive appCtx")
	}
	if m.State() != LoggedIn {
		t.Errorf("state: %s, want LoggedIn", m.State())
	}

	if got := atomic.LoadInt32(&cancelledErr); got != int32(n/2) {
		t.Errorf("cancelled requests that got error: %d, want %d", got, n/2)
	}
	if got := atomic.LoadInt32(&successCount); got != int32(n/2) {
		t.Errorf("non-cancelled requests succeeded: %d, want %d", got, n/2)
	}
}

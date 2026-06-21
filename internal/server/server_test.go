package server_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"certsign/internal/config"
	"certsign/internal/server"
	"certsign/internal/session"
	"certsign/internal/signtool"
	"certsign/internal/totp"
)

type fakeSigner struct {
	mu      sync.Mutex
	script  []fakeResult
	calls   int
	tmpDirs []string
}

type fakeResult struct {
	exitCode int
	stderr   string
	marker   string // 追加到签名文件的内容, 默认 "SIGNED"
	delay    time.Duration
}

func (f *fakeSigner) Sign(ctx context.Context, src string, emit func(signtool.LogEvent)) (*signtool.Result, error) {
	f.mu.Lock()
	f.calls++
	idx := f.calls - 1
	var r fakeResult
	if n := len(f.script); n > 0 {
		if idx >= n {
			idx = n - 1
		}
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
	if emit != nil {
		emit(signtool.LogEvent{Stream: "stdout", Line: "signing line one"})
		emit(signtool.LogEvent{Stream: "stderr", Line: "stderr line"})
	}

	tmpDir, err := os.MkdirTemp("", "fakesigner-*")
	if err != nil {
		return nil, err
	}
	dst := filepath.Join(tmpDir, filepath.Base(src))
	if err := copyFile(src, dst); err != nil {
		os.RemoveAll(tmpDir)
		return nil, err
	}
	marker := r.marker
	if marker == "" {
		marker = "SIGNED"
	}
	b, _ := os.ReadFile(dst)
	os.WriteFile(dst, append(b, []byte(marker)...), 0o644)
	f.mu.Lock()
	f.tmpDirs = append(f.tmpDirs, tmpDir)
	f.mu.Unlock()

	if r.exitCode != 0 {
		os.RemoveAll(tmpDir)
		return &signtool.Result{ExitCode: r.exitCode, StderrTail: r.stderr}, nil
	}
	return &signtool.Result{ExitCode: 0, SignedFile: dst, TmpDir: tmpDir}, nil
}

type fakeSimply struct {
	mu       sync.Mutex
	aliveOTP map[string]bool
	autoN    int
	closeN   int
}

func (f *fakeSimply) Autologin(ctx context.Context, otp string) (bool, error) {
	f.mu.Lock()
	f.autoN++
	alive := f.aliveOTP[otp]
	f.mu.Unlock()
	return alive, nil
}
func (f *fakeSimply) Close(ctx context.Context) error {
	f.mu.Lock()
	f.closeN++
	f.mu.Unlock()
	return nil
}

func copyFile(src, dst string) error {
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

// setup 构造基于 fake 的服务端.
func setup(t *testing.T, script []fakeResult) (*httptest.Server, *fakeSigner, *fakeSimply, string) {
	t.Helper()
	signer := &fakeSigner{script: script}
	t0 := time.Now().Unix()
	simply := &fakeSimply{aliveOTP: map[string]bool{
		totp.Generate([]byte("12345678901234567890123456789012"), uint64(t0/30), 6): true,
	}}
	sm := session.New(simply, signer, totp.Config{
		Secret: []byte("12345678901234567890123456789012"),
		Digits: 6, Period: 30,
	}, context.Background(), nil)
	srv := server.New(config.ServerConfig{Bind: "127.0.0.1:0", Token: "tok"}, sm, nil)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() {
		ts.Close()
		signer.mu.Lock()
		for _, d := range signer.tmpDirs {
			os.RemoveAll(d)
		}
		signer.mu.Unlock()
	})
	return ts, signer, simply, "tok"
}

func uploadBody(t *testing.T, filename, content string) (*bytes.Buffer, string) {
	t.Helper()
	body := &bytes.Buffer{}
	mw := multipart.NewWriter(body)
	part, err := mw.CreateFormFile("file", filename)
	if err != nil {
		t.Fatal(err)
	}
	part.Write([]byte(content))
	mw.Close()
	return body, mw.FormDataContentType()
}

// readResponse 解析 ndjson 响应, 返回事件列表和签名后原始字节.
func readResponse(t *testing.T, body io.Reader) ([]map[string]any, []byte) {
	t.Helper()
	br := bufio.NewReader(body)
	var events []map[string]any
	var doneBytes int64 = -1
	for doneBytes < 0 {
		line, err := br.ReadBytes('\n')
		if err != nil {
			t.Fatalf("read ndjson line: %v (line=%q)", err, line)
		}
		var ev map[string]any
		if err := json.Unmarshal(line, &ev); err != nil {
			t.Fatalf("unmarshal event %q: %v", line, err)
		}
		events = append(events, ev)
		if ev["type"] == "done" {
			if v, ok := ev["bytes"].(float64); ok {
				doneBytes = int64(v)
			}
		}
		if ev["type"] == "error" {
			// error 后无文件内容, 直接返回已有数据.
			return events, nil
		}
	}
	raw := make([]byte, doneBytes)
	if _, err := io.ReadFull(br, raw); err != nil {
		t.Fatalf("read artifact (%d bytes): %v", doneBytes, err)
	}
	return events, raw
}

func TestSign_HappyPath(t *testing.T) {
	ts, signer, simply, token := setup(t, []fakeResult{{}})
	body, ct := uploadBody(t, "app.bin", "PAYLOAD")

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/sign", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "application/x-ndjson") {
		t.Errorf("content-type: %q", got)
	}
	events, raw := readResponse(t, resp.Body)

	if events[0]["type"] != "status" || events[0]["phase"] != "uploaded" {
		t.Errorf("first event: %+v", events[0])
	}
	last := events[len(events)-1]
	if last["type"] != "done" {
		t.Errorf("last event: %+v", last)
	}
	if !bytes.Equal(raw, []byte("PAYLOAD"+"SIGNED")) {
		t.Errorf("artifact mismatch: %q", raw)
	}
	if signer.calls != 1 {
		t.Errorf("signer calls: %d", signer.calls)
	}
	if simply.closeN != 0 {
		t.Errorf("unexpected close: %d", simply.closeN)
	}
}

func TestSign_Unauthorized(t *testing.T) {
	ts, _, _, _ := setup(t, []fakeResult{{}})
	body, ct := uploadBody(t, "app.bin", "x")
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/sign", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer wrong")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 401 {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	var m map[string]string
	json.NewDecoder(resp.Body).Decode(&m)
	if m["error"] != "unauthorized" {
		t.Errorf("body: %v", m)
	}
}

func TestSign_MissingFile(t *testing.T) {
	ts, _, _, token := setup(t, []fakeResult{{}})
	body := &bytes.Buffer{}
	mw := multipart.NewWriter(body)
	mw.Close()
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/sign", body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("status: %d", resp.StatusCode)
	}
}

func TestSign_SigntoolFailure_RetriesAndForwardsSecondResult(t *testing.T) {
	// 任意 signtool 失败都会触发重登重试一次; 两次都失败时透传第二次结果.
	ts, signer, simply, token := setup(t, []fakeResult{
		{exitCode: 1, stderr: "first failure"},
		{exitCode: 2, stderr: "second failure"},
	})
	body, ct := uploadBody(t, "app.bin", "PAYLOAD")
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/sign", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	events, raw := readResponse(t, resp.Body)
	last := events[len(events)-1]
	if last["type"] != "error" {
		t.Fatalf("expected error event, got %+v", last)
	}
	if last["phase"] != "signtool" {
		t.Errorf("phase: %v", last["phase"])
	}
	if last["exit_code"].(float64) != 2 {
		t.Errorf("exit_code: %v, want 2 (透传第二次)", last["exit_code"])
	}
	if !strings.Contains(last["stderr_tail"].(string), "second failure") {
		t.Errorf("stderr_tail: %v, want second failure", last["stderr_tail"])
	}
	if raw != nil {
		t.Errorf("no artifact expected on error, got %d bytes", len(raw))
	}
	if signer.calls != 2 {
		t.Errorf("signer calls: %d, want 2 (重试一次)", signer.calls)
	}
	if simply.closeN != 1 {
		t.Errorf("close calls: %d, want 1", simply.closeN)
	}
}

func TestSign_LogLinesForwarded(t *testing.T) {
	ts, _, _, token := setup(t, []fakeResult{{}})
	body, ct := uploadBody(t, "app.bin", "x")
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/sign", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	events, _ := readResponse(t, resp.Body)
	var logs []map[string]any
	for _, e := range events {
		if e["type"] == "log" {
			logs = append(logs, e)
		}
	}
	if len(logs) < 2 {
		t.Errorf("expected >=2 log events, got %d", len(logs))
	}
	streams := map[string]bool{}
	for _, l := range logs {
		streams[l["stream"].(string)] = true
	}
	if !streams["stdout"] || !streams["stderr"] {
		t.Errorf("missing streams: %v", streams)
	}
}

func TestSign_OverloadedReturns503(t *testing.T) {
	script := []fakeResult{{delay: 150 * time.Millisecond}}
	ts, _, _, token := setup(t, script)

	const total = 1 + session.MaxQueue + 3 // 1 活跃 + MaxQueue 等待 + 3 溢出
	var wg sync.WaitGroup
	var overloaded, ok int32
	for i := 0; i < total; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			body, ct := uploadBody(t, "app.bin", "x")
			req, _ := http.NewRequest(http.MethodPost, ts.URL+"/sign", body)
			req.Header.Set("Content-Type", ct)
			req.Header.Set("Authorization", "Bearer "+token)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			io.Copy(io.Discard, resp.Body)
			switch resp.StatusCode {
			case 503:
				atomic.AddInt32(&overloaded, 1)
			case 200:
				atomic.AddInt32(&ok, 1)
			}
		}()
	}

	// 3 个溢出请求立即被拒, 其余通过 signMu 以有界延迟序列化.
	doneCh := make(chan struct{})
	go func() { wg.Wait(); close(doneCh) }()
	select {
	case <-doneCh:
	case <-time.After(15 * time.Second):
		t.Fatal("timed out waiting for overloaded test to settle")
	}

	if got := atomic.LoadInt32(&overloaded); got != 3 {
		t.Errorf("overloaded 503 count: %d, want 3", got)
	}
	if got := atomic.LoadInt32(&ok); got != 1+session.MaxQueue {
		t.Errorf("accepted count: %d, want %d", got, 1+session.MaxQueue)
	}
}

func TestHealthz(t *testing.T) {
	ts, _, _, _ := setup(t, nil)
	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	var m map[string]bool
	json.NewDecoder(resp.Body).Decode(&m)
	if !m["ok"] {
		t.Errorf("body: %v", m)
	}
}

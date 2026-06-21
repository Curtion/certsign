package client_test

import (
	"context"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"certsign/internal/client"
	"certsign/internal/config"
)

// fakeServer 提供支持 certsign 流协议的可配置 httptest.Server.
type fakeServer struct {
	t              *testing.T
	statusCode     int  // 非零则返回纯 JSON
	signErr        bool // 发送 error 事件而非 done
	signedSuffix   []byte
	extraLogs      []string
	uploadedName   string
	uploadedSize   int64
	uploadReceived []byte
}

func (f *fakeServer) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.Write([]byte(`{"ok":true}`))
			return
		}
		auth := r.Header.Get("Authorization")
		if auth != "Bearer tok" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"unauthorized"}`))
			return
		}
		if f.statusCode != 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(f.statusCode)
			w.Write([]byte(`{"error":"overloaded"}`))
			return
		}

		if err := r.ParseMultipartForm(32 << 20); err == nil {
			if file, header, err := r.FormFile("file"); err == nil {
				f.uploadedName = header.Filename
				b, _ := io.ReadAll(file)
				f.uploadedSize = int64(len(b))
				f.uploadReceived = b
				file.Close()
			}
		}

		flusher, _ := w.(http.Flusher)
		w.Header().Set("Content-Type", "application/x-ndjson")
		writeEvent := func(s string) {
			w.Write([]byte(s))
			if !strings.HasSuffix(s, "\n") {
				w.Write([]byte("\n"))
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		writeEvent(`{"type":"status","phase":"uploaded","size":7,"filename":"app.bin"}`)
		for _, l := range f.extraLogs {
			writeEvent(`{"type":"log","stream":"stdout","line":"` + l + `"}`)
		}
		if f.signErr {
			writeEvent(`{"type":"error","phase":"signtool","exit_code":1,"stderr_tail":"boom"}`)
			return
		}
		artifact := append([]byte{}, f.uploadReceived...)
		artifact = append(artifact, f.signedSuffix...)
		writeEvent(`{"type":"done","bytes":` + itoa(len(artifact)) + `}`)
		w.Write(artifact)
		if flusher != nil {
			flusher.Flush()
		}
	})
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func writeInput(t *testing.T, body string) string {
	t.Helper()
	d := t.TempDir()
	p := filepath.Join(d, "app.bin")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func basicCfg(server string) config.ClientConfig {
	return config.ClientConfig{Server: server, Token: "tok", Timeout: 10 * time.Second}
}

func TestRun_HappyPath_OverwritesInput(t *testing.T) {
	fs := &fakeServer{t: t, signedSuffix: []byte("SIGNED"), extraLogs: []string{"signing line"}}
	ts := httptest.NewServer(fs.handler())
	defer ts.Close()

	in := writeInput(t, "PAYLOAD")
	code := client.Run(context.Background(), basicCfg(ts.URL), in, client.Options{Quiet: true})
	if code != client.ExitOK {
		t.Fatalf("exit code: %d", code)
	}
	got, err := os.ReadFile(in)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "PAYLOADSIGNED" {
		t.Errorf("file content: %q", got)
	}
	if fs.uploadedName != "app.bin" {
		t.Errorf("server saw filename: %q", fs.uploadedName)
	}
	if fs.uploadedSize != 7 {
		t.Errorf("upload size: %d", fs.uploadedSize)
	}
}

func TestRun_WritesToOutputPath(t *testing.T) {
	fs := &fakeServer{t: t, signedSuffix: []byte("X")}
	ts := httptest.NewServer(fs.handler())
	defer ts.Close()

	in := writeInput(t, "DATA")
	out := filepath.Join(filepath.Dir(in), "out.bin")
	code := client.Run(context.Background(), basicCfg(ts.URL), in, client.Options{Output: out, Quiet: true})
	if code != client.ExitOK {
		t.Fatalf("exit code: %d", code)
	}
	if orig, _ := os.ReadFile(in); string(orig) != "DATA" {
		t.Errorf("input mutated: %q", orig)
	}
	if got, _ := os.ReadFile(out); string(got) != "DATAX" {
		t.Errorf("output: %q", got)
	}
}

func TestRun_ServerError_ReturnsCode2(t *testing.T) {
	fs := &fakeServer{t: t, signErr: true}
	ts := httptest.NewServer(fs.handler())
	defer ts.Close()

	in := writeInput(t, "DATA")
	code := client.Run(context.Background(), basicCfg(ts.URL), in, client.Options{Quiet: true})
	if code != client.ExitServerError {
		t.Errorf("exit code: %d, want %d", code, client.ExitServerError)
	}
	if got, _ := os.ReadFile(in); string(got) != "DATA" {
		t.Errorf("input mutated on error: %q", got)
	}
}

func TestRun_Unauthorized_ReturnsCode1(t *testing.T) {
	fs := &fakeServer{t: t}
	ts := httptest.NewServer(fs.handler())
	defer ts.Close()

	in := writeInput(t, "DATA")
	cfg := basicCfg(ts.URL)
	cfg.Token = "wrong"
	code := client.Run(context.Background(), cfg, in, client.Options{Quiet: true})
	if code != client.ExitLocalError {
		t.Errorf("exit code: %d, want %d", code, client.ExitLocalError)
	}
}

func TestRun_Overloaded_ReturnsCode2(t *testing.T) {
	fs := &fakeServer{t: t, statusCode: http.StatusServiceUnavailable}
	ts := httptest.NewServer(fs.handler())
	defer ts.Close()

	in := writeInput(t, "DATA")
	code := client.Run(context.Background(), basicCfg(ts.URL), in, client.Options{Quiet: true})
	if code != client.ExitServerError {
		t.Errorf("exit code: %d, want %d", code, client.ExitServerError)
	}
}

func TestRun_MissingInput_ReturnsCode1(t *testing.T) {
	ts := httptest.NewServer((&fakeServer{t: t}).handler())
	defer ts.Close()
	code := client.Run(context.Background(), basicCfg(ts.URL), filepath.Join(t.TempDir(), "nope.bin"), client.Options{Quiet: true})
	if code != client.ExitLocalError {
		t.Errorf("exit code: %d, want %d", code, client.ExitLocalError)
	}
}

func TestRun_Timeout_ReturnsCode3(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
	}))
	defer ts.Close()
	in := writeInput(t, "DATA")
	cfg := basicCfg(ts.URL)
	cfg.Timeout = 50 * time.Millisecond
	code := client.Run(context.Background(), cfg, in, client.Options{Quiet: true})
	if code != client.ExitTimeout && code != client.ExitLocalError {
		t.Errorf("exit code: %d, want timeout or local-error", code)
	}
}

var _ = multipart.NewWriter

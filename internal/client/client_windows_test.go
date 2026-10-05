package client_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"certsign/internal/client"
)

func TestRun_WindowsOpenDestination(t *testing.T) {
	for _, tc := range []struct {
		name      string
		output    bool
		readOnly  bool
		denyWrite bool
		truncated bool
		wantCode  int
	}{
		{name: "tauri_read_handle", wantCode: client.ExitOK},
		{name: "shorter_output", output: true, wantCode: client.ExitOK},
		{name: "readonly", readOnly: true, wantCode: client.ExitWriteError},
		{name: "write_not_shared", denyWrite: true, wantCode: client.ExitWriteError},
		{name: "truncated_download", truncated: true, wantCode: client.ExitServerError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := writeInput(t, "PAYLOAD")
			dst := in
			original := "PAYLOAD"
			opts := client.Options{}
			if tc.output {
				dst = filepath.Join(filepath.Dir(in), "output.bin")
				original = strings.Repeat("OLD", 32)
				if err := os.WriteFile(dst, []byte(original), 0o644); err != nil {
					t.Fatal(err)
				}
				opts.Output = dst
			}
			if tc.readOnly {
				if err := os.Chmod(dst, 0o444); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := os.Chmod(dst, 0o644); err != nil {
						t.Error(err)
					}
				})
			}

			path, err := syscall.UTF16PtrFromString(dst)
			if err != nil {
				t.Fatal(err)
			}
			share := uint32(syscall.FILE_SHARE_READ | syscall.FILE_SHARE_WRITE | syscall.FILE_SHARE_DELETE)
			if tc.denyWrite {
				share &^= syscall.FILE_SHARE_WRITE
			}
			handle, err := syscall.CreateFile(path, syscall.GENERIC_READ, share, nil, syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL, 0)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := syscall.CloseHandle(handle); err != nil {
					t.Error(err)
				}
			})

			server := &fakeServer{t: t, signedSuffix: []byte("SIGNED")}
			handler := server.handler()
			if tc.truncated {
				handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/x-ndjson")
					fmt.Fprint(w, "{\"type\":\"done\",\"bytes\":100}\nPARTIAL")
				})
			}
			ts := httptest.NewServer(handler)
			defer ts.Close()
			if code := client.Run(context.Background(), basicCfg(ts.URL), in, opts); code != tc.wantCode {
				t.Fatalf("exit code: %d, want %d", code, tc.wantCode)
			}
			want := original
			if tc.wantCode == client.ExitOK {
				want = "PAYLOADSIGNED"
			}
			got, err := os.ReadFile(dst)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != want {
				t.Fatalf("output: %q, want %q", got, want)
			}
			if tc.output {
				got, err := os.ReadFile(in)
				if err != nil || string(got) != "PAYLOAD" {
					t.Fatalf("input changed: %q, err: %v", got, err)
				}
			}
			leftovers, err := filepath.Glob(filepath.Join(filepath.Dir(dst), ".certsign-*"))
			if err != nil || len(leftovers) != 0 {
				t.Fatalf("temporary files: %v, err: %v", leftovers, err)
			}
		})
	}
}

package signtool

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"certsign/internal/config"
	"certsign/internal/testutil"
)

func newSigner(t *testing.T) (*Signer, string) {
	fakes := testutil.BuildFakes(t)
	s := New(config.SigningConfig{
		Signtool:     fakes.Signtool,
		Thumbprint:   "DEADBEEF",
		TimestampURL: "http://timestamp.example.com",
	})
	return s, fakes.Dir
}

func writeInput(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "input.bin")
	if err := os.WriteFile(p, []byte("ORIGINAL-CONTENT"), 0o644); err != nil {
		t.Fatalf("write input: %v", err)
	}
	return p
}

func collect() (func(LogEvent), *[]LogEvent) {
	var got []LogEvent
	return func(e LogEvent) { got = append(got, e) }, &got
}

func TestSign_Success(t *testing.T) {
	s, _ := newSigner(t)
	src := writeInput(t)

	testutil.Env(t,
		"FAKESIGNTOOL_STDOUT", "Done Adding Additional Store\nSuccessfully signed",
		"FAKESIGNTOOL_MARKER", "SIG\n",
	)
	emit, events := collect()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	res, err := s.Sign(ctx, src, emit)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	defer os.RemoveAll(res.TmpDir)

	if res.ExitCode != 0 {
		t.Fatalf("exit code: %d", res.ExitCode)
	}
	if res.SignedFile == "" {
		t.Fatal("empty SignedFile")
	}
	got, err := os.ReadFile(res.SignedFile)
	if err != nil {
		t.Fatalf("read signed file: %v", err)
	}
	if !strings.HasPrefix(string(got), "ORIGINAL-CONTENT") {
		t.Errorf("signed file lost original: %q", got)
	}
	if !strings.HasSuffix(string(got), "SIG\n") {
		t.Errorf("signed file missing marker: %q", got)
	}
	orig, _ := os.ReadFile(src)
	if string(orig) != "ORIGINAL-CONTENT" {
		t.Errorf("original was mutated: %q", orig)
	}
	if len(*events) < 2 {
		t.Errorf("expected >=2 events, got %d: %+v", len(*events), *events)
	}
}

func TestSign_NonZeroExit_TailCaptured(t *testing.T) {
	s, _ := newSigner(t)
	src := writeInput(t)

	long := strings.Repeat("x", 3000)
	testutil.Env(t,
		"FAKESIGNTOOL_STDERR", long,
		"FAKESIGNTOOL_EXIT", "1",
	)
	emit, _ := collect()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	res, err := s.Sign(ctx, src, emit)
	if err != nil {
		t.Fatalf("Sign returned error, expected Result with ExitCode: %v", err)
	}
	if res.ExitCode != 1 {
		t.Errorf("exit code: %d", res.ExitCode)
	}
	if len(res.StderrTail) != TailSize {
		t.Errorf("tail length: %d, want %d", len(res.StderrTail), TailSize)
	}
	if res.SignedFile != "" {
		t.Errorf("expected no signed file on failure, got %q", res.SignedFile)
	}
	if _, err := os.Stat(res.TmpDir); !os.IsNotExist(err) {
		t.Errorf("tmp dir should be cleaned on failure: %v", err)
	}
}

func TestSign_TimeoutKillsProcess(t *testing.T) {
	s, _ := newSigner(t)
	src := writeInput(t)

	testutil.Env(t,
		"FAKESIGNTOOL_DELAY_MS", "5000",
		"FAKESIGNTOOL_EXIT", "0",
	)
	emit, _ := collect()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	res, err := s.Sign(ctx, src, emit)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error")
	}
	if res == nil {
		t.Fatal("nil result")
	}
	if res.SignedFile != "" {
		t.Errorf("expected no signed file on timeout")
	}
	if elapsed > 3*time.Second {
		t.Errorf("timeout did not kill process quickly: %v", elapsed)
	}
}

func TestSign_CrashBeforeOutput(t *testing.T) {
	s, _ := newSigner(t)
	src := writeInput(t)

	testutil.Env(t, "FAKESIGNTOOL_CRASH_CODE", "123456789")
	emit, _ := collect()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	res, err := s.Sign(ctx, src, emit)
	if err != nil {
		t.Fatalf("Sign returned error: %v", err)
	}
	if res.ExitCode != 123456789 {
		t.Errorf("exit code: %d", res.ExitCode)
	}
}

func TestSign_RealtimeStreaming(t *testing.T) {
	s, _ := newSigner(t)
	src := writeInput(t)

	testutil.Env(t,
		"FAKESIGNTOOL_STDOUT", "line one\nline two\nline three",
	)
	emit, events := collect()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if _, err := s.Sign(ctx, src, emit); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	count := 0
	for _, e := range *events {
		if e.Stream == "stdout" && strings.HasPrefix(e.Line, "line ") {
			count++
		}
	}
	if count < 3 {
		t.Errorf("expected 3 stdout lines, got %d (%+v)", count, *events)
	}
}

func TestMatchCertMissing(t *testing.T) {
	cases := []struct {
		tail string
		want bool
	}{
		{"SignerCert not found", true},
		{"error 0x800B010A", true},
		{"CRYPT_E_NOT_FOUND 0x80092004", true},
		{"Cannot find the specified certificate", true},
		{"some other error", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := MatchCertMissing(tc.tail); got != tc.want {
			t.Errorf("MatchCertMissing(%q) = %v, want %v", tc.tail, got, tc.want)
		}
	}
}

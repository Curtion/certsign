package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeTempTOML(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("写入临时 toml 失败: %v", err)
	}
	return p
}

const fullTOML = `
[server]
bind  = "0.0.0.0:8443"
token = "s3cr3t-token-value"

[simplysign]
exe  = "C:\\Program Files\\Certum\\SimplySign\\SimplySignDesktop.exe"
email = "user@example.com"
totp_uri = "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&issuer=T&algorithm=SHA256&digits=6&period=30"

[signing]
thumbprint    = "ABCD1234EFGH5678"
signtool      = "C:\\signtool.exe"
timestamp_url = "http://timestamp.digicert.com"
timeout       = "15m"

[client]
server  = "https://signer.internal:8443"
token   = "client-token"
timeout = "5m"
`

const validSecret = "JBSWY3DPEHPK3PXP"

func TestLoad_FullServerConfig(t *testing.T) {
	p := writeTempTOML(t, fullTOML)
	cfg, err := Load(p, true)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Bind != "0.0.0.0:8443" {
		t.Errorf("bind: %q", cfg.Server.Bind)
	}
	if cfg.Server.Token != "s3cr3t-token-value" {
		t.Errorf("server token: %q", cfg.Server.Token)
	}
	if cfg.Signing.Thumbprint != "ABCD1234EFGH5678" {
		t.Errorf("thumbprint: %q", cfg.Signing.Thumbprint)
	}
	if cfg.Signing.Timeout != 15*time.Minute {
		t.Errorf("signing timeout: %v", cfg.Signing.Timeout)
	}
	if cfg.SimplySign.Email != "user@example.com" {
		t.Errorf("email: %q", cfg.SimplySign.Email)
	}
	if cfg.SimplySign.TOTPURI == "" {
		t.Error("totp_uri empty")
	}
	if cfg.SimplySign.TOTP.Digits != 6 || cfg.SimplySign.TOTP.Period != 30 {
		t.Errorf("totp not parsed: %+v", cfg.SimplySign.TOTP)
	}
	if cfg.SimplySign.TOTP.Algorithm != "SHA256" {
		t.Errorf("algorithm: %q", cfg.SimplySign.TOTP.Algorithm)
	}
	if cfg.Client.Server != "https://signer.internal:8443" {
		t.Errorf("client.server: %q", cfg.Client.Server)
	}
}

func TestLoad_DefaultTimeouts(t *testing.T) {
	body := fullTOML
	body = strings.Replace(body, `= "15m"`, `= ""`, 1)
	body = strings.Replace(body, `= "5m"`, `= ""`, 1)
	p := writeTempTOML(t, body)
	cfg, err := Load(p, true)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Signing.Timeout != DefaultSigningTimeout {
		t.Errorf("signing default: %v", cfg.Signing.Timeout)
	}
	if cfg.Client.Timeout != DefaultClientTimeout {
		t.Errorf("client default: %v", cfg.Client.Timeout)
	}
}

func TestLoad_MissingThumbprint_Fatal(t *testing.T) {
	body := strings.Replace(fullTOML, `thumbprint    = "ABCD1234EFGH5678"`, "", 1)
	p := writeTempTOML(t, body)
	_, err := Load(p, true)
	if err == nil {
		t.Fatal("expected fatal for missing thumbprint")
	}
	if !strings.Contains(err.Error(), "thumbprint 必填") {
		t.Errorf("error message: %v", err)
	}
}

func TestLoad_MissingThumbprint_OKWhenClientOnly(t *testing.T) {
	body := strings.Replace(fullTOML, `thumbprint    = "ABCD1234EFGH5678"`, "", 1)
	p := writeTempTOML(t, body)
	if _, err := Load(p, false); err != nil {
		t.Fatalf("client-only load should succeed: %v", err)
	}
}

func TestLoad_InvalidTOTPURI_Fatal(t *testing.T) {
	body := strings.Replace(fullTOML,
		`totp_uri = "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&issuer=T&algorithm=SHA256&digits=6&period=30"`,
		`totp_uri = "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1"`, 1)
	p := writeTempTOML(t, body)
	_, err := Load(p, true)
	if err == nil {
		t.Fatal("expected fatal for non-SHA256 algorithm")
	}
	if !strings.Contains(err.Error(), "不支持的算法") {
		t.Errorf("error message: %v", err)
	}
}

func TestLoad_NoSuchFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "missing.toml"), true)
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !strings.Contains(err.Error(), "read") {
		t.Errorf("error message: %v", err)
	}
}

func TestLoad_BadDuration(t *testing.T) {
	body := strings.Replace(fullTOML, `timeout = "5m"`, `timeout = "not-a-duration"`, 1)
	p := writeTempTOML(t, body)
	_, err := Load(p, true)
	if err == nil || !strings.Contains(err.Error(), "[client] timeout") {
		t.Fatalf("expected [client] timeout error, got %v", err)
	}
}

func TestResolveClient_Priority(t *testing.T) {
	p := writeTempTOML(t, fullTOML)
	cfg, err := Load(p, false)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	t.Run("file only", func(t *testing.T) {
		got := ResolveClient(cfg, ClientOverrides{})
		if got.Server != "https://signer.internal:8443" {
			t.Errorf("server: %q", got.Server)
		}
		if got.Token != "client-token" {
			t.Errorf("token: %q", got.Token)
		}
		if got.Timeout != 5*time.Minute {
			t.Errorf("timeout: %v", got.Timeout)
		}
	})

	t.Run("flag beats file", func(t *testing.T) {
		got := ResolveClient(cfg, ClientOverrides{
			Server:  "https://flag.example",
			Token:   "flag-token",
			Timeout: 7 * time.Minute,
		})
		if got.Server != "https://flag.example" {
			t.Errorf("server: %q", got.Server)
		}
		if got.Token != "flag-token" {
			t.Errorf("token: %q", got.Token)
		}
		if got.Timeout != 7*time.Minute {
			t.Errorf("timeout: %v", got.Timeout)
		}
	})

	t.Run("env beats flag and file", func(t *testing.T) {
		t.Setenv(envServer, "https://env.example")
		t.Setenv(envToken, "env-token")
		t.Setenv(envTimeout, "42s")
		got := ResolveClient(cfg, ClientOverrides{
			Server: "https://flag.example",
			Token:  "flag-token",
		})
		if got.Server != "https://env.example" {
			t.Errorf("server: %q", got.Server)
		}
		if got.Token != "env-token" {
			t.Errorf("token: %q", got.Token)
		}
		if got.Timeout != 42*time.Second {
			t.Errorf("timeout: %v", got.Timeout)
		}
	})

	t.Run("unset env falls back to flag", func(t *testing.T) {
		os.Unsetenv(envTimeout)
		got := ResolveClient(cfg, ClientOverrides{Timeout: 9 * time.Minute})
		if got.Timeout != 9*time.Minute {
			t.Errorf("timeout: %v", got.Timeout)
		}
	})
}

func TestRedactedSummary(t *testing.T) {
	p := writeTempTOML(t, fullTOML)
	cfg, err := Load(p, true)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	s := cfg.RedactedSummary()

	if strings.Contains(s, "s3cr3t-token-value") {
		t.Errorf("server token leaked: %s", s)
	}
	if strings.Contains(s, "client-token") {
		t.Errorf("client token leaked: %s", s)
	}
	if !strings.Contains(s, "s3cr") || !strings.Contains(s, "alue") {
		t.Errorf("token redaction lost prefix/suffix: %s", s)
	}
	if !strings.Contains(s, "0.0.0.0:8443") {
		t.Errorf("bind missing: %s", s)
	}
	if !strings.Contains(s, "ABCD1234EFGH5678") {
		t.Errorf("thumbprint missing: %s", s)
	}
}

func TestRedactToken_ShortToken(t *testing.T) {
	if got := redactToken(""); got != "<unset>" {
		t.Errorf("empty: %q", got)
	}
	if got := redactToken("ab"); got == "ab" {
		t.Errorf("short token not masked: %q", got)
	}
}

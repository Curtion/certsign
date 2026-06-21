package totp

import (
	"encoding/base32"
	"strings"
	"testing"
)

// RFC 6238 附录 B SHA-256 测试向量.
var rfc6238SHA256 = []struct {
	unix  int64
	code8 string
}{
	{59, "46119246"},
	{1111111109, "68084774"},
	{1111111111, "67062674"},
	{1234567890, "91819424"},
	{2000000000, "90698825"},
	{20000000000, "77737706"},
}

func TestGenerate_RFC6238SHA256(t *testing.T) {
	secret := []byte("12345678901234567890123456789012")
	for _, tc := range rfc6238SHA256 {
		counter := uint64(tc.unix) / 30
		got := Generate(secret, counter, 8)
		if got != tc.code8 {
			t.Errorf("counter=%d (t=%d): got %s, want %s", counter, tc.unix, got, tc.code8)
		}
	}
}

func TestGenerate_SixDigitsMatchesLastSix(t *testing.T) {
	secret := []byte("12345678901234567890123456789012")
	for _, tc := range rfc6238SHA256 {
		counter := uint64(tc.unix) / 30
		got6 := Generate(secret, counter, 6)
		want6 := tc.code8[len(tc.code8)-6:]
		if got6 != want6 {
			t.Errorf("t=%d: got 6-digit %s, want %s", tc.unix, got6, want6)
		}
	}
}

func TestParseURI_Valid(t *testing.T) {
	rawSecret := []byte("12345678901234567890123456789012")
	encSecret := base32.StdEncoding.EncodeToString(rawSecret)
	uri := "otpauth://totp/Certum%3Auser%40example.com?secret=" + encSecret +
		"&issuer=Certum&algorithm=SHA256&digits=6&period=30"

	cfg, err := ParseURI(uri)
	if err != nil {
		t.Fatalf("ParseURI: %v", err)
	}
	if string(cfg.Secret) != string(rawSecret) {
		t.Errorf("secret mismatch: got %x, want %x", cfg.Secret, rawSecret)
	}
	if cfg.Digits != 6 {
		t.Errorf("digits: got %d, want 6", cfg.Digits)
	}
	if cfg.Period != 30 {
		t.Errorf("period: got %d, want 30", cfg.Period)
	}
	if cfg.Issuer != "Certum" {
		t.Errorf("issuer: got %q, want Certum", cfg.Issuer)
	}
}

// 解析器对无填充宽容: 去掉等号后按 8 的倍数补全.
func TestParseURI_LenientPadding(t *testing.T) {
	rawSecret := []byte("12345678901234567890123456789012")
	encSecret := strings.TrimRight(base32.StdEncoding.EncodeToString(rawSecret), "=")

	cfg, err := ParseURI("otpauth://totp/T?secret=" + encSecret + "&algorithm=SHA256")
	if err != nil {
		t.Fatalf("unpadded: %v", err)
	}
	if string(cfg.Secret) != string(rawSecret) {
		t.Errorf("unpadded secret mismatch: got %x, want %x", cfg.Secret, rawSecret)
	}
}

func TestParseURI_NoPadding(t *testing.T) {
	const uri = "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&issuer=T&algorithm=SHA256"
	cfg, err := ParseURI(uri)
	if err != nil {
		t.Fatalf("ParseURI unpadded: %v", err)
	}
	want, _ := base32.StdEncoding.DecodeString("JBSWY3DPEHPK3PXP")
	if string(cfg.Secret) != string(want) {
		t.Errorf("secret mismatch: got %x, want %x", cfg.Secret, want)
	}
	if cfg.Digits != 6 || cfg.Period != 30 {
		t.Errorf("defaults not applied: digits=%d period=%d", cfg.Digits, cfg.Period)
	}
}

func TestParseURI_Errors(t *testing.T) {
	cases := []struct {
		name string
		uri  string
		want string
	}{
		{"missing secret", "otpauth://totp/Test?issuer=T", "缺少 secret"},
		{"wrong algorithm", "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1", "不支持的算法"},
		{"not otpauth", "https://example.com/totp?secret=JBSWY3DPEHPK3PXP", "不是 otpauth URI"},
		{"hotp not supported", "otpauth://hotp/Test?secret=JBSWY3DPEHPK3PXP", "不支持的类型"},
		{"invalid base32", "otpauth://totp/Test?secret=!!!!!!!!!&algorithm=SHA256", "base32 解码"},
		{"bad digits", "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&digits=abc", "无效的 digits"},
		{"bad period", "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&period=0", "无效的 period"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseURI(tc.uri)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}

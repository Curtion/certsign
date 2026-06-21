// Package totp 实现 RFC 6238 TOTP, 仅 HMAC-SHA256 (Certum SimplySign 专用).
package totp

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"math/big"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Config 保存从 otpauth URI 解析的 TOTP 参数.
type Config struct {
	Secret    []byte
	Digits    int
	Period    int
	Issuer    string
	Algorithm string // 始终 "SHA256"
}

// Generate 返回给定 counter 的 HOTP 值 (补零到 digits 位).
func Generate(secret []byte, counter uint64, digits int) string {
	if digits < 1 {
		panic(fmt.Sprintf("totp: digits must be >= 1, got %d", digits))
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)

	mac := hmac.New(sha256.New, secret)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	offset := int(sum[len(sum)-1] & 0x0f)
	// 动态截断: 从 offset 取 4 字节, 屏蔽最高位.
	bin := (uint32(sum[offset])&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])

	mod := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(digits)), nil)
	otp := new(big.Int).Mod(big.NewInt(int64(bin)), mod)

	return fmt.Sprintf("%0*d", digits, otp)
}

// At 返回时间 t 对应的 TOTP 值.
func At(secret []byte, cfg Config, t time.Time) string {
	counter := uint64(t.Unix()) / uint64(cfg.Period)
	return Generate(secret, counter, cfg.Digits)
}

// Now 返回当前时刻的 TOTP 值.
func Now(secret []byte, cfg Config) string {
	return At(secret, cfg, time.Now())
}

// ParseURI 解析 otpauth:// URI. 仅支持 totp + SHA256.
func ParseURI(raw string) (Config, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return Config{}, fmt.Errorf("totp: 解析 otpauth URI 失败: %w", err)
	}
	if strings.ToLower(u.Scheme) != "otpauth" {
		return Config{}, fmt.Errorf("totp: 不是 otpauth URI (scheme=%q)", u.Scheme)
	}
	if strings.ToLower(u.Host) != "totp" {
		return Config{}, fmt.Errorf("totp: 不支持的类型 %q (仅支持 totp)", u.Host)
	}

	q := u.Query()
	secretStr := strings.ToUpper(strings.TrimSpace(q.Get("secret")))
	if secretStr == "" {
		return Config{}, fmt.Errorf("totp: otpauth URI 缺少 secret")
	}
	// 标准 base32 需填充; otpauth 密钥可能无填充, 先补全.
	secretStr = strings.TrimRight(secretStr, "=")
	if m := len(secretStr) % 8; m != 0 {
		secretStr += strings.Repeat("=", 8-m)
	}
	secret, err := base32.StdEncoding.DecodeString(secretStr)
	if err != nil {
		return Config{}, fmt.Errorf("totp: base32 解码 secret 失败: %w", err)
	}

	cfg := Config{
		Secret:    secret,
		Digits:    6,
		Period:    30,
		Algorithm: "SHA256",
	}

	if d := q.Get("digits"); d != "" {
		n, err := strconv.Atoi(d)
		if err != nil || n < 1 {
			return Config{}, fmt.Errorf("totp: 无效的 digits %q", d)
		}
		cfg.Digits = n
	}
	if p := q.Get("period"); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 {
			return Config{}, fmt.Errorf("totp: 无效的 period %q", p)
		}
		cfg.Period = n
	}
	if alg := q.Get("algorithm"); alg != "" {
		if !strings.EqualFold(alg, "SHA256") {
			return Config{}, fmt.Errorf("totp: 不支持的算法 %q (仅支持 SHA256)", alg)
		}
	}
	cfg.Issuer = q.Get("issuer")

	return cfg, nil
}

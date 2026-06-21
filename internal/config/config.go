// Package config 加载和校验 certsign TOML 配置.
// 服务端模式严格校验 [server]/[simplysign]/[signing]; 客户端模式跳过.
// 客户端字段可通过 ResolveClient 按 env > flag > file 覆盖.
package config

import (
	"fmt"
	"os"
	"time"

	"github.com/pelletier/go-toml/v2"

	"certsign/internal/totp"
)

// ServerConfig holds the HTTP server settings.
type ServerConfig struct {
	Bind  string `toml:"bind"`
	Token string `toml:"token"`
	// Cert/Key are optional TLS material (future).
	Cert string `toml:"cert"`
	Key  string `toml:"key"`
}

// SimplySignConfig holds Certum SimplySign Desktop launch parameters.
// SettleTimeout controls the /autologin settle window; zero uses internal default (10s).
type SimplySignConfig struct {
	Exe           string `toml:"exe"`
	Email         string `toml:"email"`
	TOTPURI       string `toml:"totp_uri"`
	SettleTimeout time.Duration
	TOTP          totp.Config `toml:"-"`
}

// SigningConfig holds signtool invocation parameters.
type SigningConfig struct {
	Thumbprint   string        `toml:"thumbprint"`
	Signtool     string        `toml:"signtool"`
	TimestampURL string        `toml:"timestamp_url"`
	Timeout      time.Duration `toml:"timeout"`
}

// ClientConfig holds the CLI client settings.
type ClientConfig struct {
	Server  string        `toml:"server"`
	Token   string        `toml:"token"`
	Timeout time.Duration `toml:"timeout"`
}

// Config 是完整解析后的配置.
type Config struct {
	Server     ServerConfig     `toml:"server"`
	SimplySign SimplySignConfig `toml:"simplysign"`
	Signing    SigningConfig    `toml:"signing"`
	Client     ClientConfig     `toml:"client"`
}

// DefaultClientTimeout is used when [client] timeout is unset.
const DefaultClientTimeout = 10 * time.Minute

// DefaultSigningTimeout is used when [signing] timeout is unset.
const DefaultSigningTimeout = 10 * time.Minute

// rawConfig 用 string 存 duration, TOML 原生 duration 支持有限.
type rawConfig struct {
	Server struct {
		Bind  string `toml:"bind"`
		Token string `toml:"token"`
		Cert  string `toml:"cert"`
		Key   string `toml:"key"`
	} `toml:"server"`
	Simplysign struct {
		Exe           string `toml:"exe"`
		Email         string `toml:"email"`
		TOTPUri       string `toml:"totp_uri"`
		SettleTimeout string `toml:"settle_timeout"`
	} `toml:"simplysign"`
	Signing struct {
		Thumbprint   string `toml:"thumbprint"`
		Signtool     string `toml:"signtool"`
		TimestampUrl string `toml:"timestamp_url"`
		Timeout      string `toml:"timeout"`
	} `toml:"signing"`
	Client struct {
		Server  string `toml:"server"`
		Token   string `toml:"token"`
		Timeout string `toml:"timeout"`
	} `toml:"client"`
}

// Load 读取并校验配置文件. parseServer=true 时严格验证服务端字段.
func Load(path string, parseServer bool) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("config: read %s: %w", path, err)
	}

	var raw rawConfig
	if err := toml.Unmarshal(data, &raw); err != nil {
		return Config{}, fmt.Errorf("config: parse %s: %w", path, err)
	}

	cfg := Config{
		Server: ServerConfig{
			Bind:  raw.Server.Bind,
			Token: raw.Server.Token,
			Cert:  raw.Server.Cert,
			Key:   raw.Server.Key,
		},
		SimplySign: SimplySignConfig{
			Exe:     raw.Simplysign.Exe,
			Email:   raw.Simplysign.Email,
			TOTPURI: raw.Simplysign.TOTPUri,
		},
		Signing: SigningConfig{
			Thumbprint:   raw.Signing.Thumbprint,
			Signtool:     raw.Signing.Signtool,
			TimestampURL: raw.Signing.TimestampUrl,
		},
		Client: ClientConfig{
			Server: raw.Client.Server,
			Token:  raw.Client.Token,
		},
	}

	if raw.Signing.Timeout != "" {
		d, err := time.ParseDuration(raw.Signing.Timeout)
		if err != nil {
			return Config{}, fmt.Errorf("config: [signing] timeout: %w", err)
		}
		cfg.Signing.Timeout = d
	} else {
		cfg.Signing.Timeout = DefaultSigningTimeout
	}

	if raw.Simplysign.SettleTimeout != "" {
		d, err := time.ParseDuration(raw.Simplysign.SettleTimeout)
		if err != nil {
			return Config{}, fmt.Errorf("config: [simplysign] settle_timeout: %w", err)
		}
		cfg.SimplySign.SettleTimeout = d
	}

	if raw.Client.Timeout != "" {
		d, err := time.ParseDuration(raw.Client.Timeout)
		if err != nil {
			return Config{}, fmt.Errorf("config: [client] timeout: %w", err)
		}
		cfg.Client.Timeout = d
	} else {
		cfg.Client.Timeout = DefaultClientTimeout
	}

	if parseServer {
		if cfg.Signing.Thumbprint == "" {
			return Config{}, fmt.Errorf("config: thumbprint 必填, 请在 [signing] 配置证书 SHA1 指纹")
		}
		if cfg.SimplySign.TOTPURI != "" {
			parsed, err := totp.ParseURI(cfg.SimplySign.TOTPURI)
			if err != nil {
				return Config{}, fmt.Errorf("config: %w", err)
			}
			cfg.SimplySign.TOTP = parsed
		}
	}

	return cfg, nil
}

// ClientOverrides 承载 CLI 参数和 env 的覆盖值.
type ClientOverrides struct {
	Server  string
	Token   string
	Timeout time.Duration
}

const (
	envToken   = "CERTSIGN_TOKEN"
	envServer  = "CERTSIGN_SERVER"
	envTimeout = "CERTSIGN_TIMEOUT"
)

// ResolveClient 按 env > flag > file 优先级合并客户端配置.
func ResolveClient(cfg Config, o ClientOverrides) ClientConfig {
	out := cfg.Client

	if o.Server != "" {
		out.Server = o.Server
	}
	if o.Token != "" {
		out.Token = o.Token
	}
	if o.Timeout != 0 {
		out.Timeout = o.Timeout
	}

	if v := os.Getenv(envServer); v != "" {
		out.Server = v
	}
	if v := os.Getenv(envToken); v != "" {
		out.Token = v
	}
	if v := os.Getenv(envTimeout); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			out.Timeout = d
		}
	}

	return out
}

// RedactedSummary 返回启动日志用的配置摘要, token 仅保留首尾各4个字符.
func (c Config) RedactedSummary() string {
	return fmt.Sprintf(
		"server.bind=%s server.token=%s client.server=%s client.token=%s signing.thumbprint=%s",
		c.Server.Bind, redactToken(c.Server.Token),
		c.Client.Server, redactToken(c.Client.Token),
		c.Signing.Thumbprint,
	)
}

func redactToken(t string) string {
	if t == "" {
		return "<unset>"
	}
	if len(t) <= 8 {
		return t[:1] + "..." + t[len(t)-1:]
	}
	return t[:4] + "..." + t[len(t)-4:]
}

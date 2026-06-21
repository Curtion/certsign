// Package session 管理 SimplySign 会话: 惰性 autologin (三值 TOTP 容错),
// singleflight 登录去重, 签名互斥, 证书缺失自动重登.
// 无后台 keep-alive, 状态转换由 Sign 请求驱动.
package session

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"certsign/internal/signtool"
	"certsign/internal/totp"
)

// State 表示 SimplySign 会话状态.
type State int

const (
	Uninit State = iota
	LoggingIn
	LoggedIn
	Stale
)

func (s State) String() string {
	switch s {
	case Uninit:
		return "Uninit"
	case LoggingIn:
		return "LoggingIn"
	case LoggedIn:
		return "LoggedIn"
	case Stale:
		return "Stale"
	default:
		return "Unknown"
	}
}

// ErrOverloaded 在请求队列满时由 Reserve 返回.
var ErrOverloaded = errors.New("session: queue overloaded")

// MaxQueue 是一个签名进行中时允许排队的最大请求数.
const MaxQueue = 5

// Signer is *signtool.Signer 的子集, 方便测试注入.
type Signer interface {
	Sign(ctx context.Context, srcPath string, emit func(signtool.LogEvent)) (*signtool.Result, error)
}

// SimplySignClient 是 *simplysign.Manager 的子集, 方便测试注入 fake.
type SimplySignClient interface {
	Autologin(ctx context.Context, otp string) (bool, error)
	Close(ctx context.Context) error
}

// Event 是服务器流式传输给客户端的会话生命周期事件.
type Event struct {
	Phase string // "login" | "relogin" | "signing"
	Msg   string
}

// Manager 协调 SimplySign autologin 和 signtool 签名.
type Manager struct {
	mu     sync.Mutex
	state  State
	signMu sync.Mutex // 序列化签名的互斥锁

	inflight int  // 已获取槽位尚未释放的请求数
	logged   bool // 是否曾达到 LoggedIn (决定失败后回退状态)

	appCtx context.Context // 应用级 ctx, 用于登录/Close, 不受请求取消影响

	sf     singleflight.Group
	simply SimplySignClient
	signer Signer
	totp   totp.Config
}

// New 创建 Manager. appCtx 应为应用级 ctx, 用于驱动 autologin/Close.
func New(simply SimplySignClient, signer Signer, totpCfg totp.Config, appCtx context.Context) *Manager {
	if appCtx == nil {
		appCtx = context.Background()
	}
	return &Manager{
		simply: simply,
		signer: signer,
		totp:   totpCfg,
		appCtx: appCtx,
	}
}

func (m *Manager) State() State {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state
}

func (m *Manager) Ready() bool {
	return m.State() == LoggedIn
}

// tryAcquire 预留队列槽位, 超限返回 ErrOverloaded.
func (m *Manager) tryAcquire() (release func(), err error) {
	m.mu.Lock()
	if m.inflight >= 1+MaxQueue {
		m.mu.Unlock()
		return nil, ErrOverloaded
	}
	m.inflight++
	m.mu.Unlock()
	return func() {
		m.mu.Lock()
		m.inflight--
		m.mu.Unlock()
	}, nil
}

// Reserve 是 tryAcquire 的公开入口, 供 HTTP 层做队列控制.
func (m *Manager) Reserve() (release func(), err error) {
	return m.tryAcquire()
}

func (m *Manager) setState(s State) {
	m.mu.Lock()
	m.state = s
	if s == LoggedIn {
		m.logged = true
	}
	m.mu.Unlock()
}

// Sign 执行懒登录 + 签名. 调用方须先 Reserve 并 defer release.
// ctx 为 per-request ctx, 仅用于取消 signtool; 登录使用 m.appCtx.
func (m *Manager) Sign(ctx context.Context, srcPath string, log func(signtool.LogEvent), status func(Event)) (*signtool.Result, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := m.ensureLoggedIn(m.appCtx, status, false); err != nil {
		return nil, err
	}
	// 登录可能耗时, 完成后再检查 per-request ctx.
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	m.signMu.Lock()
	defer m.signMu.Unlock()

	if status != nil {
		status(Event{Phase: "signing"})
	}
	res, err := m.signer.Sign(ctx, srcPath, log)
	if err != nil {
		return nil, err
	}
	if res.ExitCode == 0 {
		return res, nil
	}

	// signtool 失败且匹配证书缺失特征: 重新登录后重试一次.
	if signtool.MatchCertMissing(res.StderrTail) {
		if status != nil {
			status(Event{Phase: "relogin", Msg: "证书缺失, 重新登录中"})
		}
		m.setState(Stale)
		if m.simply != nil {
			_ = m.simply.Close(m.appCtx) // 尽力关闭, 失败不阻塞重试.
		}
		if err := m.ensureLoggedIn(m.appCtx, status, true); err != nil {
			return nil, fmt.Errorf("session: re-login after cert error: %w", err)
		}
		// 重登也可能耗时, 再检查 per-request ctx.
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		res2, err := m.signer.Sign(ctx, srcPath, log)
		if err != nil {
			return nil, err
		}
		return res2, nil
	}

	return res, nil
}

// ensureLoggedIn 触发 autologin (singleflight 去重).
func (m *Manager) ensureLoggedIn(ctx context.Context, status func(Event), forceStale bool) error {
	if m.Ready() {
		return nil
	}
	if status != nil {
		if forceStale {
			status(Event{Phase: "relogin"})
		} else {
			status(Event{Phase: "login"})
		}
	}
	_, err, _ := m.sf.Do("login", func() (interface{}, error) {
		// 二次确认: 可能已有并发调用完成了登录.
		if m.Ready() {
			return nil, nil
		}
		m.setState(LoggingIn)
		if err := m.doAutologin(ctx); err != nil {
			m.mu.Lock()
			if m.logged {
				m.state = Stale
			} else {
				m.state = Uninit
			}
			m.mu.Unlock()
			return nil, err
		}
		m.setState(LoggedIn)
		return nil, nil
	})
	return err
}

// doAutologin 依次尝试当前 TOTP 及前后各一个时间窗口.
func (m *Manager) doAutologin(ctx context.Context) error {
	secret := m.totp.Secret
	period := int64(m.totp.Period)
	if period <= 0 {
		period = 30
	}
	t0 := time.Now().Unix() / period
	for _, c := range [3]uint64{uint64(t0), uint64(t0 - 1), uint64(t0 + 1)} {
		otp := totp.Generate(secret, c, m.totp.Digits)
		alive, err := m.simply.Autologin(ctx, otp)
		if err != nil {
			return fmt.Errorf("autologin counter=%d: %w", c, err)
		}
		if alive {
			return nil
		}
	}
	return errors.New("autologin 失败: 三个 TOTP 值均无效")
}

// Shutdown 关闭 SimplySign 会话, 用于服务优雅退出.
func (m *Manager) Shutdown(ctx context.Context) error {
	if m.simply == nil {
		return nil
	}
	return m.simply.Close(ctx)
}

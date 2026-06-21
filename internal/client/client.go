// Package client 实现 CLI 客户端: 上传文件, 流式解析 ndjson 事件, 原子替换输出.
package client

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/schollz/progressbar/v3"

	"certsign/internal/config"
)

// 退出码.
const (
	ExitOK          = 0
	ExitLocalError  = 1 // config / missing file / upload failure
	ExitServerError = 2 // server reported an error
	ExitTimeout     = 3
	ExitWriteError  = 4 // failed to write the result back
)

// Options 控制客户端行为.
type Options struct {
	Output   string // 输出路径, 空则覆盖输入
	Insecure bool   // 跳过 TLS 校验
}

// Run 上传签名并原子写入结果, 返回 Exit* 退出码.
func Run(ctx context.Context, cfg config.ClientConfig, inputPath string, opts Options) int {
	in, err := os.ReadFile(inputPath)
	if err != nil {
		clientLog("读取 %s 失败: %v", inputPath, err)
		return ExitLocalError
	}

	server := strings.TrimRight(cfg.Server, "/")
	if server == "" {
		clientLog("未配置 server 地址")
		return ExitLocalError
	}
	if cfg.Token == "" {
		clientLog("未配置 token")
		return ExitLocalError
	}

	reqCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	code, err := sign(reqCtx, cfg, opts, inputPath, in, server)
	if err != nil && code == ExitOK {
		code = ExitLocalError
	}
	return code
}

func sign(ctx context.Context, cfg config.ClientConfig, opts Options, inputPath string, content []byte, server string) (int, error) {
	buf := &bytes.Buffer{}
	mw := multipart.NewWriter(buf)
	header := mw.FormDataContentType()

	part, err := mw.CreateFormFile("file", filepath.Base(inputPath))
	if err != nil {
		return ExitLocalError, err
	}
	if _, err := part.Write(content); err != nil {
		return ExitLocalError, err
	}
	if err := mw.Close(); err != nil {
		return ExitLocalError, err
	}

	// 上传进度条.
	bodyLen := int64(buf.Len())
	var bodyReader io.Reader = buf
	bar := progressbar.NewOptions64(bodyLen,
		progressbar.OptionSetDescription("上传中..."),
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionSetWidth(20),
		progressbar.OptionShowBytes(true),
		progressbar.OptionThrottle(50*time.Millisecond),
		progressbar.OptionOnCompletion(func() {
			fmt.Fprintln(os.Stderr)
		}),
	)
	bodyReader = io.TeeReader(buf, bar)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, server+"/sign", bodyReader)
	if err != nil {
		return ExitLocalError, err
	}
	req.ContentLength = bodyLen
	req.Header.Set("Content-Type", header)
	req.Header.Set("Authorization", "Bearer "+cfg.Token)

	httpClient := &http.Client{}
	if opts.Insecure {
		httpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || ctx.Err() == context.DeadlineExceeded {
			return ExitTimeout, fmt.Errorf("timeout: %v", err)
		}
		return ExitLocalError, err
	}
	defer resp.Body.Close()

	// 非 ndjson 响应即前置错误 (401/503/400).
	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/x-ndjson") {
		var m map[string]string
		json.NewDecoder(resp.Body).Decode(&m)
		msg := m["error"]
		if msg == "" {
			msg = fmt.Sprintf("http %d", resp.StatusCode)
		}
		clientLog("服务器拒绝请求: %s", msg)
		if resp.StatusCode == http.StatusUnauthorized {
			return ExitLocalError, errors.New("unauthorized")
		}
		return ExitServerError, errors.New(msg)
	}

	// 解析 ndjson 事件直到 done, 然后读取签名后字节.
	br := bufio.NewReader(resp.Body)
	var artifact bytes.Buffer
	artifact.Grow(len(content) + 1024)
	var doneBytes int64 = -1

	for doneBytes < 0 {
		line, err := br.ReadBytes('\n')
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) || ctx.Err() == context.DeadlineExceeded {
				return ExitTimeout, err
			}
			return ExitServerError, fmt.Errorf("stream ended unexpectedly: %w", err)
		}
		var ev map[string]any
		if err := json.Unmarshal(line, &ev); err != nil {
			return ExitServerError, fmt.Errorf("parse event %q: %w", line, err)
		}
		switch ev["type"] {
		case "log":
			if l, ok := ev["line"].(string); ok {
				serverLog("signtool", l)
			}
		case "status":
			phase, _ := ev["phase"].(string)
			msg, _ := ev["msg"].(string)
			label := phaseLabel(phase)
			if msg != "" {
				label += " " + msg
			}
			serverLog("status", label)
		case "done":
			if v, ok := ev["bytes"].(float64); ok {
				doneBytes = int64(v)
			}
		case "error":
			phase, _ := ev["phase"].(string)
			msg, _ := ev["msg"].(string)
			if msg == "" {
				if t, ok := ev["stderr_tail"].(string); ok {
					msg = truncate(t, 2000)
				}
			}
			clientLog("服务器错误 (phase=%s): %s", phase, msg)
			return ExitServerError, errors.New("server error")
		}
	}

	if doneBytes < 0 {
		clientLog("流在 done 事件之前意外结束")
		return ExitServerError, errors.New("no done event")
	}

	// 下载进度条.
	var artifactReader io.Reader = br
	bar = progressbar.NewOptions64(doneBytes,
		progressbar.OptionSetDescription("下载中..."),
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionSetWidth(20),
		progressbar.OptionShowBytes(true),
		progressbar.OptionThrottle(50*time.Millisecond),
		progressbar.OptionOnCompletion(func() {
			fmt.Fprintln(os.Stderr)
		}),
	)
	artifactReader = io.TeeReader(br, bar)

	if _, err := io.CopyN(&artifact, artifactReader, doneBytes); err != nil {
		if errors.Is(err, context.DeadlineExceeded) || ctx.Err() == context.DeadlineExceeded {
			return ExitTimeout, err
		}
		return ExitServerError, fmt.Errorf("read artifact: %w", err)
	}

	out := opts.Output
	if out == "" {
		out = inputPath
	}
	if err := atomicWrite(out, artifact.Bytes()); err != nil {
		clientLog("写入 %s 失败: %v", out, err)
		return ExitWriteError, err
	}
	clientLog("已签名 %s (%s)", out, formatBytes(int64(artifact.Len())))
	return ExitOK, nil
}

// atomicWrite 先写临时文件再 rename, 防止写入中断导致文件损坏.
func atomicWrite(dst string, data []byte) error {
	dir := filepath.Dir(dst)
	tmp, err := os.CreateTemp(dir, ".certsign-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() { os.Remove(tmpName) }
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpName, dst); err != nil {
		cleanup()
		return err
	}
	return nil
}

// truncate keeps only the last n bytes of s.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

// formatBytes returns a human-readable size string (e.g. "10.2 MB").
func formatBytes(n int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)
	switch {
	case n >= GB:
		return fmt.Sprintf("%.1f GB", float64(n)/float64(GB))
	case n >= MB:
		return fmt.Sprintf("%.1f MB", float64(n)/float64(MB))
	case n >= KB:
		return fmt.Sprintf("%.1f KB", float64(n)/float64(KB))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

// phaseLabel converts a server status phase to a Chinese label.
func phaseLabel(phase string) string {
	switch phase {
	case "uploaded":
		return "上传完成"
	case "login":
		return "登录中..."
	case "signing":
		return "签名中..."
	case "relogin":
		return "重新登录中..."
	default:
		return phase
	}
}

// clientLog 输出客户端自身日志, 带日期时间和 [client] 前缀.
func clientLog(format string, args ...any) {
	ts := time.Now().Format("2006-01-02 15:04:05")
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(os.Stderr, "%s [client] %s\n", ts, msg)
}

// serverLog 输出服务端日志, 带日期时间、[server] 前缀和子前缀.
func serverLog(sub, msg string) {
	ts := time.Now().Format("2006-01-02 15:04:05")
	fmt.Fprintf(os.Stderr, "%s [server] [%s] %s\n", ts, sub, msg)
}

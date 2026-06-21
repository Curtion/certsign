// Package signtool 封装 Windows signtool.exe 调用.
// Sign 将文件复制到临时目录签名, 实时转发 stdout/stderr, 返回结果.
package signtool

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"certsign/internal/config"
)

// TailSize 是错误报告时保留的 stderr 尾部最大字节数.
const TailSize = 2000

// LogEvent 是 signtool 输出的单行 stdout/stderr.
type LogEvent struct {
	Stream string // "stdout" | "stderr"
	Line   string
}

// Result holds signtool 执行结果.
// ExitCode==0: SignedFile 有效, 调用方负责 os.RemoveAll(TmpDir).
// ExitCode!=0 或 Sign 返回 error: TmpDir 已清理.
type Result struct {
	ExitCode   int
	StderrTail string
	SignedFile string
	TmpDir     string
}

// Signer 为固定证书构建并执行 signtool 命令.
type Signer struct {
	exe          string
	thumbprint   string
	timestampURL string
}

func New(cfg config.SigningConfig) *Signer {
	return &Signer{
		exe:          cfg.Signtool,
		thumbprint:   cfg.Thumbprint,
		timestampURL: cfg.TimestampURL,
	}
}

// Sign 对 srcPath 签名, emit 实时接收 stdout/stderr 行.
func (s *Signer) Sign(ctx context.Context, srcPath string, emit func(LogEvent)) (*Result, error) {
	tmpDir, err := os.MkdirTemp("", "certsign-*")
	if err != nil {
		return nil, fmt.Errorf("signtool: 创建临时目录失败: %w", err)
	}
	base := filepath.Base(srcPath) // 只保留文件名, 防止路径穿越.
	dst := filepath.Join(tmpDir, base)

	if err := copyFile(srcPath, dst); err != nil {
		os.RemoveAll(tmpDir)
		return nil, fmt.Errorf("signtool: 暂存输入文件失败: %w", err)
	}

	args := []string{
		"sign",
		"/sha1", s.thumbprint,
		"/fd", "sha256",
		"/tr", s.timestampURL,
		"/td", "sha256",
		dst,
	}
	cmd := exec.CommandContext(ctx, s.exe, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		os.RemoveAll(tmpDir)
		return nil, fmt.Errorf("signtool: stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		os.RemoveAll(tmpDir)
		return nil, fmt.Errorf("signtool: stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		os.RemoveAll(tmpDir)
		return nil, fmt.Errorf("signtool: 启动失败: %w", err)
	}

	// 捕获 stderr 尾部, 同时转发.
	var tail []byte
	scan(stderr, "stderr", emit, func(line string) {
		tail = appendTail(tail, line)
	})

	scan(stdout, "stdout", emit, nil)

	type waitOut struct{ err error }
	waitCh := make(chan waitOut, 1)
	go func() {
		waitCh <- waitOut{cmd.Wait()}
	}()

	w := <-waitCh

	tailStr := string(tail)

	res := &Result{StderrTail: tailStr, TmpDir: tmpDir}

	if ctx.Err() != nil {
		os.RemoveAll(tmpDir)
		res.ExitCode = -1
		return res, ctx.Err()
	}

	if w.err != nil {
		if exitErr, ok := w.err.(*exec.ExitError); ok {
			res.ExitCode = exitErr.ExitCode()
		} else {
			res.ExitCode = -1
		}
		os.RemoveAll(tmpDir)
		return res, nil
	}

	// 成功: 保留 TmpDir 供调用方流式发送 + 清理.
	res.ExitCode = 0
	res.SignedFile = dst
	return res, nil
}

// scan 逐行读取并转发, 通过 sink 回调收集数据.
func scan(r io.Reader, stream string, emit func(LogEvent), sink func(string)) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if emit != nil {
			emit(LogEvent{Stream: stream, Line: line})
		}
		if sink != nil {
			sink(line)
		}
	}
	if err := sc.Err(); err != nil && emit != nil {
		emit(LogEvent{Stream: stream, Line: fmt.Sprintf("signtool: 扫描输出失败: %v", err)})
	}
}

// appendTail 追加一行并只保留最后 TailSize 字节.
func appendTail(tail []byte, line string) []byte {
	tail = append(tail, line...)
	tail = append(tail, '\n')
	if len(tail) > TailSize {
		tail = tail[len(tail)-TailSize:]
	}
	return tail
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

// MatchCertMissing 判断 stderr 尾部是否含证书缺失特征.
func MatchCertMissing(stderrTail string) bool {
	low := bytes.ToLower([]byte(stderrTail))
	for _, sig := range [][]byte{
		[]byte("cannot find the specified certificate"),
		[]byte("signercert"),
		[]byte("0x800b010a"),
		[]byte("0x80092004"),
	} {
		if bytes.Contains(low, sig) {
			return true
		}
	}
	return false
}

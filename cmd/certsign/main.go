// certsign 客户端/服务端签名工具.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"certsign/internal/client"
	"certsign/internal/config"
	"certsign/internal/server"
	"certsign/internal/session"
	"certsign/internal/signtool"
	"certsign/internal/simplysign"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "serve" {
		os.Exit(runServe(os.Args[2:]))
	}
	os.Exit(runClient(os.Args[1:]))
}

func newLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stderr, nil))
}

func runServe(args []string) int {
	fs := flag.NewFlagSet("certsign serve", flag.ExitOnError)
	configPath := fs.String("config", "./config.toml", "配置文件路径")
	fs.Parse(args)

	logger := newLogger()

	cfg, err := config.Load(*configPath, true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "certsign: %v\n", err)
		return 1
	}
	logger.Info("配置已加载", "summary", cfg.RedactedSummary())

	signer := signtool.New(cfg.Signing)
	simply := simplysign.New(cfg.SimplySign, logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// 注入 app 级 ctx, 避免 per-request ctx 取消影响登录/Close.
	sm := session.New(simply, signer, cfg.SimplySign.TOTP, ctx, logger)

	srv := server.New(cfg.Server, sm, logger)
	if err := srv.Run(ctx); err != nil {
		logger.Error("服务端异常退出", "err", err)
		return 1
	}
	return 0
}

func runClient(args []string) int {
	fs := flag.NewFlagSet("certsign", flag.ExitOnError)
	configPath := fs.String("config", "./config.toml", "配置文件路径")
	serverURL := fs.String("server", "", "服务器 URL (覆盖配置文件)")
	token := fs.String("token", "", "Bearer token (覆盖配置文件; 环境变量 CERTSIGN_TOKEN)")
	output := fs.String("output", "", "输出路径 (默认覆盖输入文件)")
	timeout := fs.Duration("timeout", 0, "超时时间 (覆盖配置文件)")
	insecure := fs.Bool("insecure", false, "跳过 TLS 证书校验")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "用法: certsign [flags] <input-file>")
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if fs.NArg() < 1 {
		fs.Usage()
		return 1
	}
	input := fs.Arg(0)

	// 客户端模式不需要 [signing] thumbprint.
	cfg, err := config.Load(*configPath, false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s certsign: %v\n", time.Now().Format("2006-01-02 15:04:05"), err)
		return 1
	}
	clientCfg := config.ResolveClient(cfg, config.ClientOverrides{
		Server:  *serverURL,
		Token:   *token,
		Timeout: *timeout,
	})

	opts := client.Options{
		Output:   *output,
		Insecure: *insecure,
	}
	return client.Run(context.Background(), clientCfg, input, opts)
}

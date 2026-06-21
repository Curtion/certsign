// certsign-totp 打印当前 TOTP 值, 用于核对与 SimplySign 登录 OTP 是否一致.
// 走与 server 相同的 config.Load → totp.ParseURI → totp.Generate 链路.
//
//	certsign-totp [-config ./config.toml] [-watch]
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"certsign/internal/config"
	"certsign/internal/totp"
)

func main() {
	configPath := flag.String("config", "./config.toml", "配置文件路径")
	watch := flag.Bool("watch", false, "持续刷新, 每秒重绘一次")
	flag.Parse()

	cfg, err := config.Load(*configPath, true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "certsign-totp: %v\n", err)
		os.Exit(1)
	}
	t := cfg.SimplySign.TOTP
	if len(t.Secret) == 0 {
		fmt.Fprintln(os.Stderr, "certsign-totp: 配置缺少 [simplysign] totp_uri")
		os.Exit(1)
	}

	if *watch {
		runWatch(t)
		return
	}
	printOnce(t, time.Now())
}

func printOnce(t totp.Config, now time.Time) {
	period := int64(t.Period)
	if period <= 0 {
		period = 30
	}
	counter := uint64(now.Unix() / period)
	remain := period - now.Unix()%period

	fmt.Printf("config:        %s\n", t.Algorithm)
	fmt.Printf("digits/period: %d / %ds\n", t.Digits, t.Period)
	fmt.Printf("secret bytes:  %x (%d bytes)\n", t.Secret, len(t.Secret))
	fmt.Printf("unix time:     %d\n", now.Unix())
	fmt.Printf("counter:       %d\n", counter)
	fmt.Printf("前一窗口 OTP:  %s\n", totp.Generate(t.Secret, counter-1, t.Digits))
	fmt.Printf("当前窗口 OTP:  %s  (剩余 %ds)\n", totp.Generate(t.Secret, counter, t.Digits), remain)
	fmt.Printf("后一窗口 OTP:  %s\n", totp.Generate(t.Secret, counter+1, t.Digits))
}

func runWatch(t totp.Config) {
	for {
		fmt.Print("\033[H\033[2J")
		printOnce(t, time.Now())
		fmt.Println("\nCtrl+C 退出...")
		time.Sleep(time.Second)
	}
}

// fake-simplysign 是 SimplySignDesktop.exe 的测试替身.
//
//	fake-simplysign /autologin <email> <otp>
//	fake-simplysign /close
//
// /autologin 环境变量:
//
//	FAKESIMPLYSIGN_MODE   alive (默认): 常驻模拟登录成功
//	                      exit: 立即退出 0
//	                      exit_nonzero: 立即退出 1 (模拟 OTP 错误)
//	                      delayed: 延迟后退出
package main

import (
	"os"
	"strconv"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		os.Exit(0)
	}
	switch os.Args[1] {
	case "/close", "/c":
		os.Exit(0)
	case "/autologin":
		runAutologin()
	default:
		os.Exit(0)
	}
}

func runAutologin() {
	switch os.Getenv("FAKESIMPLYSIGN_MODE") {
	case "exit":
		os.Exit(0)
	case "exit_nonzero":
		os.Exit(1)
	case "delayed":
		d := envIntDefault("FAKESIMPLYSIGN_DELAY_MS", 1000)
		time.Sleep(time.Duration(d) * time.Millisecond)
		os.Exit(0)
	default: // alive
		d := envIntDefault("FAKESIMPLYSIGN_ALIVE_MS", 60000)
		time.Sleep(time.Duration(d) * time.Millisecond)
		os.Exit(0)
	}
}

func envIntDefault(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

// fake-signtool 是 signtool.exe 的测试替身, 行为由环境变量控制.
//
//	fake-signtool sign /sha1 <thumbprint> /fd sha256 ... <file>
//
// 环境变量:
//
//	FAKESIGNTOOL_STDOUT / FAKESIGNTOOL_STDERR  输出文本
//	FAKESIGNTOOL_EXIT      退出码 (默认 0)
//	FAKESIGNTOOL_DELAY_MS  退出前延迟 (ms)
//	FAKESIGNTOOL_MARKER    追加到签名文件的字节 (默认 "FAKESIGN\n")
//	FAKESIGNTOOL_NO_MARKER 非空则不修改文件
//	FAKESIGNTOOL_CRASH_CODE 立即以此码退出
package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	if v := os.Getenv("FAKESIGNTOOL_CRASH_CODE"); v != "" {
		code, _ := strconv.Atoi(v)
		os.Exit(code)
	}

	// 找到最后一个非 flag 参数 (目标文件), 追加 marker.
	file := lastPositional(os.Args[1:])
	if file != "" && os.Getenv("FAKESIGNTOOL_NO_MARKER") == "" {
		marker := os.Getenv("FAKESIGNTOOL_MARKER")
		if marker == "" {
			marker = "FAKESIGN\n"
		}
		if err := appendFile(file, marker); err != nil {
			fmt.Fprintf(os.Stderr, "fake-signtool: write %s: %v\n", file, err)
			os.Exit(1)
		}
	}

	if d := envInt("FAKESIGNTOOL_DELAY_MS"); d > 0 {
		time.Sleep(time.Duration(d) * time.Millisecond)
	}

	if v := os.Getenv("FAKESIGNTOOL_STDOUT"); v != "" {
		fmt.Fprint(os.Stdout, v)
		if !strings.HasSuffix(v, "\n") {
			fmt.Fprintln(os.Stdout)
		}
	}
	if v := os.Getenv("FAKESIGNTOOL_STDERR"); v != "" {
		fmt.Fprint(os.Stderr, v)
		if !strings.HasSuffix(v, "\n") {
			fmt.Fprintln(os.Stderr)
		}
	}

	os.Exit(envIntDefault("FAKESIGNTOOL_EXIT", 0))
}

// lastPositional 返回最后一个不以 '/' 或 '-' 开头的参数.
func lastPositional(args []string) string {
	for i := len(args) - 1; i >= 0; i-- {
		a := args[i]
		if a == "" || a[0] == '/' || a[0] == '-' {
			continue
		}
		return a
	}
	return ""
}

func appendFile(path, s string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(s)
	return err
}

func envInt(key string) int {
	v := os.Getenv(key)
	n, _ := strconv.Atoi(v)
	return n
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

// Package testutil 提供测试共享工具: 编译 fake 二进制到临时目录.
package testutil

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// Fakes 保存编译后的 fake 二进制绝对路径.
type Fakes struct {
	Dir        string
	Signtool   string
	Simplysign string
}

// BuildFakes 编译 fake-signtool 和 fake-simplysign 到临时目录.
func BuildFakes(t *testing.T) Fakes {
	t.Helper()
	dir := t.TempDir()
	ext := ""
	if runtime.GOOS == "windows" {
		ext = ".exe"
	}
	f := Fakes{
		Dir:        dir,
		Signtool:   filepath.Join(dir, "fake-signtool"+ext),
		Simplysign: filepath.Join(dir, "fake-simplysign"+ext),
	}
	for _, b := range []struct{ pkg, out string }{
		{"certsign/cmd/fake-signtool", f.Signtool},
		{"certsign/cmd/fake-simplysign", f.Simplysign},
	} {
		cmd := exec.Command("go", "build", "-o", b.out, b.pkg)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v\n%s", b.pkg, err, out)
		}
	}
	return f
}

// Env 批量设置环境变量, 测试结束时自动恢复.
func Env(t *testing.T, kv ...string) {
	t.Helper()
	if len(kv)%2 != 0 {
		t.Fatalf("Env: odd number of key/value arguments")
	}
	for i := 0; i < len(kv); i += 2 {
		k, v := kv[i], kv[i+1]
		t.Setenv(k, v)
	}
}

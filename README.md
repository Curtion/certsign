# 说明

> 当前程序完全由`GLM 5.2`生成

针对`Certum 云代码证书`签名的一个服务, 方便在CI/CD环境中进行自动化签名.

[原理参考](https://www.devas.life/how-to-automate-signing-your-windows-app-with-certum/)

软件分为两服务端和客户端:
 - 服务端运行在一台`Windows`机器上, 用于自动登录`SimplySign`、对外提供`HTTP`接口、调用`signtool`为软件签名。
 - 客户端为命令行工具, 支持`MacOS`、`Windows`和`Linux`, 用于上传文件, 调用`HTTP`接口, 原地回写文件。如果无法使用命令行也可以根据[API](docs/api.md)协议自定义客户端。

# 使用方式

## 服务端

1. 修改`config.toml`配置文件
2. `certsign serve [flags]` 启动服务端

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--config` | `./config.toml` | 配置文件路径 |

**端点**: `POST /sign` (签名), `GET /healthz` (存活)

> 详细协议见 [docs/api.md](docs/api.md)

## 客户端

`certsign [flags] <File Path>`, 签名后**原地覆盖**输入文件.

**无需配置文件**: server/token/timeout 可通过命令行或环境变量传入.

| 优先级 | 方式 | 示例 |
|--------|------|------|
| 高 | 环境变量 | `CERTSIGN_SERVER`, `CERTSIGN_TOKEN`, `CERTSIGN_TIMEOUT` |
| 中 | 命令行 | `--server`, `--token`, `--timeout`, `--output`, `--insecure` |
| 低 | 配置文件 | `[client]` 段 (可选, `--config` 指定路径) |

常用: `certsign --server http://10.0.0.5:8000 --token mytoken myapp.exe`

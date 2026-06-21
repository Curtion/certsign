# 说明

针对`Certum 云代码证书`签名的一个服务, 提供一个HTTP接口, 供用户上传文件进行签名.

[原理参考](https://www.devas.life/how-to-automate-signing-your-windows-app-with-certum/)

# 使用方式

## 服务端

1. 修改`config.toml`配置文件
2. `certsign serve [flags]` 启动服务端

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--config` | `./config.toml` | 配置文件路径 |

**端点**: `POST /sign` (签名), `GET /healthz` (存活)

## 客户端

`certsign [flags] <File Path>`, 签名后**原地覆盖**输入文件.

**无需配置文件**: server/token/timeout 可通过命令行或环境变量传入.

| 优先级 | 方式 | 示例 |
|--------|------|------|
| 高 | 环境变量 | `CERTSIGN_SERVER`, `CERTSIGN_TOKEN`, `CERTSIGN_TIMEOUT` |
| 中 | 命令行 | `--server`, `--token`, `--timeout`, `--output`, `--insecure` |
| 低 | 配置文件 | `[client]` 段 (可选, `--config` 指定路径) |

常用: `certsign --server http://10.0.0.5:8000 --token mytoken myapp.exe`
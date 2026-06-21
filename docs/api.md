# HTTP API 协议

不用内置 CLI 客户端时, 可自行发送 HTTP 请求。内置 Go 客户端 (`internal/client`) 即协议的参考实现。

> 本协议为非标准 HTTP 协议, 使用 `application/x-ndjson` 后跟 raw 二进制流的两阶段响应。

## 认证

所有 `/sign` 请求需携带 `Authorization: Bearer <token>` 头, token 与服务端 `server.token` 配置一致。

## GET /healthz

```
GET /healthz
→ 200 {"ok":true}
```

无认证要求, 用于存活探针。

## POST /sign

**请求** — `multipart/form-data`, 字段:

| 字段 | 类型 | 说明 |
|------|------|------|
| `file` | binary | 待签名文件, 表单字段名固定为 `file` |

**响应** — 分两阶段, 按顺序:

1. **ndjson 事件流** — `Content-Type: application/x-ndjson`, 每条事件是一行 JSON (以 `\n` 结尾)。事件按顺序发送, 客户端逐行解析。
2. **raw 二进制流** — `done` 事件后, 响应体剩余部分即签名后的文件字节, 长度 = `done` 事件的 `bytes` 字段值。客户端需精确读取该字节数 (不能依赖 EOF, 因为反代可能保持连接)。

**响应头**
- `Content-Type: application/x-ndjson` 指示已进入事件流
- `X-Content-Type-Options: nosniff`

**前置错误** (在 ndjson 流建立之前返回)

这些响应以 `Content-Type: application/json` 返回, 不是 ndjson:

| HTTP 状态 | 含义 | 响应体 |
|-----------|------|--------|
| 401 | token 不匹配 | `{"error":"unauthorized"}` |
| 503 | 签名队列满 | `{"error":"overloaded"}` |
| 400 | 请求格式错误 | `{"error":"..."}` (如 `missing file field`, `invalid multipart: ...`) |
| 405 | 非 POST 方法 | `{"error":"method not allowed"}` |

## ndjson 事件类型

每条事件 JSON 均含 `"type"` 字段, 取值如下:

| type | 出现时机 | 关键字段 |
|------|----------|----------|
| `status` | 上传完成时 | `phase:"uploaded"`, `size`(int), `filename`(string) |
| `status` | 签名流程状态变更 | `phase`(string), `msg`(string, 可选) — `phase` 取值: `login` / `relogin` / `signing` |
| `log` | signtool 实时输出 | `stream:"stdout"` 或 `stream:"stderr"`, `line`(string) |
| `done` | 签名成功, 即将发送二进制 | `bytes`(int) — 签名后文件大小, **此后响应切 raw, 不再有 ndjson** |
| `error` | 签名失败 | `phase`(string), `msg`(string, 可选), `exit_code`(int, 可选), `stderr_tail`(string, 可选) |

- `done` 必定是事件流的最后一行 JSON
- `done` 之后不再有 `\n` 分隔符, 客户端应切换到按 `bytes` 计数的原始读取
- `error` 的 `phase` 可能为: `login` (登录失败), `signtool` (签名工具失败), `internal` (超时/内部错误)
- `status` 的 `phase` 由 session 状态机发送, 具体值见 `internal/session` 中的 `Event` 定义

## 完整流程

```
客户端                                服务端
  |                                     |
  |-- POST /sign (multipart file) ---->|
  |                                     |-- 前置检查 (auth, 队列, 格式)
  |                                     |-- 若失败: HTTP 4xx/5xx + JSON error
  |                                     |
  |<--- ndjson: status(uploaded) -------|
  |<--- ndjson: status(login/relogin/signing) --|  (可能有多个)
  |<--- ndjson: log(...) --------------|  (0 或多个, signtool 实时输出)
  |                                     |
  |<--- ndjson: done{bytes:N} ----------|
  |<--- raw binary (N bytes) -----------|  (签名后文件, 无分隔符)
  |                                     |
  |       或: 签名失败                  |
  |<--- ndjson: error{...} -------------|
```

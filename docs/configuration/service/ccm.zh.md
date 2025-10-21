---
icon: material/new-box
---

!!! question "自 sing-box 1.13.0 起"

# CCM

CCM（Claude Code 多路复用器）服务是一个代理服务器，允许使用 API 密钥身份验证代替 OAuth 来访问 Claude Code API。

它处理与 Claude API 的 OAuth 身份验证，并允许客户端通过 `x-api-key` 头使用简单的 API 密钥进行身份验证。

### 结构

```json
{
  "type": "ccm",

  ... // 监听字段

  "credential_path": "",
  "usages_path": "",
  "users": [],
  "headers": {},
  "detour": "",
  "tls": {}
}
```

### 监听字段

参阅 [监听字段](/zh/configuration/shared/listen/) 了解详情。

### 字段

#### credential_path

Claude Code OAuth 凭据文件路径。

如果未指定，使用 `~/.claude/.credentials.json`。

在 macOS 上，首先从系统钥匙串读取凭据，然后回退到文件。

刷新的令牌会写回相同位置。

#### usages_path

用于存储聚合 API 使用统计信息的文件路径。

如果未指定，使用跟踪将被禁用。

启用后，服务会跟踪并保存统计信息，包括请求计数、令牌使用量（输入、输出、缓存读取、缓存创建）以及基于 Claude API 定价计算的美元成本。

统计信息按模型、上下文窗口（200k 标准版 vs 1M 高级版）以及可选的用户（启用身份验证时）进行组织。

文件每分钟自动保存一次，并在服务关闭时保存。

#### users

用于 API 密钥身份验证的用户列表。

如果为空，不执行身份验证。

客户端使用 `x-api-key` 头和令牌值进行身份验证。

#### headers

发送到 Claude API 的自定义 HTTP 头。

这些头会覆盖同名的现有头。

#### detour

用于连接到 Claude API 的出站标签。

#### tls

TLS 配置，参阅 [TLS](/zh/configuration/shared/tls/#inbound)。

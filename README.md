# Hyperdown 自动签到

针对 [hyperdown.net](https://hyperdown.net) 的每日自动签到脚本。用 Python 标准库完整复刻了客户端的加密请求协议（X25519 + XChaCha20-Poly1305），不依赖任何第三方包。

另外附带一个 Windows PowerShell 工具，用来从 Hyperdown 客户端的本地加密文件里取出登录 token。

> 本仓库**不包含任何 token**。首次使用需要自己从客户端取一份，见下文。

## 特性

- **零第三方依赖**：只需要 Python 3.8+，X25519 / ChaCha20 / Poly1305 / HKDF 都在脚本内部实现，`--selftest` 用 RFC 7748 官方测试向量校验。
- **token 自动续期**：access token 快过期时用 refresh token 换新的，并把新 token 原子写回状态文件。
- **幂等**：今天已签到会正常返回成功，不会报错。
- **凭据不落库**：token 只存在 `~/.hyperdown_checkin.json`（权限 0600），仓库和脚本里都没有硬编码凭据。

## 文件说明

| 文件 | 作用 |
|---|---|
| `hyperdown-checkin.sh` | 签到主脚本。sh 外壳 + 内嵌 python3，单文件即可运行 |
| `hyperdown-token.ps1` | Windows 端解密工具，从客户端本地 vault 中取出 token |
| `~/.hyperdown_checkin.json` | 运行时状态文件（access / refresh token），**不要提交到版本库** |

## 快速开始

### 1. 准备 token

**方式 A：从 Windows 客户端导出（推荐）**

Hyperdown 客户端把登录态加密存在本地，密钥放在 Windows 凭据管理器里（目标名 `Hyperdown Local Vault:file-encryption-key-v1`）。这个脚本可以解出来并直接写成签到脚本要的状态文件：

```powershell
# 只查看解密结果
powershell -ExecutionPolicy Bypass -File .\hyperdown-token.ps1 D:\Hyperdown\data\session.json

# 查看并同步到 ~/.hyperdown_checkin.json
powershell -ExecutionPolicy Bypass -File .\hyperdown-token.ps1 D:\Hyperdown\data\session.json -WriteState
```

**方式 B：用环境变量提供**

```sh
export HYPERDOWN_ACCESS_TOKEN='...'
export HYPERDOWN_REFRESH_TOKEN='...'
```

状态文件的优先级最高：只要 `~/.hyperdown_checkin.json` 存在且两个 token 都不为空，就不会读环境变量。

### 2. 运行

```sh
./hyperdown-checkin.sh                  # 执行签到
./hyperdown-checkin.sh --status         # 查看账号状态、今日是否已签到、剩余流量
./hyperdown-checkin.sh --selftest       # 校验内置加密实现（不联网）
./hyperdown-checkin.sh --state FILE     # 指定状态文件路径
./hyperdown-checkin.sh -q               # 静默模式，适合放定时任务
```

`--status` 输出示例：

```
账号: you@example.com
今日已签到: 是
累计签到: 42 天
最近签到: 2026-10-26T08:15:03Z
可用流量: 123.45 GB
```

### 3. 定时任务

```cron
15 8 * * * /path/to/hyperdown-checkin.sh -q >> /var/log/hyperdown-checkin.log 2>&1
```

## 加密协议说明

签到接口不是普通的 REST 调用，每个请求都要封装成一版自定义「信封」（`X-Hyperdown-Secure: v1`）。脚本里的实现如下：

1. 生成 X25519 临时密钥对，与服务端公钥做 ECDH 得到共享密钥；
2. 用 HKDF-SHA256 派生会话密钥：
   `salt = SHA256("<request_id>:<ts>")`，
   `info = "hyperdown-secure-api:v1:" + METHOD + ":" + path`；
3. 用 XChaCha20-Poly1305 加密 payload，AAD 为 `METHOD\npath\nrequest_id\nts`；
4. 用会话密钥对
   `v1\0METHOD\0path\0request_id\0ts\0nonce\0pub\0ciphertext\0access_token`
   做 HMAC-SHA256 签名；
5. 请求体是 JSON：`{v, request_id, ts, nonce, pub, ciphertext, sign}`。

请求本身仍然带 `Authorization: Bearer <access_token>`，加密层只是额外的一层完整性/防重放保护。

## 注意事项

- **refresh token 会轮换**：服务端每次刷新都会签发新的 refresh token，旧的立即失效。所以状态文件不能丢，也不要在脚本之外（比如客户端里）同时刷新同一个账号，否则两边会互相踢下线。
- **需要准确的系统时间**：时间偏差过大会返回 `secure_request_expired`，先校准 NTP。
- **协议是逆向自客户端的**：服务端随时可能改动，改动后脚本会失效。请以学习和个人使用为目的。
- 如果你用过早期版本（脚本里内嵌过默认 token），建议在客户端重新登录一次换一份新 token。

## 免责声明

本项目仅用于个人账号的自动化签到与协议学习，与 Hyperdown 官方无关。请遵守服务条款，不要用于批量、多账号或任何滥用场景。

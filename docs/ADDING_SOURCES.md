# 新增订阅源指南 / Adding a subscription source

> 本仓库是公开仓库：订阅 URL、凭据、节点数据永远不进 Git。所有凭据只活在
> Actions Secrets 和 Sub-Store 里。/ This repository is public: subscription
> URLs, credentials and node data never belong in Git.

## 情况 A：普通订阅（绝大多数情况）— 零 Actions 改动

/ Case A: an ordinary subscription — no Actions change needed.

1. 在 Sub-Store（hk3）里新增一个 sub，填上游订阅 URL。
2. 命名避开保留前缀：`probe-`、`chain-`、`rust-`（这些是本管线自己的产物名，
   会被 `selected_source` 排除以防自反馈回路；`测活-DMIT`、`官方可用` 两个名字
   同样被排除）。
3. 结束。下一轮测活（cron `23 */6 * * *` 或手动 dispatch）会自动发现并测它：
   源列表来自 `GET /api/subs` 的实时读取，代码不需要知道任何一个源的存在。
4. 测活后，每源文件保存在私有状态仓库的 JSON bundle 中，读取需要认证。
   Gist 只发布合并的 `mihomo-alive.yaml`。按源导入需要能认证的适配服务或
   本地文件，不能再给 Sub-Store 添加匿名的 `source-*.yaml` Gist URL。
   已有部署参见 [安全迁移说明](SECURITY_MIGRATION.md)。

## 情况 B：需要独立凭据的源 — 只改一个 Secret 的值

/ Case B: a source that needs its own credential — update one Secret's value.

有些上游不是"拿 URL 就能拉"：可能要 `Authorization` 头、可能要 token 查询参数、
甚至完全托管在别的主机上。为此代码预留了**一个**入口：

- Actions Secret：`SOURCE_SECRETS_JSON`（`.github/workflows/probe-all.yml` 已
  挂好 `SOURCE_SECRETS_JSON: ${{ secrets.SOURCE_SECRETS_JSON }}`，永远不用改）。
- 值是一个 JSON map，键 = **Sub-Store 里显示的源名**（精确匹配，支持中文）：

```json
{
  "某机场":   { "header": { "Authorization": "Bearer xxx" } },
  "token源":  { "query": { "token": "abc123" } },
  "外部源":   { "url": "https://other-host.example/sub?token=abc123&target=ClashMeta" }
}
```

| 字段 | 作用 | 备注 |
|---|---|---|
| `header` | 拉取该源时附加的 HTTP 头 | 拉源列表不受影响，只作用于该源的 `/download/` 请求 |
| `query` | 追加/覆盖 URL 查询参数 | 与 `?target=ClashMeta` 合并，同名参数以此处为准 |
| `url` | 整条 URL 覆盖（源不在本 Sub-Store 时用） | 必须 HTTPS、不带 userinfo 或 fragment；重定向/大小限制照常生效 |

三个字段都可选，但每条至少要有一项；未知字段、形状不对、JSON 坏了都会以
固定错误码 `source_secrets_invalid` 失败——**凭据片段永远不会进日志**（日志
只有固定错误码，GitHub 又对 secret 值做精确打码，双保险）。

操作步骤：

1. Repo → Settings → Secrets and variables → Actions → 新建/更新
   `SOURCE_SECRETS_JSON`，粘贴整个 JSON map（已有源的条目原样保留）。
2. 手动 dispatch 一次 `probe-all.yml` 验证（日志里该源应正常进入测量；若配错
   会看到 `source_secrets_invalid` 或该源的 `source_failure`，不会半发布）。
3. 之后加第 N 个源：重复第 1 步改 secret 值即可，**不改代码、不改 workflow**。

## 轮换凭据 / Rotating a credential

同情况 B 第 1 步：更新 `SOURCE_SECRETS_JSON` 里对应源的值 → dispatch 验证。
没有缓存层要清，下一轮拉取即用新值。

## 安全规则（不变量）

- secret 值绝不写进本仓库、issue、日志或聊天记录；GitHub 对 Actions 日志里的
  secret 做精确匹配打码，但不要依赖它做变换（URL 编码/截断都会绕过打码）。
- `SOURCE_SECRETS_JSON` 本身只经环境变量进入主脚本内存，不传给 mihomo/curl/SSH
  子进程环境，不进 artifact 或 Gist。拉取结果中的节点连接凭据仍会出现在
  私有临时配置、私有状态及合并订阅中，连接所需的凭据不能靠脱敏去掉。
- 若某个源的凭据泄露：直接更新 secret 值（轮换），旧值即刻失效于本管线。

## 代码挂载点（评审用）

- 解析与校验：`actions_probe_all.load_source_secrets()`（固定错误码、形状校验、
  scheme/host 校验）。
- 应用：`SubStore.config(name)` —— `url` 覆盖 / `query` 合并 / `header` 透传给
  `Transport`（重定向与 32MB 上限纪律不变）。
- 接线：`run()` 里 `SubStore(base, transport, source_secrets=load_source_secrets(env))`。
- 测试：`tests/test_actions_probe_all.py::SourceSecretsTests`（离线 stub transport）。

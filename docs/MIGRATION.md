# 测活迁移记录（2026-11-18）

## 结论

所有订阅测活已从 hk3 / LXC 上的旧脚本迁到 GitHub Actions（私有仓库
`omaler886/proxy-probe-actions`），测活结果只写固定 Gist 文件，**不回写 Sub-Store**。

## 链路

```
Sub-Store (只读 GET)
   └─ /api/subs 取源列表 → /download/<name>?target=ClashMeta 取节点
GitHub Actions runner (ubuntu-24.04, mihomo v1.19.29 固定校验)
   ├─ 逐节点依赖闭包 mihomo -t 校验（不支持的协议单独剔除，不污染整源）
   ├─ 每节点固定 loopback HTTP listener → curl 显式代理 → cloudflare.com/cdn-cgi/trace
   ├─ 只认 trace 返回的 ip + loc（公网地址 + 合法国家码），无直连降级、无出口缓存
   └─ 重命名：<源标签>-<国家>-<协议>-<出口hash>-<连接指纹>
Gist 599bdba3…（public:false）
   ├─ mihomo-alive.yaml（合并）
   ├─ source-<sha256(源名)>.yaml（每源一份固定文件）
   ├─ manifest.json（源名/计数/digest/保旧标记）
   └─ hb-full.yaml（旧控制器产物，发布器不碰）
```

## GlaDOS 去重规则

按**实测出口 IP** 分组：同出口多入口只留一条，组内优先 `ss`（再按连接指纹稳定排序）；
组内没有 SS 就保留一条确定性成员。**独立出口不做协议过滤**——AnyTLS/Trojan 等照常保留。

实测（2026-11-18）：54 个存活 → 10 个出口 → 落 9 条 SS + 1 条独立出口的 AnyTLS。

## 用户指定七源实测（2026-11-18）

| 源 | 输入 | 存活 | 发布 | 国家 |
|---|---|---|---|---|
| ikunkun | 7 | 1 | 1 | JP |
| pokenmen | 32 | 24 | 24 | HK/JP/SG/US |
| 健康中心 | 44 | 8 | 8 | HK/JP/SG/TW/US |
| prologue | 109 | 78 | 78 | 15 国（NL 13 / US 21 / IT 8 …） |
| 233pio | 1 | 1 | 1 | AU |
| saki | — | 0 | 保旧 | Sub-Store 上游 500，拿不到节点 |
| glados | 54 | 54 | 10 | JP/SG/TW/US，出口去重 |

## 全源实测（2026-11-18，42 源）

1502 个输入节点、574 个取得有效 trace、26 个源成功发布。

失败的 16 个源分三类，都不是「节点真的死了」：

1. **重名节点把整源打挂**（已修）：`dafeng` 40 条只有 16 个名字、`node-swapped` 275 条 97 个重名、
   `sssssss-alive2` 95 条 65 个重名。内核按名字索引会静默丢重名项，旧脚本是自动加 `#2` 后缀；
   新脚本原先直接让整源报错。现已改为确定性改名（首个保留原名，后续加后缀）。
2. **Sub-Store 上游取数 500**：`saki`、`lw家宽`、`美国 puredns`、`收集的节点`、`三网cf`。
   这是 Sub-Store 侧的问题（同样的 500 在 hk3 上直接复现），不是测活结论。
3. **链式依赖解析不到**：`warp` 等 `dialer-proxy` 指向 `香港`/`日本` 这类来自其它订阅的节点名，
   解析不到就按失败关闭处理——**不会**把带链节点降级成直连去测（否则测的是它自己的 server，
   客户端根本不会那样用）。

## 旧执行器下线

| 位置 | 状态 | 证据 |
|---|---|---|
| hk3 `substore-probe.timer` / `-weekly.timer` | 已 disable + stop | `UnitFileState=disabled`、`ActiveState=inactive` |
| hk3 `probe-agent.service` / `mihomo-probe-agent.service` | 已 disable + stop | 同上 |
| hk3 `substore-backup.timer` | 保留 | `active`（与测活无关） |
| Sub-Store 文件区 | 14 个配置，0 个 `probe-/chain-/rust-` 产物 | API 复核 |
| Sub-Store 订阅 | 111 条未删 | 本地订阅含手写原始节点清单，不能按 `source: local` 批量删 |
| LXC2 / LXC5 上的旧测活 | **未停用（机器不可达）** | `<LXC_ENTRY>:<PORT>`、`<LXC_ENTRY>:<PORT>` 与 IPv6 直连都 NOBANNER/OSError，SSH 进不去 |

LXC 那两台恢复 SSH 后仍需单独停用，否则可能继续写回 Sub-Store。

## Sub-Store 侧迁移（2026-11-18）

测活产物不再存进 Sub-Store，改成「Sub-Store 只持有稳定 URL」：

- 新建 11 个远程订阅 `gist-<源>`，URL 用 **不带 revision** 的 Gist raw 形式
  `https://gist.githubusercontent.com/omaler886/599bdba3…/raw/source-<sha256>.yaml`（实测 200，
  永远指向最新 revision，不会因为发布产生新地址）。
- 5 个用户集合（`air` / `测说` / `ss-air` / `非优化` / `sssssss-alive`）的成员从
  `probe-<源>-local` 换成 `gist-<源>`，改完逐个下载校验：91 / 28 / 27 / 22 / 76 条，均可正常下载。
- 删除 **67** 个无引用的旧测活订阅（`probe-*` / `chain-*` / `rust-*`），订阅总数 122 → 55。
- 保留 1 个：`probe-美国 puredns-local`——该源在 Actions 侧还没产出成功产物，
  集合 `sssss` 仍引用它，删了会让集合变空。等该源恢复自愈后按同一脚本替换。
- 迁移前备份：`/root/substore-sync/actions-migration-20261118/collections-before-gist-migration.json`
  与 `files-backup-20261118/subs/`（111 条订阅全文）。

删除接口备忘：订阅走 `DELETE /api/sub/<name>`；`/api/file/<name>` 是文件区，对订阅名返回 500。

## 已知上游问题

`saki` 的订阅 URL（`saki.tomorin.xyz`）在 hk3 上直接请求返回 **HTTP 404**，Sub-Store 因此
`/download/saki*` 报 500、0 节点。这是机场侧链接失效，不是测活结论。

## 安全边界

- Gist `public: false` 只是**不被列出**，任何拿到 raw URL 的人都可读——订阅正文含节点凭据。
- 订阅正文与内核配置只落临时 runner 目录（0700/0600），**不上传为 Actions artifact 或缓存**。
- 日志只输出计数与（显式筛选时的）源名，不输出 URL、节点名、server、密码、raw IP。
- 发布器拒绝写 `public: true` 的 Gist；`hb-full.yaml` 等非受管文件不参与比较也不被覆盖。
- GitHub Gist PATCH 不支持 `If-Match`（实测 HTTP 400 "Conditional request headers are not allowed
  in unsafe requests"）。改为 workflow 串行 + 写前重读受管文件快照比对，**不是**服务端 CAS，
  所以不要给这些受管文件再加第二个写者。
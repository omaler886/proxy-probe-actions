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
Gist `<GIST_ID>`（public:false）
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

## 全源实测（2026-11-18，最终一轮 run 44258889966）

- **42 个源 / 1483 个输入节点 / 739 个取得有效 trace / 29 个源发布 / 13 个源保旧**
- Gist：`public:false`，29 个 `source-*.yaml` + `mihomo-alive.yaml`（**522** 条合并节点）+ `manifest.json`，
  `hb-full.yaml` 未动；`gist-*` 自引用产物已删除。
- 回归中修掉的两个真实缺陷：
  1. **自引用回路**：Sub-Store 集合改成 `gist-*` 远程订阅后，下一轮把这些自己的产物当上游又测了一遍
     （53 源 / 1793 节点）。`selected_source()` 现在排除 `gist-` 前缀。
  2. **残留产物不清**：发布器默认保留“不在本轮列表里的远端源”，导致上一轮误测的 `gist-glados`、
     `gist-ikunkun` 永久留在 Gist。现在自引用产物在同一次 PATCH 里以 `{"content": null}` 删除。

### 13 个保旧源的原因（都不是“节点全死”）

| 源 | 输入 | 判定 | 真实原因 |
|---|---|---|---|
| 美国 puredns | 105 | zero_alive | Sub-Store 里该订阅的 URL **指向自己的实例且内含换行**，请求即 `InvalidURL`；需要在 Sub-Store 改 URL |
| saki | 0 | source_failure | 上游 `<UPSTREAM_HOST>` 返回 **404**，链接失效 |
| lw家宽 | 0 | source_failure | 上游 `lw.isdo.dpdns.org/uqn/buniq` 返回 **404** |
| dafeng-s | 50 | zero_alive | 香港视角抽样 6 个也 0 存活（对照组 prologue 5 抽样 4 活）→ 节点确实不可用 |
| dafeng | 40 | zero_alive | 同上，且原订阅 40 条只有 16 个不同名字（已由 `dedupe_names` 修掉整源打挂） |
| warp | 16 | zero_alive | 全部带 `dialer-proxy` 指向 `香港`/`日本`，依赖节点不在任何可取订阅里 → 按失败关闭，不降级成直连 |
| lxc-us-ports | 11 | zero_alive | 指向 NAT LXC 池机，池子本身 SSH/端口长期 NOBANNER |
| NTT-verify / NTT / hk-cf / CM-CF | 6/1/2/1 | zero_alive | 单点或少量节点，trace 不通 |
| 收集的节点 / 三网cf | 3/3 | zero_alive | 极小本地源，入口为 CF 前置域名，trace 穿不过去 |

### 最终可用性复核（hk3 上 API 实测）

- 11 个 `gist-*` 订阅全部可下载：2177=12、233pio=2、ai=26、bamboo=22、fe=16、glados=10、ikunkun=1、
  pokenmen=24、prologue=72、purens=142、健康中心=8
- 12 个集合中 11 个正常（air=92、ssss=28、CDN=6、xray-opencode=1、中国地区=17、混合subfree=26、
  测说=28、ss-air=25、非优化=22、去除大妈系列 亚太地区=29、sssssss-alive=76）；
  `usa` 下载报错，但**迁移前它本来就是空集合**（`subscriptions: []`，已用迁移前备份核对），与本次迁移无关。
- 剩余旧测活订阅只有 `probe-美国 puredns-local`（集合 `sssss` 仍在引用，等该源恢复后替换）。

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
  `https://gist.githubusercontent.com/<OWNER>/<GIST_ID>/raw/source-<sha256>.yaml`（实测 200，
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

`saki` 的订阅 URL（`<UPSTREAM_HOST>`）在 hk3 上直接请求返回 **HTTP 404**，Sub-Store 因此
`/download/saki*` 报 500、0 节点。这是机场侧链接失效，不是测活结论。

## 安全边界

- Gist `public: false` 只是**不被列出**，任何拿到 raw URL 的人都可读——订阅正文含节点凭据。
- 订阅正文与内核配置只落临时 runner 目录（0700/0600），**不上传为 Actions artifact 或缓存**。
- 日志只输出计数与（显式筛选时的）源名，不输出 URL、节点名、server、密码、raw IP。
- 发布器拒绝写 `public: true` 的 Gist；`hb-full.yaml` 等非受管文件不参与比较也不被覆盖。
- GitHub Gist PATCH 不支持 `If-Match`（实测 HTTP 400 "Conditional request headers are not allowed
  in unsafe requests"）。改为 workflow 串行 + 写前重读受管文件快照比对，**不是**服务端 CAS，
  所以不要给这些受管文件再加第二个写者。
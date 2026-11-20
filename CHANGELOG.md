# Changelog

本项目遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## v1.0.2 — 2026-11-20

### 修复

- **非法 IPv4 被静默当成域名**：`ban add 300.1.1.1`、`ban add 1.2.3` 这类输入过去会通过域名校验，只往 DNS 层写了一条无效记录，IP 层完全没有下发——用户以为封了 IP，实际什么都没拦。现在顶级标签为纯数字的输入不再视为域名，并明确报错：`非法 IP 地址: 300.1.1.1（如果确实是域名，请加 --type domain）`
- **`make` 直接失败**：版本号提取的 sed 正则里括号未转义，提前闭合了 `$(shell ...)`，导致 `*** 对函数“shell”的未终止的调用`

### 测试

- 单元测试新增 6 项断言（越界 IPv4、三段数字、纯数字顶级标签、数字标签域名、单标签主机名）
- 新增 `tests/edge-cases.sh`：10 组边界用例（域名归一化、重复去重、非法输入、空配置目录、`0.0.0.0` 删除歧义、`ipv6` 开关、stdin/stdout 管道、过期过滤、flush 清理、20 并发写）

## v1.0.1 — 2026-11-08

修复 dnsmasq 被系统网络管理接管导致阻断静默失效的问题。

### 修复

- **NetworkManager 接管 dnsmasq**：NM 会用自带的 `--conf-file` 启动 dnsmasq，既不读 `/etc/dnsmasq.d`，还会在每次网络事件后重启它。现在：
  - 同时写入 `/etc/dnsmasq.d/ban.conf` 与 `/etc/NetworkManager/dnsmasq.d/ban.conf`
  - 重载链覆盖 `dnsmasq.service`、sysv `service`、NM 托管（`nmcli general reload dns-rc`、`systemctl reload NetworkManager`）
  - **不再"顺手启动"未运行的 dnsmasq**，也不重启 NetworkManager（避免中断用户网络）
- **生效性探测 + 自动回退**：写入后真实解析一个被封禁域名，若拿不到 `0.0.0.0` 就判定 dnsmasq 未生效，自动回退到 hosts 托管区块并记录告警，不再出现"配置写了但没拦住"
- **模式切换清理**：在 dnsmasq 与 hosts 之间切换时自动清除另一层的残留配置，避免两套规则并存或陈旧残留
- **NM dispatcher 钩子**：`ban install` 现在会安装 `/etc/NetworkManager/dispatcher.d/50-ban`，在 `up/vpn-up/dhcp*-change` 等事件后自动重新下发规则；`ban uninstall` 会移除
- 新增配置项 `resolv_conf`、`dnsmasq_dir`，便于特殊 DNS 环境与测试
- `ban doctor` 增加 NetworkManager 运行状态、NM drop-in 目录、dispatcher 钩子的检查

### 测试

- 新增 `tests/dns-fallback.sh`：6 项回归（未运行→回退、auto 降级、模式切换清理、hosts 幂等、关闭 DNS 层、dnsmasq 真生效时不误降级）

## v1.0.0 — 2026-11-08

首个正式版本。

### 功能

- **双层阻断**：DNS 层（dnsmasq drop-in / `/etc/hosts` 托管区块）+ 防火墙 IP 层（nftables 集合 / ipset）
- **无常驻进程**：规则常驻内核；开机由 `ban-restore.service`（oneshot）恢复，域名 IP 变化由 `ban-refresh.timer` 定期刷新
- **临时封禁自动过期**：`ban add example.com --for 30m`，利用 nftables / ipset 原生 timeout，到期由内核移除
- **白名单最高优先**：内置回环、链路本地、组播；`ban allow add|del|list` 管理
- **后端自动探测**：nftables 优先，缺失时回退 iptables（有 ipset 用集合，否则逐条规则）
- **CLI**：`add` / `del` / `list` / `status` / `enable` / `disable` / `flush` / `refresh` / `gc` / `allow` / `export` / `import` / `install` / `uninstall` / `restore` / `doctor`
- **JSON 输出**：`--json` 适用于 `list`、`status`、`allow list`
- **环境自检**：`ban doctor` 检查后端、dnsmasq、nsswitch、上游 DNS、systemd timer

### 工程实现

- C++17，零第三方依赖；`-static-libstdc++ -static-libgcc`，另提供全静态构建
- 状态持久化采用 `flock` 串行化 + 临时文件 `rename` 原子替换
- 规则下发采用「全量重渲染 + 单事务 `nft -f`」，无规则空窗期
- 自建 UDP DNS 客户端直问上游，避免 hosts 封禁导致自身解析到 `0.0.0.0`
- 内核不支持集合 `timeout` 时自动逐级降级并告警，过期改由 `ban gc` 兜底

### 发行产物

| 文件 | 说明 |
| --- | --- |
| `ban_1.0.0_amd64.deb` | Debian / Ubuntu |
| `ban-1.0.0-1-x86_64.pkg.tar.zst` | Arch / CachyOS / Manjaro |
| `ban-1.0.0-1.x86_64.rpm` | openSUSE / Fedora / RHEL |
| `ban-1.0.0-x86_64-linux.tar.gz` | 便携二进制（动态链接 glibc） |
| `ban-1.0.0-x86_64-linux-static.tar.gz` | 全静态二进制 |
| `ban-1.0.0.tar.gz` | 源码包（`rpmbuild -ta` 可重打包） |
| `SHA256SUMS` | 校验和 |

### 测试

- 单元测试 35 项断言
- `tests/integration.sh`：隔离 netns 内 12 项功能测试
- `tests/blocking.sh`：真实连接验证（封禁生效 / 白名单优先 / 清理恢复）

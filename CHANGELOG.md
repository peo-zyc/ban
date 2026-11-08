# Changelog

本项目遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

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

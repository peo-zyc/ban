# ban — Linux 域名 / IP 封禁 CLI

用一条命令封禁域名或 IP，规则直接落到内核（nftables / ipset），**不需要任何常驻进程**。
开机由 systemd oneshot 恢复，域名 IP 变化由 systemd timer 定期刷新。

```
$ sudo ban add example.com --for 30m
$ sudo ban add 203.0.113.0/24 --comment "恶意网段"
$ ban list
$ ban status
```

## 特性

- **无常驻进程**：规则是内核状态；`ban` 只在执行命令那一刻存在
- **双层阻断**：DNS 层（dnsmasq / `/etc/hosts` 托管区块）+ 防火墙 IP 层（nftables 集合 / ipset）
- **自动过期**：`--for 30m` 利用 nftables / ipset 的原生 timeout，超时由内核自动移除
- **白名单最高优先**：默认内置回环、链路本地、组播，防止自锁
- **后端自动探测**：优先 nftables，缺失时退回 iptables（有 `ipset` 则用集合，否则逐条规则）
- **崩溃安全**：`flock` 串行化 + 临时文件 `rename` 原子替换
- **零第三方依赖**：C++17，静态链接 libstdc++，单个二进制可拷到其它发行版
- **配置可迁移**：`export` / `import`（JSON 或文本格式）

## 原理

```
ban add example.com
        │
        ├─→ resolver（自建 UDP DNS 客户端，绕过 /etc/hosts）
        │        └─→ IP 集合：nft set `inet ban banned_v4/v6`（带 timeout）
        │
        └─→ DNS 层：dnsmasq `address=/example.com/0.0.0.0`
                 或 /etc/hosts 托管区块

ban install
        ├─→ ban-restore.service   开机 oneshot：按已保存配置重建规则
        └─→ ban-refresh.timer     每 10 分钟：重新解析域名 + 清理过期规则
```

关键点：

- 防火墙规则在 `output` 与 `forward` 两个 hook 上都生效，因此**容器/NAT 出站同样被拦**
- 每次变更采用「全量重渲染 + 单事务提交」，`nft -f` 原子生效，没有规则空窗期
- 域名解析走**自建的 UDP DNS 客户端**，直接问真实上游，避免「DNS 层已封禁 → 自己解析到 0.0.0.0」的自锁

## 构建与安装

需要 `g++`（C++17）或 `cmake ≥ 3.16`。

```bash
# 方式一：Makefile
make
sudo make install

# 方式二：CMake
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
sudo cmake --install build
```

部署到系统（写入 systemd 单元、启用开机恢复与定时刷新）：

```bash
sudo ban install
```

`ban install` 会：

1. 创建 `/etc/ban`，写入默认 `ban.conf`
2. 把自身复制到 `/usr/local/bin/ban`
3. 生成并启用 `ban-restore.service`、`ban-refresh.service`、`ban-refresh.timer`
4. 立即按当前配置下发一次规则

常用参数：`--bindir 目录`、`--interval 分钟`、`--backend nft|iptables|auto`、`--action reject|drop`、`--no-systemd`。

### 直接使用发行包

从 [Releases](https://github.com/peo-zyc/ban/releases) 下载对应产物：

| 文件 | 适用系统 | 安装方式 |
| --- | --- | --- |
| `ban_1.0.0_amd64.deb` | Debian / Ubuntu | `sudo dpkg -i ban_1.0.0_amd64.deb` |
| `ban-1.0.0-1-x86_64.pkg.tar.zst` | Arch / CachyOS / Manjaro | `sudo pacman -U ban-1.0.0-1-x86_64.pkg.tar.zst` |
| `ban-1.0.0-x86_64-linux.tar.gz` | 任意 glibc 发行版 | 解压后 `install -Dm755 ban /usr/local/bin/ban` |
| `ban-1.0.0-x86_64-linux-static.tar.gz` | 无依赖（全静态） | 同上，可跑在任意 x86_64 Linux |
| `ban-1.0.0.tar.gz` | 源码包 | `rpmbuild -ta ban-1.0.0.tar.gz`（openSUSE / Fedora） |

装完执行一次 `sudo ban install` 即可。

自行从源码构建全部发行包：

```bash
sh packaging/build-release.sh        # 产出到 dist/，含 SHA256SUMS
```

> openSUSE / Fedora 的 RPM 需要 `rpmbuild`（`sudo zypper install rpm-build`），spec 见 `packaging/rpm/ban.spec`。

## 命令

| 命令 | 说明 |
| --- | --- |
| `ban add <域名\|IP\|CIDR>...` | 添加封禁；`--for 30m` 临时、`--comment` 备注、`--type` 强制类型、`--no-dns` 跳过解析 |
| `ban del <ID\|目标>...` | 删除（支持按 ID、域名、IP、CIDR） |
| `ban list` | 列出规则；`--json`、`--expired`、`--type domain\|ip\|cidr` |
| `ban status` | 后端、规则数、集合条目、拦截流量、DNS 方式、timer 状态 |
| `ban enable` / `ban disable` | 启用 / 停用（规则保留） |
| `ban flush` | 清空全部规则并移除防火墙与 DNS 阻断；`--all` 同时重置白名单 |
| `ban refresh` | 重新解析所有域名并更新 IP 集合 |
| `ban gc` | 清理已过期规则 |
| `ban allow add\|del\|list <CIDR>` | 白名单管理（优先级高于封禁） |
| `ban export [文件]` | 导出；`--format json\|text`、`--output 文件` |
| `ban import [文件]` | 导入；`--replace` 覆盖而非合并，可读 stdin |
| `ban install` / `ban uninstall` | 系统集成 / 卸载；`uninstall --purge` 同时删除配置 |
| `ban restore` | 仅按已保存配置恢复（供 systemd 调用） |
| `ban doctor` | 环境自检 |

全局选项：`--json`、`--etc-dir 目录`、`-v/--verbose`、`-q/--quiet`、`-h/--help`、`-V/--version`。

退出码：`0` 成功、`1` 一般错误、`2` 用法错误、`3` 权限不足、`4` 依赖缺失、`5` 部分失败。

## 配置

`/etc/ban/ban.conf`：

```ini
backend = auto              # auto | nft | iptables
action = reject             # reject | drop
dns_mode = auto             # auto | dnsmasq | hosts | off
dns_enabled = true
ipv6 = true
enabled = true
refresh_interval_min = 10
hosts_file = /etc/hosts
log_file = /var/log/ban.log
```

状态文件（均由本程序管理，不要手工编辑）：

- `/etc/ban/rules.conf` — 规则（TAB 分隔，`# next_id=` 记录自增 ID）
- `/etc/ban/allow.conf` — 白名单（**删除该文件即恢复内置默认白名单**）
- `/etc/ban/cache.json` — 域名解析缓存
- `/etc/ban/rules.lock` — 写操作互斥锁

## 限制与注意事项

- **DoH / 自带解析器可绕过 DNS 层**：浏览器内置 DoH、应用自带 DNS 时，DNS 层无效。IP 层仍会拦（前提是解析到了正确 IP），但 CDN/共享 IP 场景可能误伤其它站点。
- **`hosts` 模式只做精确匹配**：不支持 `*.example.com` 通配。需要通配子域请安装并启用 `dnsmasq`（`dns_mode = dnsmasq`），本程序会写 `address=/example.com/0.0.0.0` 覆盖全部子域。
- **域名 IP 会变**：靠 `ban-refresh.timer` 定期刷新；解析失败时**保留旧结果**，不会误放行。
- **同 IP 多站点**：封 IP 会波及同 IP 的其它服务，按域名封禁更精准。
- **其它网络命名空间**：规则作用于宿主 netns；容器出站经过 `forward` 已被覆盖，但 `docker run --network host` 之外的独立 netns 需在对应 ns 内单独配置。
- **不接管系统已有防火墙**：只创建自己的 `table inet ban` / `BAN_OUT`、`BAN_FWD` 链。

## 故障排查

```bash
sudo ban doctor          # 环境自检：后端、dnsmasq、nsswitch、上游 DNS、timer
sudo ban status          # 规则是否真的落到内核
sudo nft list table inet ban
systemctl status ban-refresh.timer
journalctl -u ban-restore.service -u ban-refresh.service
```

常见问题：

| 现象 | 处理 |
| --- | --- |
| `nft 无法操作规则（需要 root）` | 用 `sudo` 运行 |
| 封禁后仍能访问 | `ban status` 看后端是否可用；确认应用是否走 DoH |
| 临时封禁到期没解除 | 内核不支持集合 timeout 时会降级，需 `ban gc`；把 timer 间隔调小 |
| 域名只拦了一部分子域 | 切到 `dns_mode = dnsmasq` |
| 误封导致无法上网 | `sudo ban flush` 立即清空 |

## 测试

```bash
make test                                  # 单元测试（无需 root）
sudo unshare -rn sh tests/integration.sh   # 隔离网络命名空间内的功能测试
sudo unshare -rn sh tests/blocking.sh      # 端到端验证：连接是否真的被阻断
```

## 许可证

[MIT](LICENSE) © 2026 peo-zyc

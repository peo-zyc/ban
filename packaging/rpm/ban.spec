%global _unitdir %{_prefix}/lib/systemd/system
%global debug_package %{nil}

Name:           ban
Version:        1.0.0
Release:        1%{?dist}
Summary:        Linux domain/IP blocking CLI with kernel-resident rules
License:        MIT
URL:            https://github.com/peo-zyc/ban
Source0:        %{name}-%{version}.tar.gz
BuildRequires:  gcc-c++
BuildRequires:  cmake >= 3.16
BuildRequires:  make
Requires:       glibc
Recommends:     nftables
Recommends:     iptables
Recommends:     ipset
Suggests:       dnsmasq

%description
ban 是一个 Linux 域名/IP 封禁命令行工具。

规则直接下发到内核 (nftables 集合或 ipset)，因此不需要任何常驻进程：
开机由 systemd oneshot 恢复规则，域名解析到的 IP 变化由 systemd timer 定期刷新。

支持 DNS 层 (dnsmasq / hosts 托管区块) 与防火墙 IP 层双层阻断、临时封禁自动过期、
白名单优先、配置导入导出与环境自检。

%prep
%setup -q

%build
cmake -S . -B build-rpm \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX=%{_prefix}
cmake --build build-rpm --parallel

%install
DESTDIR=%{buildroot} cmake --install build-rpm

install -d %{buildroot}%{_docdir}/%{name}
install -m644 README.md LICENSE %{buildroot}%{_docdir}/%{name}/

%post
echo ">>> 运行 'sudo ban install' 以启用开机恢复与定时刷新"

%files
%{_bindir}/ban
%{_unitdir}/ban-restore.service
%{_unitdir}/ban-refresh.service
%{_unitdir}/ban-refresh.timer
%doc %{_docdir}/%{name}/README.md
%doc %{_docdir}/%{name}/LICENSE

%changelog
* Sun Nov 08 2026 peo-zyc <peo-zyc@users.noreply.github.com> - 1.0.0-1
- Initial release

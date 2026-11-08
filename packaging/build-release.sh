#!/bin/sh
# 构建发布产物到 dist/：
#   - ban-<ver>-x86_64-linux.tar.gz          便携二进制包（动态链接 glibc）
#   - ban-<ver>-x86_64-linux-static.tar.gz   全静态二进制包（若可静态链接）
#   - ban_<ver>_amd64.deb                    Debian / Ubuntu
#   - ban-<ver>-1-x86_64.pkg.tar.zst         Arch / CachyOS / Manjaro
#   - ban-<ver>.tar.gz                       源码包（rpmbuild / OBS 用）
#   - SHA256SUMS
#
# 用法: packaging/build-release.sh [版本号]
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

VERSION=${1:-$(sed -n 's/^project(ban VERSION \([0-9][0-9.]*\).*/\1/p' CMakeLists.txt | head -1)}
[ -n "$VERSION" ] || { echo "无法确定版本号" >&2; exit 1; }

NAME=ban
ARCH=$(uname -m)
DIST="$ROOT/dist"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT INT TERM

rm -rf "$DIST" build-release
mkdir -p "$DIST"

echo "==> 编译 $NAME $VERSION (Release, $ARCH)"
cmake -S . -B build-release -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr >/dev/null
cmake --build build-release -j"$(nproc 2>/dev/null || echo 2)" >/dev/null
BIN="$ROOT/build-release/ban"
strip --strip-all "$BIN"
"$BIN" --version

# ---------------------------------------------------------------- 便携包
stage_portable() {
    suffix=$1
    src_bin=$2
    dir="$WORK/$NAME-$VERSION$suffix"
    mkdir -p "$dir/systemd"
    cp "$src_bin" "$dir/ban"
    cp README.md LICENSE "$dir/"
    cp systemd/ban-restore.service systemd/ban-refresh.service systemd/ban-refresh.timer "$dir/systemd/"
    tar -C "$WORK" -czf "$DIST/$NAME-$VERSION-$ARCH-linux$suffix.tar.gz" "$NAME-$VERSION$suffix"
    echo "    $NAME-$VERSION-$ARCH-linux$suffix.tar.gz"
}

echo "==> 打包便携二进制"
stage_portable "" "$BIN"

echo "==> 尝试全静态构建"
if g++ -std=c++17 -O2 -static -Isrc -o "$WORK/ban-static" src/*.cpp 2>"$WORK/static.log"; then
    if "$WORK/ban-static" --version >/dev/null 2>&1; then
        strip --strip-all "$WORK/ban-static"
        stage_portable "-static" "$WORK/ban-static"
    else
        echo "    静态二进制无法运行，跳过"
    fi
else
    echo "    当前工具链不支持全静态链接，跳过（见下方原因）"
    head -3 "$WORK/static.log" | sed 's/^/    /'
fi

# ---------------------------------------------------------------- deb
echo "==> 打包 deb"
DEB="$WORK/deb"
mkdir -p "$DEB/DEBIAN" "$DEB/usr/bin" "$DEB/usr/lib/systemd/system" \
         "$DEB/usr/share/doc/$NAME"
install -m755 "$BIN" "$DEB/usr/bin/$NAME"
install -m644 systemd/ban-restore.service systemd/ban-refresh.service \
              systemd/ban-refresh.timer "$DEB/usr/lib/systemd/system/"
install -m644 README.md LICENSE "$DEB/usr/share/doc/$NAME/"

(cd "$DEB" && find usr -type f -printf '%P\n' | sort | xargs -r md5sum > DEBIAN/md5sums)
INSTALLED_SIZE=$(du -sk "$DEB/usr" | cut -f1)

cat > "$DEB/DEBIAN/control" <<EOF
Package: $NAME
Version: $VERSION
Section: net
Priority: optional
Architecture: amd64
Maintainer: peo-zyc <peo-zyc@users.noreply.github.com>
Installed-Size: $INSTALLED_SIZE
Depends: libc6 (>= 2.34)
Recommends: nftables | iptables
Suggests: ipset, dnsmasq
Homepage: https://github.com/peo-zyc/ban
Description: Linux domain/IP blocking CLI with kernel-resident rules
 ban 是一个 Linux 域名/IP 封禁命令行工具。
 .
 规则直接下发到内核 (nftables 集合或 ipset)，因此不需要任何常驻进程：
 开机由 systemd oneshot 恢复规则，域名解析到的 IP 变化由 systemd timer
 定期刷新。支持 DNS 层与防火墙 IP 层双层阻断、临时封禁自动过期、
 白名单优先、配置导入导出与环境自检。
EOF

( cd "$DEB/DEBIAN" && tar -czf "$WORK/control.tar.gz" ./control ./md5sums )
( cd "$DEB" && tar -czf "$WORK/data.tar.gz" ./usr )
printf '2.0\n' > "$WORK/debian-binary"
ar rcs "$DIST/${NAME}_${VERSION}_amd64.deb" \
    "$WORK/debian-binary" "$WORK/control.tar.gz" "$WORK/data.tar.gz"
echo "    ${NAME}_${VERSION}_amd64.deb"

# ---------------------------------------------------------------- Arch
echo "==> 打包 Arch (makepkg)"
if command -v makepkg >/dev/null 2>&1; then
    A="$WORK/arch"
    mkdir -p "$A"
    cp "$BIN" "$A/ban"
    cp README.md LICENSE "$A/"
    cp systemd/ban-restore.service systemd/ban-refresh.service \
       systemd/ban-refresh.timer "$A/"
    cp packaging/arch/PKGBUILD "$A/"
    sed -i "s/^pkgver=.*/pkgver=$VERSION/" "$A/PKGBUILD"
    if ( cd "$A" && makepkg -f --nodeps --noconfirm --log >/dev/null 2>&1 ); then
        cp "$A"/*.pkg.tar.zst "$DIST/"
        echo "    $(ls "$A"/*.pkg.tar.zst | xargs -n1 basename)"
    else
        echo "    makepkg 失败，跳过（可手动执行: cd packaging/arch && makepkg -f）" >&2
    fi
else
    echo "    未安装 makepkg，跳过"
fi

# ---------------------------------------------------------------- 源码包
echo "==> 生成源码包"
git archive --format=tar.gz --prefix="$NAME-$VERSION/" -o "$DIST/$NAME-$VERSION.tar.gz" HEAD
echo "    $NAME-$VERSION.tar.gz"

# ---------------------------------------------------------------- 校验和
echo "==> 生成 SHA256SUMS"
( cd "$DIST" && sha256sum *.tar.gz *.deb *.pkg.tar.zst 2>/dev/null | sort > SHA256SUMS )

echo
echo "==> 产物清单 ($DIST)"
ls -lh "$DIST" | sed 's/^/    /'

#!/bin/sh
# OpenXDR 一行安装：
#   curl -fsSL https://github.com/yaklang/OpenXDR/releases/latest/download/install.sh | sudo sh -s -- <控制台域名或 IP>
#
# 做的事：检查 Docker → 下载编排文件 → 生成数据库口令、admin 口令与凭据加密密钥 → 签发 mTLS 证书 →
# 写 Caddyfile（公网域名自动申请 Let's Encrypt 证书，内网地址用自建 CA）→ 拉起 → 等就绪 → 打印登录信息。
# 可重复执行：已有的口令、密钥与 CA 原样保留，只更新版本与服务端证书，所以升级也是再跑一遍。
#
# 环境变量：
#   OPENXDR_DIR      安装目录，默认 /opt/openxdr
#   OPENXDR_VERSION  版本，默认这个脚本所属的版本
#   OPENXDR_TLS      acme / internal，默认按地址判断：解析到公网 IP 的域名用 acme，其余用 internal
#   OPENXDR_EMAIL    acme 模式下给 Let's Encrypt 的联系邮箱（可选）
set -eu

VERSION=${OPENXDR_VERSION:-__OPENXDR_VERSION__}
[ "$VERSION" = "__OPENXDR_VERSION__" ] && VERSION=latest
DIR=${OPENXDR_DIR:-/opt/openxdr}
REPO=https://github.com/yaklang/OpenXDR
if [ "$VERSION" = latest ]; then BASE=${OPENXDR_BASE_URL:-$REPO/releases/latest/download}; else BASE=${OPENXDR_BASE_URL:-$REPO/releases/download/$VERSION}; fi

say() { printf '\033[1m==>\033[0m %s\n' "$*"; }
die() { printf '\033[31m错误：\033[0m%s\n' "$*" >&2; exit 1; }

# ---- 前置检查 ----
[ "$(id -u)" = 0 ] || die "需要 root：在命令前加 sudo"
command -v docker >/dev/null 2>&1 || die "没有找到 Docker。先安装：curl -fsSL https://get.docker.com | sh"
docker compose version >/dev/null 2>&1 || die "需要 Docker Compose v2（docker compose 子命令）"
docker info >/dev/null 2>&1 || die "Docker 守护进程没在运行"

HOST=${1:-}
if [ -z "$HOST" ]; then
  HOST=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')
  [ -n "$HOST" ] || die "无法判断本机地址，请把控制台域名或 IP 作为参数传入"
  say "未指定地址，使用本机地址 $HOST（被纳管主机要能访问到它）"
fi
case $HOST in *[!A-Za-z0-9.:-]*|"") die "地址不合法：$HOST" ;; esac

is_ip() { echo "$1" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$|:'; }
is_private() {
  echo "$1" | grep -Eq '^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.)|^(fc|fd|fe80|::1)'
}
TLS=${OPENXDR_TLS:-}
if [ -z "$TLS" ]; then
  TLS=internal
  if ! is_ip "$HOST"; then
    addr=$(getent ahostsv4 "$HOST" 2>/dev/null | awk 'NR==1{print $1}')
    [ -n "$addr" ] && ! is_private "$addr" && TLS=acme
  fi
fi
case $TLS in acme|internal) ;; *) die "OPENXDR_TLS 只能是 acme 或 internal" ;; esac

# 端口是否被监听：ss 优先，netstat 兜底；两者都没有返回 2，让调用方明确说跳过
listening() {
  if command -v ss >/dev/null 2>&1; then
    ss -ltnH "sport = :$1" 2>/dev/null | grep -q .
  elif command -v netstat >/dev/null 2>&1; then
    netstat -ltn 2>/dev/null | awk -v p=":$1" '$4 ~ p"$" {found=1} END {exit !found}'
  else
    return 2
  fi
}

# 已经是我们自己在占用就不算冲突（重复执行 / 升级）
busy=""
for port in 80 443 8081; do
  code=0
  listening "$port" || code=$?
  if [ $code -eq 2 ]; then
    say "没有 ss 或 netstat，跳过端口占用检查（有冲突时 Docker 启动会报错）"
    break
  fi
  if [ $code -eq 0 ] && ! docker ps --format '{{.Names}} {{.Ports}}' | grep -q "^openxdr-.*:$port->"; then busy="$busy $port"; fi
done
[ -z "$busy" ] || die "端口被占用：$busy（OpenXDR 需要 80、443 与 8081）"

# ---- 文件与密钥 ----
mkdir -p "$DIR/certs"
cd "$DIR"
say "下载编排文件（$VERSION）"
curl -fsSL "$BASE/docker-compose.yml" -o docker-compose.yml.new || die "下载失败：$BASE/docker-compose.yml"
curl -fsSL "$BASE/nats.conf" -o nats.conf.new || die "下载失败：$BASE/nats.conf"
mv nats.conf.new nats.conf
mv docker-compose.yml.new docker-compose.yml

rand() { head -c "$1" /dev/urandom | base64 | tr -d '\n/+='; }
touch .env && chmod 600 .env
get() { sed -n "s/^$1=//p" .env | head -1; }
put() {
  if grep -q "^$1=" .env; then sed -i "s|^$1=.*|$1=$2|" .env; else echo "$1=$2" >> .env; fi
}
[ -n "$(get POSTGRES_PASSWORD)" ] || put POSTGRES_PASSWORD "$(rand 24)"
[ -n "$(get ADMIN_PASSWORD)" ] || put ADMIN_PASSWORD "$(rand 12)"
[ -n "$(get HOST_CREDENTIAL_KEY)" ] || put HOST_CREDENTIAL_KEY "$(head -c 32 /dev/urandom | base64 | tr -d '\n')"
PREV_HOST=$(get OPENXDR_HOST)
put OPENXDR_HOST "$HOST"
put OPENXDR_VERSION "$VERSION"

IMAGE=ghcr.io/yaklang/openxdr-server:$VERSION
say "拉取镜像"
docker compose --progress quiet pull --policy missing

# 首次安装、地址变了或缺指令签名私钥（旧版装的）才签（沿用已有 CA 与签名私钥）；私钥给 server 容器里的 openxdr 用户（uid 10001）读
CHANGED=""
if [ ! -f certs/server.crt ] || [ ! -f certs/command-signing.key ] || [ "$PREV_HOST" != "$HOST" ]; then
  say "签发 mTLS 证书"
  docker run --rm --user 0 -v "$DIR/certs:/certs" --entrypoint openxdr-gencerts "$IMAGE" /certs "$HOST" >/dev/null
  chown -R 10001 certs && chmod 600 certs/*.key
  CHANGED=1
fi

if [ "$TLS" = acme ]; then
  say "控制台证书：Let's Encrypt（$HOST 需要从公网能访问 80 与 443）"
  cat > Caddyfile.new <<EOF
{
	${OPENXDR_EMAIL:+email $OPENXDR_EMAIL}
}
$HOST {
	encode gzip
	# HSTS 只在这里发：这层才是浏览器看到的 HTTPS；安全头（CSP 等）由 web 镜像里的 nginx 发
	header Strict-Transport-Security "max-age=31536000"
	reverse_proxy web:80
}
EOF
else
  say "控制台证书：自建 CA（被纳管主机需要先信任它，见安装完成后的说明）"
  cat > Caddyfile.new <<EOF
{
	auto_https off
	# 按 IP 访问时客户端不带 SNI，没有它 Caddy 选不出证书
	default_sni $HOST
}
https://$HOST {
	tls /certs/server.crt /certs/server.key
	encode gzip
	header Strict-Transport-Security "max-age=31536000"
	reverse_proxy web:80
}
# 明文口只做两件事：给主机下载 CA（下载后按指纹核对），其余跳到 HTTPS
http://$HOST {
	handle /openxdr-ca.crt {
		rewrite * /ca.crt
		root * /certs
		file_server
	}
	handle {
		redir https://$HOST{uri}
	}
}
EOF
fi

cmp -s Caddyfile.new Caddyfile 2>/dev/null || CHANGED=1
mv Caddyfile.new Caddyfile

say "启动"
docker compose --progress quiet up -d --remove-orphans
# 证书与 Caddyfile 是挂载进去的，内容变了容器不会自己重载
[ -z "$CHANGED" ] || docker compose --progress quiet restart server caddy
i=0
until docker compose exec -T server wget -qO- http://127.0.0.1:8080/readyz >/dev/null 2>&1; do
  i=$((i + 1))
  [ $i -lt 90 ] || die "server 两分钟内没有就绪，查看日志：cd $DIR && docker compose logs server"
  sleep 2
done

FP=$(sha256sum certs/ca.crt | awk '{print $1}')
cat <<EOF

$(printf '\033[32m')OpenXDR 已就绪$(printf '\033[0m')

  控制台    https://$HOST
  账号      admin
  口令      $(get ADMIN_PASSWORD)
  安装目录  $DIR（.env 里的口令与密钥请和数据库一起备份）

EOF
if [ "$TLS" = internal ]; then
cat <<EOF
控制台用的是自建 CA。浏览器首次访问会提示不受信任；被纳管的主机必须先信任这张 CA，才能执行控制台给出的安装命令：

  # 下面的命令先核对指纹，对得上才装进信任库；对不上会报错停下，说明下载被人篡改了
  # Debian / Ubuntu
  curl -fsSL http://$HOST/openxdr-ca.crt -o /tmp/openxdr-ca.crt && echo "$FP  /tmp/openxdr-ca.crt" | sha256sum -c && cp /tmp/openxdr-ca.crt /usr/local/share/ca-certificates/openxdr.crt && update-ca-certificates
  # RHEL / CentOS / Rocky
  curl -fsSL http://$HOST/openxdr-ca.crt -o /tmp/openxdr-ca.crt && echo "$FP  /tmp/openxdr-ca.crt" | sha256sum -c && cp /tmp/openxdr-ca.crt /etc/pki/ca-trust/source/anchors/openxdr.crt && update-ca-trust
  # Windows（管理员 PowerShell）
  iwr http://$HOST/openxdr-ca.crt -OutFile openxdr-ca.crt; if ((Get-FileHash openxdr-ca.crt).Hash -eq '$FP') { certutil -addstore Root openxdr-ca.crt } else { throw '指纹不一致，已停止' }

  CA 指纹（SHA256）：$FP

EOF
fi
cat <<EOF
下一步：
  1. 登录后在「系统设置 → AI 模型」填模型端点（任意 OpenAI 兼容服务），AI 研判与 AI 助手随即可用
  2. 「资产 → 添加主机」选组，复制安装命令到主机上执行；防火墙需放行 443 与 8081
  3. 升级：再执行一遍安装命令，或修改 $DIR/.env 的 OPENXDR_VERSION 后 docker compose pull && docker compose up -d
EOF

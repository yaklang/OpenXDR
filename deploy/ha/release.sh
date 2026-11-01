#!/bin/sh
# HA 滚动发布：本地从当前提交构建 server / web 镜像，推到两个节点，先升不持有 VIP 的节点，
# 健康检查通过后再升另一个。任何一步失败立即停下，已升的节点可用 pre-<标签> 回滚。
#
# 用法：deploy/ha/release.sh <节点A> <节点B>
#   节点为 ssh 目的地（可以是 ssh config 里的别名）。
# 环境变量：
#   SSH          ssh 命令，默认 ssh；需要指定配置文件时如 SSH="ssh -F ~/.ssh/openxdr"
#   VIP          虚拟 IP，用来判断谁在对外服务，默认 10.1.1.199
#   HA_DIR       节点上的部署目录，默认 /opt/openxdr-ha
#   GOPROXY      构建 server 时的 Go 代理，国内网络可设 https://goproxy.cn,direct
#   NPM_REGISTRY 构建 web 时的 npm 源，如 https://registry.npmmirror.com
#   ALPINE_MIRROR 构建 server 镜像时的 alpine 软件源，如 https://mirrors.ustc.edu.cn
#   ALLOW_DIRTY  设为 1 才允许工作区有未提交改动（镜像会带上它们，标签加 -dirty）
#   SKIP_IPDB    设为 1 不下载离线 IP 归属库，镜像里库为空、归属字段留空（下不到 DB-IP 时用）
#
# 同步内容：两个镜像，rules/ 与 tasks/（节点上 bind mount，逐个文件原地覆盖，
# 不整体替换目录——容器挂的是目录本身，换掉目录它会继续看旧的）；temporal-rules/ 按内容哈希发布成
# 不可变版本目录，再原子切换 current 链接。
# 回滚：在节点上 cd $HA_DIR，把 openxdr-ha-{server,web}:pre-<标签> 重新 tag 成 latest 后
#   docker compose -f docker-compose.ha-node.yml up -d --no-build --no-deps server web
# 节点存在 docker-compose.dygk.yml 时，发布与回滚均需追加 -f docker-compose.dygk.yml。
set -eu

[ $# -eq 2 ] || { sed -n '2,9p' "$0"; exit 2; }
SSH=${SSH:-ssh}
VIP=${VIP:-10.1.1.199}
HA_DIR=${HA_DIR:-/opt/openxdr-ha}
ROOT=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
TAG=$(git -C "$ROOT" rev-parse --short HEAD)
if [ -n "$(git -C "$ROOT" status --porcelain --untracked-files=no)" ]; then
  [ "${ALLOW_DIRTY:-}" = 1 ] || { echo "工作区有未提交改动；确认要带上它们就设 ALLOW_DIRTY=1" >&2; exit 1; }
  TAG=$TAG-dirty
fi

remote() { node=$1; shift; $SSH "$node" "$@"; }

# 先升不持有 VIP 的节点，对外服务的那台最后动
first=$1 second=$2
if remote "$first" "ip -4 -o addr | grep -qw '$VIP'"; then first=$2 second=$1; fi

echo "== 构建 $TAG"
# 离线 IP 归属库与 release.yml 同口径：下载当月 DB-IP Lite 并校验后打进镜像；下不到就停下，别悄悄发一个缺库的镜像
ipdb=$(mktemp -d)
trap 'rm -rf "$ipdb"' EXIT
mkdir "$ipdb/ipdb"
if [ "${SKIP_IPDB:-}" != 1 ]; then
  (cd "$ROOT/server" && go run ./cmd/ipdb -dir "$ipdb/ipdb") ||
    { echo "离线 IP 归属库下载或校验失败；确认不要它就设 SKIP_IPDB=1" >&2; exit 1; }
fi
docker build -q -f "$ROOT/server/Dockerfile" ${GOPROXY:+--build-arg GOPROXY="$GOPROXY"} ${ALPINE_MIRROR:+--build-arg ALPINE_MIRROR="$ALPINE_MIRROR"} \
  --build-context ipdb="$ipdb" -t "openxdr-ha-server:$TAG" "$ROOT"
docker build -q -f "$ROOT/web/Dockerfile" ${NPM_REGISTRY:+--build-arg NPM_REGISTRY="$NPM_REGISTRY"} -t "openxdr-ha-web:$TAG" "$ROOT/web"

bundle=$(mktemp)
trap 'rm -rf "$bundle" "$ipdb"' EXIT
tar -C "$ROOT" -czf "$bundle" rules tasks temporal-rules

for node in "$first" "$second"; do
  echo "== $node：推镜像与规则"
  docker save "openxdr-ha-server:$TAG" "openxdr-ha-web:$TAG" | remote "$node" 'docker load -q'
  remote "$node" "set -eu
    cd '$HA_DIR'
    tmp=\$(mktemp -d); trap 'rm -rf \"\$tmp\"' EXIT
    tar -C \"\$tmp\" -xzf -
    for d in rules tasks; do
      mkdir -p \$d
      # 递归原地覆盖（规则有子目录，如 rules/sigmahq）；目录是 bind mount，不能整个换掉
      cp -rf \"\$tmp\"/\$d/. \$d/
      find \$d -type f | while read -r f; do [ -e \"\$tmp/\$f\" ] || rm -f \"\$f\"; done
    done
    # 时序规则按不可变版本目录发布：内容哈希做版本名，写完带 SHA256SUMS 再原子切换 current 链接（相对路径，
    # 容器里也解析得到）；server 整批加载链接指向的目录，不会读到半写入的版本。保留最近 5 个版本
    mkdir -p temporal-rules
    ver=v-\$(cd \"\$tmp/temporal-rules\" && cat \$(ls *.yml | sort) | sha256sum | cut -c1-12)
    if [ ! -d temporal-rules/\$ver ]; then
      mkdir temporal-rules/.\$ver.tmp
      cp \"\$tmp\"/temporal-rules/*.yml temporal-rules/.\$ver.tmp/
      (cd temporal-rules/.\$ver.tmp && sha256sum *.yml > SHA256SUMS)
      mv temporal-rules/.\$ver.tmp temporal-rules/\$ver
    fi
    ln -sfn \$ver temporal-rules/current.tmp && mv -T temporal-rules/current.tmp temporal-rules/current
    ls -dt temporal-rules/v-* | tail -n +6 | xargs -r rm -rf" < "$bundle"

  echo "== $node：切换到 $TAG"
  remote "$node" "set -eu
    cd '$HA_DIR'
    compose='docker compose -f docker-compose.ha-node.yml'
    if [ -f docker-compose.dygk.yml ]; then compose=\"\$compose -f docker-compose.dygk.yml\"; fi
    if [ -f docker-compose.logs.yml ]; then compose=\"\$compose -f docker-compose.logs.yml\"; fi
    \$compose config --quiet
    for c in server web; do
      docker tag openxdr-ha-\$c:latest openxdr-ha-\$c:pre-$TAG
      docker tag openxdr-ha-\$c:$TAG openxdr-ha-\$c:latest
    done
    \$compose up -d --no-build --no-deps --force-recreate server web
    for i in \$(seq 1 60); do
      curl -fsS --max-time 3 http://127.0.0.1:18080/readyz >/dev/null 2>&1 && exit 0
      sleep 2
    done
    docker logs --tail 40 openxdr-ha-server-1
    exit 1" || { echo "!! $node 健康检查失败，已停止；该节点回滚标签 pre-$TAG" >&2; exit 1; }
done
echo "== 完成：两个节点都在 $TAG"

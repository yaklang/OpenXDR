#!/bin/sh
# 沙箱主机防火墙：容器出口只放行模型端点（其余立刻拒绝），容器不能访问宿主；sandboxd 端口只对平台节点开放。
# 规则放在自有链里，重复执行只会重建自有链；Docker 不管 DOCKER-USER，重启 docker 也不会冲掉。
# DNS 不受这里管控：openxdr-sandbox 是自定义网络，容器只用 Docker 内嵌解析 127.0.0.11，
# 由宿主侧 dockerd 代为向上游查询，不经过 DOCKER-USER / FORWARD。下方规则只拒绝容器直连外部 53，
# 经内嵌解析的 DNS 隧道外泄没有被拦。要收口需让宿主或 dockerd 的上游只指向受控解析器
# （如 daemon.json 的 dns、或只解析模型端点的本地解析器），或模型端点直接写 IP。
# 用法：MODEL_ENDPOINTS="10.0.0.5:8000 ..." PLATFORM_NODES="10.0.0.1 10.0.0.2" sh firewall.sh
set -eu
BRIDGE=${SANDBOX_BRIDGE:-br-sandbox}
PORT=${SANDBOXD_PORT:-8090}
: "${MODEL_ENDPOINTS:?需要 MODEL_ENDPOINTS（模型端点 IP:端口，空格分隔）}"
: "${PLATFORM_NODES:?需要 PLATFORM_NODES（server 节点 IP，空格分隔）}"

# setup 与 timer 共用锁，避免临时集合被并发刷新破坏。
exec 9>/run/openxdr-sandbox-firewall.lock
flock -x 9
MODE=${1:-setup}
case "$MODE" in setup|refresh) ;; *) echo "用法：$0 [setup|refresh]" >&2; exit 2 ;; esac

refresh_sets() {
  ports=$(for ep in $MODEL_ENDPOINTS; do echo "${ep##*:}"; done | sort -u)
  for port in $ports; do
    case "$port" in ''|*[!0-9]*) echo "端口无效：$port" >&2; return 1 ;; esac
    [ "$port" -ge 1 ] && [ "$port" -le 65535 ] || return 1
    live="oxsbx-$port"
    temp="$live-next"
    ipset create "$live" hash:ip family inet -exist
    ipset create "$temp" hash:ip family inet -exist
    ipset flush "$temp"
    failed=0
    for ep in $MODEL_ENDPOINTS; do
      [ "${ep##*:}" = "$port" ] || continue
      host=${ep%:*}
      case "$host" in
        *[!0-9.]*|'') ips=$(getent ahostsv4 "$host" | awk '{print $1}' | sort -u) || ips= ;;
        *) ips=$host ;;
      esac
      if [ -z "$ips" ]; then
        echo "解析失败，保留端口 $port 的原集合：$host" >&2
        failed=1
        continue
      fi
      for ip in $ips; do ipset add "$temp" "$ip" -exist; done
    done
    # 任一端点失败都保留整个端口的旧集合，避免误删其他端点。
    if [ "$failed" = 0 ]; then ipset swap "$temp" "$live"; fi
    ipset destroy "$temp"
  done
}

refresh_sets
[ "$MODE" = refresh ] && exit 0

chain() { iptables -N "$1" 2>/dev/null || iptables -F "$1"; iptables -C "$2" -j "$1" 2>/dev/null || iptables -I "$2" 1 -j "$1"; }

iptables -I DOCKER-USER 1 -i "$BRIDGE" -j REJECT
iptables -I DOCKER-USER 1 -o "$BRIDGE" -j DROP
iptables -I INPUT 1 -i "$BRIDGE" -j DROP
iptables -I INPUT 1 -p tcp --dport "$PORT" -j DROP
chain OPENXDR-SBX-FWD DOCKER-USER
iptables -A OPENXDR-SBX-FWD -o "$BRIDGE" -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
iptables -A OPENXDR-SBX-FWD -o "$BRIDGE" -j DROP
iptables -A OPENXDR-SBX-FWD -i "$BRIDGE" -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
for port in $ports; do
  iptables -A OPENXDR-SBX-FWD -i "$BRIDGE" -p tcp -m set --match-set "oxsbx-$port" dst --dport "$port" -j RETURN
done
# 出口拒绝而不是丢弃：沙箱里访问外网立刻失败（TCP 回 RST、其余回 ICMP），不会挂到超时、看起来像静默返回空
iptables -A OPENXDR-SBX-FWD -i "$BRIDGE" -p tcp -j REJECT --reject-with tcp-reset
iptables -A OPENXDR-SBX-FWD -i "$BRIDGE" -j REJECT --reject-with icmp-admin-prohibited

chain OPENXDR-SBX-IN INPUT
iptables -A OPENXDR-SBX-IN -i "$BRIDGE" -j DROP
for ip in $PLATFORM_NODES; do
  iptables -A OPENXDR-SBX-IN -p tcp -s "$ip" --dport "$PORT" -j RETURN
done
iptables -A OPENXDR-SBX-IN -p tcp --dport "$PORT" -j DROP

# 如宿主机支持 ip6tables，默认阻断沙箱网桥全部 IPv6 转发与入站流量，消除 IPv6 旁路外泄面。
if command -v ip6tables >/dev/null 2>&1 && ip6tables -L -n >/dev/null 2>&1; then
  chain6() { ip6tables -N "$1" 2>/dev/null || ip6tables -F "$1"; ip6tables -C "$2" -j "$1" 2>/dev/null || ip6tables -I "$2" 1 -j "$1"; }
  chain6 OPENXDR-SBX-FWD6 FORWARD
  ip6tables -A OPENXDR-SBX-FWD6 -i "$BRIDGE" -j DROP
  ip6tables -A OPENXDR-SBX-FWD6 -o "$BRIDGE" -j DROP
  chain6 OPENXDR-SBX-IN6 INPUT
  ip6tables -A OPENXDR-SBX-IN6 -i "$BRIDGE" -j DROP
  ip6tables -A OPENXDR-SBX-IN6 -p tcp --dport "$PORT" -j DROP
fi

echo "沙箱防火墙已生效：出口 $MODEL_ENDPOINTS，平台 $PLATFORM_NODES"
iptables -D DOCKER-USER -i "$BRIDGE" -j REJECT
iptables -D DOCKER-USER -o "$BRIDGE" -j DROP
iptables -D INPUT -i "$BRIDGE" -j DROP
iptables -D INPUT -p tcp --dport "$PORT" -j DROP

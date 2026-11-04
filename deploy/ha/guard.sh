#!/bin/sh
# HA 宿主机防火墙：只放行该放行的来源，其余丢弃。可重复执行，每次整链重建。
#
# 用法：guard.sh node|witness
#   node     数据节点：5432（PostgreSQL）、8008（Patroni REST）与 6222（NATS 集群路由）只收本机、两个节点与 VIP，
#            8008 另收 MONITOR_IPS（节点外的 Prometheus）。链名 OPENXDR-DBGUARD。
#   witness  witness：2379（etcd）与 6222（NATS 集群路由）只收本机与 ETCD_ALLOW（两节点访问 witness 时的出口地址，
#            经 NAT 出网时是 NAT 后的公网地址；witness 不主动连节点）。链名 OPENXDR-ETCDGUARD。
#            6222 拿到路由口令就能以集群成员身份读写整个事件流，不能只靠口令。
# 环境变量（systemd 单元从 /etc/default/openxdr-guard 读）：
#   NODE_IPS     两个节点地址，默认 "10.1.1.198 10.1.1.197"
#   VIP          默认 10.1.1.199
#   MONITOR_IPS  可选，空格分隔
#   ETCD_ALLOW   witness 必填，空格分隔，可写 CIDR
# IPv6 同样建这条链：etcd、NATS 是 Go 程序，监听 0.0.0.0 实际是双栈，IPv6 也连得进来。
# 放行名单里带冒号的地址进 IPv6 链，其余进 IPv4 链；没有 ip6tables 的主机跳过 IPv6。
set -eu

role=${1:-}
case "$role" in
  node)
    chain=OPENXDR-DBGUARD
    ports=5432,8008,6222
    allow="${NODE_IPS:-10.1.1.198 10.1.1.197} ${VIP:-10.1.1.199}"
    ;;
  witness)
    chain=OPENXDR-ETCDGUARD
    ports=2379,6222
    allow=${ETCD_ALLOW:?witness 需要 ETCD_ALLOW：两个节点访问 witness 的出口地址}
    ;;
  *)
    sed -n '2,14p' "$0" >&2
    exit 2
    ;;
esac

# 地址属于哪一族：带冒号的是 IPv6
family() {
  case "$1" in *:*) echo ip6tables ;; *) echo iptables ;; esac
}

# 建一族的链。参数：iptables 或 ip6tables，加这一族的放行地址。
# iptables-restore --noflush 只清空并重建声明过的这条链，一次提交，中途不会出现放空的窗口。
# lo 放行本机：Patroni 自连、etcd 网关回连自己的地址都走 lo。
apply() {
  cmd=$1
  shift
  {
    echo '*filter'
    echo ":$chain - [0:0]"
    echo "-A $chain -i lo -j ACCEPT"
    for ip in "$@"; do echo "-A $chain -s $ip -j ACCEPT"; done
    if [ "$role" = node ]; then
      for ip in ${MONITOR_IPS:-}; do
        [ "$(family "$ip")" = "$cmd" ] && echo "-A $chain -p tcp --dport 8008 -s $ip -j ACCEPT"
      done
    fi
    echo "-A $chain -j DROP"
    echo 'COMMIT'
  } | "$cmd-restore" --noflush
  jump="-p tcp -m multiport --dports $ports -j $chain"
  # shellcheck disable=SC2086 # jump 需要按空格拆成参数
  "$cmd" -C INPUT $jump 2>/dev/null || "$cmd" -I INPUT 1 $jump
}

v4= v6=
for ip in $allow; do
  if [ "$(family "$ip")" = ip6tables ]; then v6="$v6 $ip"; else v4="$v4 $ip"; fi
done
# shellcheck disable=SC2086 # 地址按空格拆成参数
apply iptables $v4
if command -v ip6tables >/dev/null 2>&1; then
  # shellcheck disable=SC2086
  apply ip6tables $v6
fi
echo "$chain 已生效：端口 $ports，放行 lo $allow${MONITOR_IPS:+（8008 另放行 $MONITOR_IPS）}"

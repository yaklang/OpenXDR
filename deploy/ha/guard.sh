#!/bin/sh
# HA 宿主机防火墙：只放行该放行的来源，其余丢弃。可重复执行，每次整链重建。
#
# 用法：guard.sh node|witness
#   node     数据节点：5432（PostgreSQL）与 8008（Patroni REST）只收本机、两个节点与 VIP，
#            8008 另收 MONITOR_IPS（节点外的 Prometheus）。链名 OPENXDR-DBGUARD。
#   witness  witness：2379（etcd）只收本机与 ETCD_ALLOW（两节点访问 witness 时的出口地址，
#            经 NAT 出网时是 NAT 后的公网地址）。链名 OPENXDR-ETCDGUARD。
# 环境变量（systemd 单元从 /etc/default/openxdr-guard 读）：
#   NODE_IPS     两个节点地址，默认 "10.1.1.198 10.1.1.197"
#   VIP          默认 10.1.1.199
#   MONITOR_IPS  可选，空格分隔
#   ETCD_ALLOW   witness 必填，空格分隔，可写 CIDR
# 只管 IPv4：Patroni、PostgreSQL、etcd 模板都只监听 0.0.0.0。
set -eu

role=${1:-}
case "$role" in
  node)
    chain=OPENXDR-DBGUARD
    ports=5432,8008
    allow="${NODE_IPS:-10.1.1.198 10.1.1.197} ${VIP:-10.1.1.199}"
    ;;
  witness)
    chain=OPENXDR-ETCDGUARD
    ports=2379
    allow=${ETCD_ALLOW:?witness 需要 ETCD_ALLOW：两个节点访问 witness 的出口地址}
    ;;
  *)
    sed -n '2,14p' "$0" >&2
    exit 2
    ;;
esac

# iptables-restore --noflush 只清空并重建声明过的这条链，一次提交，中途不会出现放空的窗口。
# lo 放行本机：Patroni 自连、etcd 网关回连自己的地址都走 lo。
{
  echo '*filter'
  echo ":$chain - [0:0]"
  echo "-A $chain -i lo -j ACCEPT"
  for ip in $allow; do echo "-A $chain -s $ip -j ACCEPT"; done
  if [ "$role" = node ]; then
    for ip in ${MONITOR_IPS:-}; do echo "-A $chain -p tcp --dport 8008 -s $ip -j ACCEPT"; done
  fi
  echo "-A $chain -j DROP"
  echo 'COMMIT'
} | iptables-restore --noflush

jump="-p tcp -m multiport --dports $ports -j $chain"
# shellcheck disable=SC2086 # jump 需要按空格拆成参数
iptables -C INPUT $jump 2>/dev/null || iptables -I INPUT 1 $jump
echo "$chain 已生效：端口 $ports，放行 lo $allow${MONITOR_IPS:+（8008 另放行 $MONITOR_IPS）}"

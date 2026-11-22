#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
  echo "用法: $0 <输出目录> <witness IP或域名>" >&2
  exit 2
fi

out=$1
witness=$2
mkdir -p "$out"
chmod 700 "$out"

openssl genrsa -out "$out/ha-ca.key" 4096
openssl req -x509 -new -sha256 -days 3650 -key "$out/ha-ca.key" \
  -subj '/CN=OpenXDR HA CA' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -addext 'subjectKeyIdentifier=hash' \
  -out "$out/ha-ca.crt"

issue() {
  name=$1
  san=$2
  eku=$3
  cfg=$(mktemp)
  trap 'rm -f "$cfg"' EXIT
  printf '%s\n' \
    '[req]' 'distinguished_name=dn' 'req_extensions=ext' 'prompt=no' \
    '[dn]' "CN=$name" '[ext]' "subjectAltName=$san" "extendedKeyUsage=$eku" >"$cfg"
  openssl genrsa -out "$out/$name.key" 3072
  openssl req -new -key "$out/$name.key" -config "$cfg" -out "$out/$name.csr"
  openssl x509 -req -sha256 -days 825 -in "$out/$name.csr" \
    -CA "$out/ha-ca.crt" -CAkey "$out/ha-ca.key" -CAcreateserial \
    -extfile "$cfg" -extensions ext -out "$out/$name.crt"
  rm -f "$out/$name.csr" "$cfg"
  trap - EXIT
}

node1_ip=${NODE1_IP:-10.0.0.198}
node2_ip=${NODE2_IP:-10.0.0.197}
issue nats-node1 "IP:$node1_ip,DNS:openxdr-node1" 'serverAuth,clientAuth'
issue nats-node2 "IP:$node2_ip,DNS:openxdr-node2" 'serverAuth,clientAuth'
case "$witness" in
  *[!0-9.]*) witness_san="DNS:$witness" ;;
  *) witness_san="IP:$witness" ;;
esac
issue nats-witness "$witness_san,DNS:openxdr-witness" 'serverAuth,clientAuth'
# etcd 的 HTTP gateway 会用服务端证书回连本机 gRPC，因此需要双向 EKU。
issue etcd-server "$witness_san,DNS:openxdr-witness" 'serverAuth,clientAuth'
issue etcd-client 'DNS:openxdr-patroni' 'clientAuth'

chmod 600 "$out"/*.key
chmod 644 "$out"/*.crt

#!/bin/sh
# 生成 OpenXDR 自签证书：一个 CA，一张服务端证书，一张采集端证书。
# 用法: ./scripts/gen-certs.sh [输出目录] [server 的域名或 IP]
set -eu

OUT=${1:-certs}
HOST=${2:-localhost}
DAYS=3650

mkdir -p "$OUT"
cd "$OUT"

# CA
openssl req -x509 -newkey rsa:4096 -sha256 -days $DAYS -nodes \
  -keyout ca.key -out ca.crt -subj "/CN=OpenXDR Root CA"

# 服务端证书：SAN 必须包含采集端实际连接的地址，否则握手会被拒
case "$HOST" in
  *[0-9].[0-9]*) SAN="IP:$HOST,DNS:localhost,IP:127.0.0.1" ;;
  *)             SAN="DNS:$HOST,DNS:localhost,IP:127.0.0.1" ;;
esac
openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr \
  -subj "/CN=$HOST"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days $DAYS -sha256 -out server.crt \
  -extfile /dev/stdin <<EOF
subjectAltName = $SAN
extendedKeyUsage = serverAuth
EOF

# 采集端证书：agent 和 sensor 共用，需要按主机区分身份时各签一张
openssl req -newkey rsa:2048 -nodes -keyout client.key -out client.csr \
  -subj "/CN=openxdr-collector"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days $DAYS -sha256 -out client.crt \
  -extfile /dev/stdin <<EOF
extendedKeyUsage = clientAuth
EOF

rm -f server.csr client.csr ca.srl
chmod 600 ./*.key

echo "证书已生成于 $(pwd):"
echo "  server: TLS_CA_FILE=ca.crt TLS_CERT_FILE=server.crt TLS_KEY_FILE=server.key"
echo "  采集端: OPENXDR_CA=ca.crt OPENXDR_CERT=client.crt OPENXDR_KEY=client.key"

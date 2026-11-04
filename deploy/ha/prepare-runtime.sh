#!/bin/sh
set -eu

runtime=${1:-runtime}

for file in patroni.yml openxdr-db-password nats.conf keepalived.conf; do
  test -f "$runtime/$file" || {
    echo "缺少 $runtime/$file，请先运行 render.py" >&2
    exit 1
  }
done
test -d "$runtime/secrets" || { echo "缺少 $runtime/secrets" >&2; exit 1; }
# patroni 容器只挂这三个文件，缺了 docker 会在宿主机上建同名空目录
for file in ha-ca.crt etcd-client.crt etcd-client.key; do
  test -f "$runtime/secrets/$file" || { echo "缺少 $runtime/secrets/$file" >&2; exit 1; }
done
test -d "$runtime/app-certs" || { echo "缺少 $runtime/app-certs" >&2; exit 1; }

# postgres:16-alpine 的 postgres UID 为 70；server 镜像固定使用 UID 10001。
chown 70:70 "$runtime/patroni.yml" "$runtime/openxdr-db-password"
chmod 400 "$runtime/openxdr-db-password"
chmod 600 "$runtime/patroni.yml" "$runtime/nats.conf" "$runtime/keepalived.conf"
chown -R 70:70 "$runtime/secrets"
find "$runtime/secrets" -type d -exec chmod 700 {} +
find "$runtime/secrets" -type f -name '*.key' -exec chmod 600 {} +
find "$runtime/secrets" -type f ! -name '*.key' -exec chmod 640 {} +
chown -R 10001:10001 "$runtime/app-certs"
find "$runtime/app-certs" -type d -exec chmod 700 {} +
find "$runtime/app-certs" -type f -exec chmod 600 {} +

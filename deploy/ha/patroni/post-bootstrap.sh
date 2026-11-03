#!/bin/sh
set -eu
# openxdr 口令从挂载的文件读（psql 用 \set 反引号读，不进环境变量也不进命令行）；
# replicator 角色由 Patroni 在本脚本之后按 patroni.yml 创建，这里不管。
password_file=/etc/patroni/openxdr-db-password
test -s "$password_file" || { echo "缺少 $password_file" >&2; exit 1; }
psql "$1" -v ON_ERROR_STOP=1 <<'SQL'
\set openxdr_password `cat /etc/patroni/openxdr-db-password`
-- CREATEROLE 供 server 自动开通各组只读查询角色（server/internal/queryrole）
SELECT format('CREATE ROLE openxdr LOGIN CREATEDB CREATEROLE PASSWORD %L', :'openxdr_password')
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'openxdr') \gexec
SELECT 'CREATE DATABASE openxdr OWNER openxdr'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'openxdr') \gexec
SQL

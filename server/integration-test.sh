#!/bin/sh
# 集成测试：每个包用独立的测试库并行跑（cmd/integrationexec 按包目录分库），
# 并行时失败的包再串行重跑一次——重跑仍失败才算失败，重跑通过的会列出来，提醒这些测试对负载敏感、要修。
#
# 用法（工作目录 server/）：INTEGRATION_DATABASE_URL=postgres://... sh integration-test.sh [go test 参数...]
# 环境变量：INTEGRATION_PARALLEL 并行包数，默认 4
# 测试库建议关掉落盘保证（fsync / synchronous_commit / full_page_writes），见 AGENTS.md
set -u
: "${INTEGRATION_DATABASE_URL:?需要 INTEGRATION_DATABASE_URL}"
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
go build -o "$dir/integrationexec" ./cmd/integrationexec || exit 1

go test -tags integration -p "${INTEGRATION_PARALLEL:-4}" -exec "$dir/integrationexec" "$@" ./... >"$dir/log" 2>&1
status=$?
cat "$dir/log"
[ "$status" -eq 0 ] && exit 0

failed=$(grep -E '^FAIL[[:space:]]+openxdr/' "$dir/log" | awk '{print $2}' | sort -u)
if [ -z "$failed" ]; then
	exit "$status"
fi
echo
echo "== 并行时失败的包，串行重跑一次：$failed"
# shellcheck disable=SC2086 # 包列表按空白拆开
go test -count=1 -tags integration -p 1 -exec "$dir/integrationexec" "$@" $failed || exit 1
echo
echo "== 注意：上面这些包只在并行时失败、串行重跑通过，是对负载敏感的测试，需要修"

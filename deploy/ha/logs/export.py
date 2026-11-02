#!/usr/bin/env python3
"""受限 SSH 入口：只导出 OpenXDR 的 journal，不接受远端命令。"""
import json
import subprocess
import sys

request = json.loads(sys.stdin.buffer.readline(4096))
cursor = request.get('cursor', '')
if not isinstance(cursor, str) or len(cursor) > 1024 or '\n' in cursor:
    raise SystemExit('无效游标')
cmd = ['journalctl', '--no-pager', '-o', 'json', 'CONTAINER_TAG=openxdr-ha']
cmd += ['--after-cursor', cursor] if cursor else ['--since', '7 days ago']
process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
drained = True
size = 0
try:
    for n, line in enumerate(process.stdout):
        if n >= 5000 or size + len(line.encode()) > 8*1024*1024:
            drained = False
            break
        size += len(line.encode())
        item = json.loads(line)
        name = item.get('CONTAINER_NAME', '')
        if not name.startswith('openxdr-ha-'):
            continue
        message = item.get('MESSAGE', '')
        if isinstance(message, list):
            message = bytes(message).decode('utf-8', errors='replace')
        print(json.dumps({
            'cursor': item['__CURSOR'], 'time': int(item['__REALTIME_TIMESTAMP']),
            'service': name, 'container': item.get('CONTAINER_ID_FULL', ''),
            'message': message,
        }, ensure_ascii=False))
    if drained:
        if process.wait(timeout=5) != 0:
            raise SystemExit('journal 导出失败，请检查游标和权限')
finally:
    if process.poll() is None:
        process.terminate()
    process.wait()

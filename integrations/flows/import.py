#!/usr/bin/env python3
"""将 ntopng / nProbe JSONL 导入 OpenXDR；失败即停止，保留输入文件，可幂等重传。"""
import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server', required=True, help='OpenXDR HTTPS 地址')
    parser.add_argument('--source', required=True, choices=['ntopng', 'nprobe'])
    parser.add_argument('file', help='每行一个原始 JSON 流量对象，可含 Syslog 前缀')
    args = parser.parse_args()
    token = os.environ.get('OPENXDR_INTEGRATION_TOKEN')
    if not token:
        parser.error('缺少 OPENXDR_INTEGRATION_TOKEN')
    server = urllib.parse.urlsplit(args.server)
    if server.scheme != 'https' or not server.netloc or server.username or server.password or server.query or server.fragment:
        parser.error('--server 必须是无凭据、查询参数与 fragment 的 HTTPS 地址')
    endpoint = args.server.rstrip('/') + '/api/integration/v1/flows/' + args.source + '/events'
    # 不跟随重定向，避免令牌被转发到其他站点。
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    opener = urllib.request.build_opener(NoRedirect)
    accepted = 0
    with open(args.file, encoding='utf-8') as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                # ntopng 导出可带 Syslog 头，JSON 起点之前的文本不属于流量。
                start = line.index('{')
                payload = line[start:].strip()
                value = json.loads(payload)
                if not isinstance(value, dict):
                    raise ValueError('需要 JSON 对象')
                if len(payload.encode('utf-8')) > 256 * 1024:
                    raise ValueError('超过 256 KiB')
                request = urllib.request.Request(endpoint, data=payload.encode('utf-8'),
                    headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'}, method='POST')
                with opener.open(request, timeout=30) as response:
                    if response.status != 202:
                        raise ValueError('未收到 202 确认')
                accepted += 1
            except (ValueError, urllib.error.URLError) as error:
                detail = 'HTTP ' + str(error.code) if isinstance(error, urllib.error.HTTPError) else type(error).__name__
                print(f'第 {line_number} 行失败（{detail}），已确认 {accepted} 条；输入文件未修改，可修正后重传。', file=sys.stderr)
                return 1
    print(f'已确认入队 {accepted} 条。')
    return 0


if __name__ == '__main__':
    sys.exit(main())

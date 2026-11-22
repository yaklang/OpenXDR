#!/usr/bin/env python3
"""从指定主库拉取一次节点外备份；不安装定时任务，不删除历史备份。"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--node', required=True)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--ha-dir', default='/opt/openxdr-ha')
    args = parser.parse_args()
    os.umask(0o077)
    args.output.mkdir(parents=True, exist_ok=False)
    ssh = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', args.node]
    pg = ['docker', 'exec', '-u', 'postgres', 'openxdr-ha-patroni-1']
    query = ['psql', '-X', '-At', '-v', 'ON_ERROR_STOP=1', '-d', 'openxdr', '-c']
    result = subprocess.check_output(ssh + [shlex.join(pg + query + [
        "SELECT json_build_object('primary', NOT pg_is_in_recovery(),"
        "'database_bytes',pg_database_size(current_database()),"
        "'postgres',current_setting('server_version'),'captured_at',now())"
    ])], text=True)
    metadata = json.loads(result)
    if not metadata['primary']:
        raise SystemExit('指定节点不是主库；未开始导出')
    if shutil.disk_usage(args.output).free < metadata['database_bytes'] * 1.2:
        raise SystemExit('本地空间不足：至少预留数据库总大小的 1.2 倍')
    metadata.update(node=args.node, status='running', files={})
    manifest = args.output / 'manifest.json'
    manifest.write_text(json.dumps(metadata, ensure_ascii=False, indent=2))

    def capture(name, command):
        partial = args.output / (name + '.partial')
        with partial.open('xb') as out, (args.output / (name + '.log')).open('xb') as err:
            subprocess.run(ssh + [command], stdout=out, stderr=err, check=True)
        digest = hashlib.sha256()
        with partial.open('rb') as src:
            for block in iter(lambda: src.read(8 * 1024 * 1024), b''):
                digest.update(block)
        partial.rename(args.output / name)
        metadata['files'][name] = {'bytes': (args.output / name).stat().st_size,
                                   'sha256': digest.hexdigest()}
        manifest.write_text(json.dumps(metadata, ensure_ascii=False, indent=2))
        print(f'{name} 完成', flush=True)

    # 角色口令和运行时密钥同样敏感，整个输出目录为 0700，文件为 0600。
    try:
        capture('roles.sql', shlex.join(pg + ['pg_dumpall', '--roles-only']))
        capture('runtime.tar.gz', shlex.join([
            'tar', '-C', args.ha_dir, '-czf', '-', '.env', 'docker-compose.ha-node.yml',
            'runtime/.env', 'runtime/patroni.yml', 'runtime/openxdr-db-password',
            'runtime/nats.conf', 'runtime/keepalived.conf', 'runtime/app-certs',
            'runtime/secrets', 'rules', 'tasks', 'temporal-rules',
        ]))
        capture('database.dump', shlex.join(pg + [
            'pg_dump', '--format=custom', '--compress=1', '--lock-wait-timeout=10s',
            '--dbname=openxdr',
        ]))
    except Exception as exc:
        metadata.update(status='failed', error=type(exc).__name__)
        manifest.write_text(json.dumps(metadata, ensure_ascii=False, indent=2))
        raise
    metadata.update(status='complete', finished_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
    manifest.write_text(json.dumps(metadata, ensure_ascii=False, indent=2))
    print('备份完成；尚未代表恢复验收通过', flush=True)


if __name__ == '__main__':
    main()

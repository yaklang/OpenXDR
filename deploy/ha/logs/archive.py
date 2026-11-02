#!/usr/bin/env python3
"""集中归档受限 journal 导出；游标与日志同事务提交，重复读取不会重复入库。"""
import argparse
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import time


def open_db(path):
    Path(path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.umask(0o077)
    db = sqlite3.connect(path, timeout=10)
    db.executescript('''PRAGMA auto_vacuum=INCREMENTAL; PRAGMA journal_mode=WAL;
      CREATE TABLE IF NOT EXISTS logs(host TEXT, cursor TEXT, time INTEGER, service TEXT, container TEXT, message TEXT,
        PRIMARY KEY(host,cursor));
      CREATE INDEX IF NOT EXISTS logs_time ON logs(time);
      CREATE TABLE IF NOT EXISTS cursors(host TEXT PRIMARY KEY, cursor TEXT);''')
    return db


def collect(db, config):
    for source in config['sources']:
        host = source['name']
        row = db.execute('SELECT cursor FROM cursors WHERE host=?', (host,)).fetchone()
        result = subprocess.run(source['command'], input=json.dumps({'cursor': row[0] if row else ''})+'\n',
                                text=True, capture_output=True, timeout=45)
        if result.returncode:
            raise RuntimeError('日志源读取失败：'+host)
        with db:
            for line in result.stdout.splitlines():
                item = json.loads(line)
                db.execute('INSERT OR IGNORE INTO logs VALUES (?,?,?,?,?,?)',
                           (host,item['cursor'],item['time'],item['service'],item['container'],item['message']))
                db.execute('INSERT INTO cursors VALUES (?,?) ON CONFLICT(host) DO UPDATE SET cursor=excluded.cursor',
                           (host,item['cursor']))
    with db:
        db.execute('DELETE FROM logs WHERE time < ?', (int((time.time()-7*86400)*1e6),))
    # 最多保留约 2 GiB 活跃页；超过时优先退役最早记录，SQLite 页可复用。
    page_size = db.execute('PRAGMA page_size').fetchone()[0]
    while (db.execute('PRAGMA page_count').fetchone()[0]-db.execute('PRAGMA freelist_count').fetchone()[0])*page_size > 2*1024**3:
        with db:
            db.execute('DELETE FROM logs WHERE rowid IN (SELECT rowid FROM logs ORDER BY time LIMIT 10000)')
    db.execute('PRAGMA incremental_vacuum(10000)')
    db.execute('PRAGMA wal_checkpoint(TRUNCATE)')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--db', default='/var/lib/openxdr-logs/archive.sqlite')
    sub = parser.add_subparsers(dest='action', required=True)
    collect_parser = sub.add_parser('collect')
    collect_parser.add_argument('--config', required=True)
    query = sub.add_parser('query')
    query.add_argument('--hours', type=float, default=24)
    query.add_argument('--service', default='')
    query.add_argument('--contains', default='')
    query.add_argument('--limit', type=int, default=100)
    args = parser.parse_args()
    db = open_db(args.db)
    try:
        if args.action == 'collect':
            collect(db, json.loads(Path(args.config).read_text()))
        else:
            if not 1 <= args.limit <= 10000 or not 0 < args.hours <= 168:
                parser.error('limit 须为 1–10000，hours 须为 0–168')
            for row in db.execute('''SELECT host,time,service,container,message FROM logs
                WHERE time>=? AND (?='' OR service=?) AND instr(message,?)>0 ORDER BY time DESC LIMIT ?''',
                (int((time.time()-args.hours*3600)*1e6),args.service,args.service,args.contains,args.limit)):
                print(json.dumps(dict(zip(['host','time','service','container','message'],row)),ensure_ascii=False))
    finally:
        db.close()


if __name__ == '__main__':
    main()

import { randomUUID } from 'node:crypto';

// 事实与导出日志由调用方置于同一 SQLite 事务；回调仅用于唤醒。
export function createEventFeed(db, { maxEvents, retention, now, quarantineTTL = 1800000 }) {
  db.exec(`CREATE TABLE IF NOT EXISTS ox_export_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS ox_export (sequence INTEGER PRIMARY KEY, id TEXT UNIQUE NOT NULL, ts INTEGER NOT NULL, body TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS ox_quarantine (ip TEXT PRIMARY KEY, until INTEGER NOT NULL, requests INTEGER NOT NULL, revealed TEXT NOT NULL);`);
  db.prepare('INSERT OR IGNORE INTO ox_export_meta VALUES (?,?)').run('epoch', randomUUID());
  db.prepare('INSERT OR IGNORE INTO ox_export_meta VALUES (?,?)').run('sequence', '0');
  const value = key => db.prepare('SELECT value FROM ox_export_meta WHERE key=?').get(key).value;
  const purge = () => {
    db.prepare('DELETE FROM ox_quarantine WHERE until<=?').run(now());
    db.prepare('DELETE FROM ox_export WHERE ts < ?').run(now() - retention);
    db.prepare('DELETE FROM ox_export WHERE sequence <= COALESCE((SELECT sequence FROM ox_export ORDER BY sequence DESC LIMIT 1 OFFSET ?),0)').run(maxEvents);
  };
  return {
    transaction(action) {
      const own = !db.isTransaction;
      if (own) db.exec('BEGIN IMMEDIATE');
      try { const result = action(); if (own) db.exec('COMMIT'); return result; }
      catch (error) { if (own) db.exec('ROLLBACK'); throw error; }
    },
    append(item) {
      const sequence = Number(value('sequence')) + 1;
      const record = { ...item, eventId: randomUUID(), streamEpoch: value('epoch'), sequence };
      db.prepare("UPDATE ox_export_meta SET value=? WHERE key='sequence'").run(String(sequence));
      db.prepare('INSERT INTO ox_export VALUES (?,?,?,?)').run(sequence, record.eventId, item.ts, JSON.stringify(record));
      if (item.kind === 'quarantine_started') {
        db.prepare('INSERT INTO ox_quarantine VALUES (?,?,0,?) ON CONFLICT(ip) DO UPDATE SET until=excluded.until').run(item.ip, now() + quarantineTTL, '[]');
        db.exec('DELETE FROM ox_quarantine WHERE rowid NOT IN (SELECT rowid FROM ox_quarantine ORDER BY rowid DESC LIMIT 1000)');
      }
      if (item.kind === 'quarantine_request') {
        const prior = db.prepare('SELECT revealed FROM ox_quarantine WHERE ip=?').get(item.ip);
        if (prior) {
          const revealed = new Set(JSON.parse(prior.revealed));
          if (['/admin/users', '/api/v1/users'].includes(item.data?.path)) revealed.add('/api/v1/tokens');
          if (item.data?.path === '/upload' && item.data?.method === 'POST') revealed.add('/api/v1/backup');
          if (item.data?.path === '/db' && item.data?.method === 'POST') revealed.add('/admin/flag');
          db.prepare('UPDATE ox_quarantine SET requests=requests+1, revealed=? WHERE ip=?').run(JSON.stringify([...revealed]), item.ip);
        }
      }
      purge();
      return record;
    },
    read(cursor = null, limit = 100) {
      if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) throw new Error('导出批量上限无效');
      purge();
      const epoch = value('epoch');
      const latest = Number(value('sequence'));
      const earliest = db.prepare('SELECT min(sequence) AS n FROM ox_export').get().n ?? latest + 1;
      const after = cursor?.after ?? 0;
      if (cursor && (cursor.epoch !== epoch || !Number.isSafeInteger(after) || after < 0 || after > latest || after < earliest - 1)) {
        const error = new Error('导出游标失效，事件流存在缺口');
        error.code = 'export_gap'; error.epoch = epoch; error.after = earliest - 1;
        throw error;
      }
      if (!cursor && earliest > 1) {
        const error = new Error('首个可用事件之前已有日志淘汰');
        error.code = 'export_gap'; error.epoch = epoch; error.after = earliest - 1; throw error;
      }
      const items = db.prepare('SELECT body FROM ox_export WHERE sequence>? ORDER BY sequence LIMIT ?').all(after, limit).map(row => JSON.parse(row.body));
      return { items, cursor: { epoch, after: items.at(-1)?.sequence ?? after } };
    },
    clear() {
      db.exec('DELETE FROM ox_export; DELETE FROM ox_quarantine');
      db.prepare("UPDATE ox_export_meta SET value=? WHERE key='epoch'").run(randomUUID());
      db.prepare("UPDATE ox_export_meta SET value='0' WHERE key='sequence'").run();
    },
    quarantineState() {
      purge();
      return db.prepare('SELECT ip,until,requests,revealed FROM ox_quarantine ORDER BY rowid').all().map(row => ({ ...row, revealed: JSON.parse(row.revealed) }));
    },
  };
}

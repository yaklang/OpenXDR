import { DatabaseSync } from 'node:sqlite';
import { randomBytes, createHmac } from 'node:crypto';

const supported = new Set(['entry', 'archive', 'verify_view', 'honeypot_triggered', 'honeypot_completed', 'ip_banned', 'blocked_request', 'quarantine_started', 'quarantine_request']);
const ignored = new Set(['profile_submitted', 'http_fingerprint', 'page_render', 'challenge_completed', 'challenge_issued', 'challenge_rejected', 'challenge_replayed', 'client_capabilities_fetched', 'client_downloaded', 'client_metadata_fetched', 'client_workflow_view', 'quarantine_budget', 'quarantine_db_query']);
export const knownSourceKinds = new Set([...supported, ...ignored]);
const sampled = new Set(['entry', 'archive', 'verify_view', 'blocked_request', 'quarantine_request']);

export class ConnectorState {
  constructor(file) {
    this.db = new DatabaseSync(file);
    this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=1000;
      CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS pending (id TEXT PRIMARY KEY, body TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS samples (key TEXT PRIMARY KEY, ts INTEGER NOT NULL);`);
    this.db.prepare('INSERT OR IGNORE INTO metadata VALUES (?,?)').run('salt', randomBytes(32).toString('hex'));
  }
  get(key) { const row = this.db.prepare('SELECT value FROM metadata WHERE key=?').get(key); return row ? JSON.parse(row.value) : null; }
  set(key, value) { this.db.prepare('INSERT INTO metadata VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value').run(key, JSON.stringify(value)); }
  cursor() { return this.get('cursor'); }
  pending() { return this.db.prepare('SELECT body FROM pending ORDER BY rowid LIMIT 100').all().map(row => JSON.parse(row.body)); }
  size() { return this.db.prepare('SELECT count(*) AS n FROM pending').get().n; }
  collect(page) {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const salt = this.db.prepare("SELECT value FROM metadata WHERE key='salt'").get().value;
      this.db.prepare('DELETE FROM samples WHERE ts < ?').run(Date.now() - 86400000);
      for (const item of page.items) {
        if (!supported.has(item.kind)) {
          if (ignored.has(item.kind)) continue;
          const error = new Error('上游事实尚未准入：' + item.kind); error.fatal = true; throw error;
        }
        const session = item.session ? createHmac('sha256', salt).update(item.session).digest('hex') : '';
        const key = item.kind + ':' + session;
        if (sampled.has(item.kind)) {
          const prior = this.db.prepare('SELECT ts FROM samples WHERE key=?').get(key);
          if (prior && item.ts - prior.ts < 600000) continue;
          this.db.prepare('INSERT INTO samples VALUES (?,?) ON CONFLICT(key) DO UPDATE SET ts=excluded.ts').run(key, item.ts);
        }
        if (this.size() >= 10000) throw new Error('连接器积压已达到上限');
        const fact = { eventId: item.eventId, streamEpoch: item.streamEpoch, sequence: item.sequence, occurredAt: new Date(item.ts).toISOString(), session, kind: item.kind, count: 1 };
        this.db.prepare('INSERT OR IGNORE INTO pending VALUES (?,?)').run(fact.eventId, JSON.stringify(fact));
      }
      this.set('cursor', page.cursor);
      this.db.exec('COMMIT');
    } catch (error) { this.db.exec('ROLLBACK'); throw error; }
  }
  gap(error, id) {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      if (this.size() >= 10000) throw new Error('连接器积压已达到上限');
      const fact = { eventId: id, streamEpoch: error.epoch, sequence: Math.max(1, error.after), occurredAt: new Date().toISOString(), session: '', kind: 'export_gap' };
      this.db.prepare('INSERT INTO pending VALUES (?,?)').run(id, JSON.stringify(fact));
      this.set('cursor', { epoch: error.epoch, after: error.after });
      this.db.exec('COMMIT');
    } catch (failure) { this.db.exec('ROLLBACK'); throw failure; }
  }
  acknowledge(ids) {
    this.db.exec('BEGIN IMMEDIATE');
    try { for (const id of ids) this.db.prepare('DELETE FROM pending WHERE id=?').run(id); this.db.exec('COMMIT'); }
    catch (error) { this.db.exec('ROLLBACK'); throw error; }
  }
  close() { this.db.close(); }
}

import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { randomUUID } from 'node:crypto';
import { createEventFeed } from '../web/export-feed.mjs';
import { ConnectorState } from '../web/state.mjs';

test('事件导出能识别截断与清空换代，并保留稳定 ID', () => {
  const db = new DatabaseSync(':memory:');
  const feed = createEventFeed(db, { maxEvents: 2, retention: 10000, now: () => 1000 });
  feed.append({ ts: 1000, kind: 'entry' });
  const first = feed.read(); assert.equal(first.items.length, 1);
  assert.equal(feed.read().items[0].eventId, first.items[0].eventId);
  feed.append({ ts: 1000, kind: 'archive' }); feed.append({ ts: 1000, kind: 'archive' });
  assert.throws(() => feed.read(), { code: 'export_gap' });
  assert.equal(feed.read(first.cursor).items.length, 2);
  feed.clear(); assert.throws(() => feed.read(first.cursor), { code: 'export_gap' }); db.close();
});

test('假后台状态保留来源有效期和请求预算，日志清空时一并清理', () => {
  const db = new DatabaseSync(':memory:');
  const feed = createEventFeed(db, { maxEvents: 10, retention: 10000, now: () => 1000, quarantineTTL: 5000 });
  feed.append({ ts: 1000, kind: 'quarantine_started', ip: '192.0.2.4', data: {} });
  feed.append({ ts: 1000, kind: 'quarantine_request', ip: '192.0.2.4', data: { path: '/admin/users', method: 'GET' } });
  assert.equal(feed.quarantineState()[0].until, 6000); assert.equal(feed.quarantineState()[0].requests, 1);
  assert.deepEqual(feed.quarantineState()[0].revealed, ['/api/v1/tokens']);
  feed.clear(); assert.equal(feed.quarantineState().length, 0); db.close();
});

test('连接器只输出白名单事实，网络重试沿用 ID，确认后才删除', () => {
  const state = new ConnectorState(':memory:');
  const item = { eventId: randomUUID(), streamEpoch: randomUUID(), sequence: 1, ts: Date.now(), session: 'source-session', ip: '192.0.2.4', kind: 'honeypot_triggered', data: { access_key: 'secret' } };
  state.collect({ items: [item], cursor: { epoch: item.streamEpoch, after: 1 } });
  const pending = state.pending(); assert.equal(pending[0].eventId, item.eventId);
  assert.match(pending[0].session, /^[a-f0-9]{64}$/);
  assert(!JSON.stringify(pending).includes('192.0.2.4')); assert(!JSON.stringify(pending).includes('secret'));
  assert.deepEqual(state.pending(), pending); state.acknowledge([item.eventId]); assert.equal(state.size(), 0); state.close();
});

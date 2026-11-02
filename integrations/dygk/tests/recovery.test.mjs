import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import http from 'node:http';
import { ConnectorState } from '../web/state.mjs';
import { start, releaseInfo } from '../web/main.mjs';
import { root, prepare } from '../scripts/prepare-upstream.mjs';

const source = existsSync(join(root, 'local-source')) || process.env.DYGK_SOURCE === 'remote' || process.env.DYGK_LOCAL_SOURCE;

test('连接器磁盘重启保留积压、游标和匿名会话标识，确认重放幂等', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'dygk-recovery-'));
  try {
    const file = join(dir, 'connector.sqlite');
    let state = new ConnectorState(file);
    const item = { eventId: randomUUID(), streamEpoch: randomUUID(), sequence: 1, ts: Date.now(), session: 'session', kind: 'honeypot_triggered' };
    const page = { items: [item], cursor: { epoch: item.streamEpoch, after: 1 } };
    state.collect(page); const before = state.pending(); state.close();
    state = new ConnectorState(file);
    assert.deepEqual(state.pending(), before); assert.deepEqual(state.cursor(), page.cursor);
    state.collect(page); assert.equal(state.size(), 1);
    state.acknowledge([item.eventId]); state.acknowledge([item.eventId]); state.close();
    state = new ConnectorState(file); assert.equal(state.size(), 0); state.close();
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('真实 HTTP 运行端断连补传、丢失确认重试、错误版本拒绝及恢复原配置', { skip: source ? false : '未提供上游源码，不能执行真实运行端恢复测试' }, async () => {
  const dir = await mkdtemp(join(tmpdir(), 'dygk-runtime-recovery-'));
  const release = await releaseInfo(await prepare(undefined, false));
  const config = { revision: randomUUID(), release, kind: 'http', profile: 'decoy', port: 0,
    config: { attachment: 'standalone', mode: 'observe', origin: '', prefix: '/_dygk', entries: 3, branches: 4, depth: 4, maxNodes: 256, requestLimit: 120 } };
  const accepted = new Set(); let fail = false; let duplicate = false; let runtime;
  const server = http.createServer(async (req, res) => {
    const chunks = []; for await (const chunk of req) chunks.push(chunk);
    const body = chunks.length ? JSON.parse(Buffer.concat(chunks)) : {};
    res.setHeader('content-type', 'application/json');
    if (req.url.endsWith('/config')) return res.end(JSON.stringify(config));
    if (req.url.endsWith('/observations')) {
      for (const item of body.items) { if (accepted.has(item.eventId)) duplicate = true; accepted.add(item.eventId); }
      if (fail) { res.statusCode = 503; return res.end('{}'); }
      return res.end(JSON.stringify({ accepted: body.items.map(item => item.eventId) }));
    }
    res.end('{}');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const env = { DECOY_PLATFORM_URL: `http://127.0.0.1:${server.address().port}`, DECOY_DEPLOYMENT: randomUUID(), DECOY_RUNTIME_TOKEN: 'a'.repeat(64), DYGK_STATE_DIR: dir };
  try {
    runtime = await start(env);
    fail = true;
    const response = await fetch(`http://127.0.0.1:${runtime.gateway.server.address().port}/_dygk/entry/0`);
    assert.equal(response.status, 200); await response.text();
    await assert.rejects(runtime.pump());
    const ids = runtime.state.pending().map(item => item.eventId); assert(ids.length > 0);
    assert.equal(runtime.platform.health().errorCode, 'delivery_failed');
    fail = false; await runtime.pump();
    assert.equal(runtime.state.size(), 0); assert(duplicate); assert(ids.every(id => accepted.has(id)));
    assert.equal(runtime.platform.health().errorCode, '');
    await runtime.stop(); runtime = undefined;
    config.release = { ...release, digest: 'sha256:'+'0'.repeat(64) };
    await assert.rejects(start(env), /不一致/);
    config.release = release;
    runtime = await start(env);
    assert.equal(runtime.state.size(), 0); assert.equal(runtime.gateway.server.listening, true);
  } finally {
    fail = false; if (runtime) await runtime.stop();
    await new Promise(resolve => server.close(resolve));
    await rm(dir, { recursive: true, force: true });
  }
});

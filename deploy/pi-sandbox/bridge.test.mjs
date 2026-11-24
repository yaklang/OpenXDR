import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import http from 'node:http';
import { registerHooks } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

// 沙箱依赖只在容器镜像中安装；单测仅验证 bridge.mjs 的轮次上限与结束态判定逻辑
registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === '@earendil-works/pi-coding-agent') {
      return { url: 'stub://pi-coding-agent', shortCircuit: true };
    }
    return nextResolve(specifier, context);
  },
  load(url, context, nextLoad) {
    if (url === 'stub://pi-coding-agent') {
      return {
        format: 'module',
        source: [
          'export const createAgentSession = () => { throw new Error("not used in unit test"); };',
          'export class DefaultResourceLoader {}',
          'export class ModelRuntime {}',
          'export const SessionManager = {};',
          'export const SettingsManager = {};',
        ].join('\n'),
        shortCircuit: true,
      };
    }
    return nextLoad(url, context);
  },
});

const { shouldLimitTurn, resolveRunOutcome, serveXdr } = await import('./bridge.mjs');

test('工具调用流中断报错（stopReason=error 且含部分 toolCall）达到 maxTurns 不误判为 max_turns', () => {
  const msg = {
    role: 'assistant',
    stopReason: 'error',
    errorMessage: 'upstream stream terminated',
    content: [
      { type: 'text', text: '正在排查...' },
      { type: 'toolCall', id: 'tc-1', name: 'bash', arguments: { command: 'ls' } },
    ],
  };
  assert.equal(shouldLimitTurn(msg, 4, 4), false);
  assert.throws(
    () => resolveRunOutcome(msg, 4, false),
    /upstream stream terminated/,
  );
});

test('工具调用被外部中止（stopReason=aborted 且含部分 toolCall）达到 maxTurns 不误判为 max_turns', () => {
  const msg = {
    role: 'assistant',
    stopReason: 'aborted',
    errorMessage: 'request aborted',
    content: [{ type: 'toolCall', id: 'tc-2', name: 'bash', arguments: {} }],
  };
  assert.equal(shouldLimitTurn(msg, 4, 4), false);
  assert.throws(
    () => resolveRunOutcome(msg, 4, false),
    /request aborted/,
  );
});

test('最后一轮纯文本正常结束不误判为 max_turns', () => {
  const msg = {
    role: 'assistant',
    stopReason: 'stop',
    content: [{ type: 'text', text: '已完成排查并给出结论' }],
  };
  assert.equal(shouldLimitTurn(msg, 4, 4), false);
  assert.deepEqual(resolveRunOutcome(msg, 4, false), {
    type: 'result',
    response: '已完成排查并给出结论',
    turns: 4,
    stop_reason: 'stop',
  });
});

test('正常产出工具调用且达到 maxTurns 时判定为 max_turns，未达上限时不截停', () => {
  const msg = {
    role: 'assistant',
    stopReason: 'toolUse',
    content: [
      { type: 'text', text: '继续执行检查' },
      { type: 'toolCall', id: 'tc-3', name: 'bash', arguments: { command: 'df -h' } },
    ],
  };
  assert.equal(shouldLimitTurn(msg, 3, 4), false);
  assert.equal(shouldLimitTurn(msg, 4, 4), true);
  assert.deepEqual(resolveRunOutcome(msg, 4, true), {
    type: 'result',
    response: '继续执行检查',
    turns: 4,
    stop_reason: 'max_turns',
  });

  // 主动 session.abort() 导致尾消息 stopReason=aborted 时，仍按 max_turns 正常结算
  const abortedByLimit = {
    role: 'assistant',
    stopReason: 'aborted',
    content: [{ type: 'text', text: '继续执行检查' }],
  };
  assert.deepEqual(resolveRunOutcome(abortedByLimit, 4, true), {
    type: 'result',
    response: '继续执行检查',
    turns: 4,
    stop_reason: 'max_turns',
  });
});

test('即便 limited 为真，真实 model error 也不会被 max_turns 掩盖', () => {
  const errMsg = {
    role: 'assistant',
    stopReason: 'error',
    errorMessage: '502 Bad Gateway',
    content: [{ type: 'text', text: '' }],
  };
  assert.throws(
    () => resolveRunOutcome(errMsg, 4, true),
    /502 Bad Gateway/,
  );
  assert.throws(
    () => resolveRunOutcome(undefined, 4, true),
    /Pi 未返回有效结果/,
  );
});

function postUnix(socketPath, body) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      socketPath,
      path: '/tool',
      method: 'POST',
      headers: { 'content-type': 'application/json' },
    }, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(Buffer.concat(chunks).toString()) }));
    });
    req.on('error', reject);
    req.end(body);
  });
}

test('serveXdr 对 null、原始类型或数组 JSON 请求体返回 HTTP 400', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'bridge-xdr-test-'));
  const socket = join(dir, 'xdr.sock');
  let called = 0;
  const server = serveXdr(new Set(['report']), async () => {
    called++;
    return { success: true, output: 'ok' };
  }, undefined, socket);
  await new Promise(resolve => server.once('listening', resolve));
  try {
    for (const payload of ['null', '123', '"hello"', 'true', '[]']) {
      const res = await postUnix(socket, payload);
      assert.equal(res.status, 400, `payload=${payload}`);
      assert.equal(typeof res.body.error, 'string');
    }
    assert.equal(called, 0);

    const ok = await postUnix(socket, JSON.stringify({ name: 'report', args: { title: 't' } }));
    assert.equal(ok.status, 200);
    assert.deepEqual(ok.body, { output: 'ok' });
    assert.equal(called, 1);
  } finally {
    await new Promise(resolve => server.close(resolve));
    rmSync(dir, { recursive: true, force: true });
  }
});

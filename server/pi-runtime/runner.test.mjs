import test from 'node:test';
// 验证切换发生在单次模型 HTTP 请求内，已执行的工具结果继续沿用。
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { run } from './runner.mjs';

const tool = { name: 'query', description: '查询测试数据', parameters: {
  type: 'object', properties: { sql: { type: 'string' } }, required: ['sql'], additionalProperties: false,
} };

test('额度耗尽后沿用备用模型与工具历史，工具只执行一次', async t => {
  const calls = [];
  let tools = 0;
  const apiBase = await mockModel(t, (body, res) => {
    calls.push(body.model);
    if (body.model === 'primary') { res.writeHead(429); res.end('{}'); return; }
    const hasResult = body.messages.some(m => m.role === 'tool');
    completion(res, hasResult ? { role: 'assistant', content: '完成' } : toolDelta, hasResult ? 'stop' : 'tool_calls');
  });
  const events = [];
  await run({ type:'run', api_base:apiBase, model:'primary', fallback_models:'backup', prompt:'测试', tools:[tool] },
    e => events.push(e), async () => { tools++; return { success:true, output:'已执行' }; });
  assert.deepEqual(calls, ['primary','backup','backup']);
  assert.equal(tools,1);
  const assistants = events.filter(e => e.event?.type === 'message_end' && e.event.message?.role === 'assistant');
  assert.ok(assistants.length >= 2);
  assert.ok(assistants.every(e => e.event.message.model === 'backup'));
  assert.equal(events.at(-1).response,'完成');
});

test('服务额度耗尽后切换 API 和密钥，沿用已执行的工具结果', async t => {
  const calls=[];let tools=0;
  const backup=await mockModel(t,(body,res)=>{
    calls.push('backup');assert.equal(res.req.headers.authorization,'Bearer backup-key');
    assert.equal(body.model,'backup-model');assert.ok(body.messages.some(m=>m.role==='tool'));
    completion(res,{role:'assistant',content:'备用完成'},'stop');
  });
  const primary=await mockModel(t,(body,res)=>{
    calls.push(body.model);assert.equal(res.req.headers.authorization,'Bearer primary-key');
    if (body.messages.some(m=>m.role==='tool')) {res.writeHead(402);res.end('{}');return;}
    completion(res,toolDelta,'tool_calls');
  });
  const events=[];
  await run({type:'run',api_base:primary,api_key:'primary-key',model:'primary-model',fallback_models:'primary-backup',
    fallback_endpoints:[{base_url:backup,api_key:'backup-key',model:'backup-model'}],prompt:'测试',tools:[tool]},
    e=>events.push(e),async()=>{tools++;return {success:true,output:'工具完成'};});
  assert.deepEqual(calls,['primary-model','primary-model','primary-backup','backup']);
  assert.equal(tools,1);assert.equal(events.at(-1).response,'备用完成');
  const last=events.findLast(e=>e.event?.type==='message_end' && e.event.message?.role==='assistant');
  assert.equal(last.event.message.model,'backup-model');
});

async function mockModel(t, responder) {
  const server = createServer(async (req, res) => {
    let body = '';
    for await (const part of req) body += part;
    responder(JSON.parse(body), res);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => { server.closeAllConnections(); server.close(); });
  return `http://127.0.0.1:${server.address().port}/v1`;
}

function completion(res, delta, reason) {
  res.writeHead(200, { 'Content-Type': 'text/event-stream' });
  res.write(`data: ${JSON.stringify({ id: 'test', object: 'chat.completion.chunk',
    model: 'test', choices: [{ index: 0, delta, finish_reason: null }] })}\n\n`);
  res.end(`data: ${JSON.stringify({ choices: [{ index: 0, delta: {}, finish_reason: reason }],
    usage: { prompt_tokens: 10, completion_tokens: 3, total_tokens: 13 } })}\n\ndata: [DONE]\n\n`);
}

const toolDelta = { role: 'assistant', tool_calls: [{ index: 0, id: 'call_1', type: 'function',
  function: { name: 'query', arguments: '{"sql":"select 1"}' } }] };

test('真实 SDK + JSONL 子进程完成工具往返与最终回答', { timeout: 15000 }, async t => {
  let calls = 0;
  const apiBase = await mockModel(t, (body, res) => {
    calls++;
    assert.equal(body.model, 'test');
    assert.equal(body.chat_template_kwargs, undefined);
    assert.deepEqual(body.tools.map(item => item.function.name), ['query']);
    if (calls === 1) completion(res, toolDelta, 'tool_calls');
    else {
      assert.equal(body.messages.find(message => message.role === 'tool').content, '查询结果 1');
      completion(res, { role: 'assistant', content: '巡检完成' }, 'stop');
    }
  });
  const child = spawn(process.execPath, [new URL('./runner.mjs', import.meta.url).pathname], { stdio: ['pipe', 'pipe', 'pipe'] });
  t.after(() => child.kill());
  let stderr = '';
  child.stderr.on('data', data => { stderr += data; });
  const exited = new Promise(resolve => child.once('close', resolve));
  const lines = createInterface({ input: child.stdout });
  child.stdin.write(JSON.stringify({ type: 'run', api_base: apiBase, model: 'test', prompt: '测试', tools: [tool] }) + '\n');
  const events = [];
  for await (const line of lines) {
    const event = JSON.parse(line);
    events.push(event);
    if (event.type === 'tool_request') {
      assert.deepEqual(event.args, { sql: 'select 1' });
      child.stdin.write(JSON.stringify({ type: 'tool_result', call_id: event.call_id,
        success: true, output: '查询结果 1' }) + '\n');
    }
  }
  assert.equal(await exited, 0, stderr);
  assert.equal(calls, 2);
  assert.equal(events.at(-1).response, '巡检完成');
  assert.equal(events.at(-1).stop_reason, 'stop');
  assert.ok(events.some(event => event.event?.type === 'tool_execution_end'));
  assert.ok(events.some(event => event.event?.type === 'message_end' && event.event.message.role === 'toolResult'));
});

test('达到轮数限制时停止，不宣称自然完成', async t => {
  const apiBase = await mockModel(t, (_, res) => completion(res, toolDelta, 'tool_calls'));
  const events = [];
  await run({ type: 'run', api_base: apiBase, model: 'test', prompt: '测试', tools: [tool], max_turns: 1 },
    event => events.push(event), async () => ({ success: false, output: '未获审批' }));
  assert.equal(events.at(-1).stop_reason, 'max_turns');
  assert.ok(events.some(event => event.event?.type === 'tool_execution_end' && event.event.isError));
});

test('供应商失败不能生成成功结果', async t => {
  const apiBase = await mockModel(t, (_, res) => {
    res.writeHead(401, { 'Content-Type': 'application/json' });
    res.end('{"error":{"message":"无效密钥"}}');
  });
  const events = [];
  await assert.rejects(run({ type: 'run', api_base: apiBase, model: 'test', prompt: '测试' },
    event => events.push(event)), /无效密钥|401/);
  assert.ok(events.every(event => event.type !== 'result'));
});

test('拒绝重复工具名和无效输入', async () => {
  await assert.rejects(run({ type: 'run', api_base: 'http://localhost', model: 'test', prompt: '测试', tools: [tool, tool] }), /工具/);
  await assert.rejects(run({ type: 'run' }), /prompt/);
});

test('父进程关闭输入时终止待完成的模型请求', { timeout: 5000 }, async t => {
  let requested;
  const started = new Promise(resolve => { requested = resolve; });
  const apiBase = await mockModel(t, () => requested());
  const child = spawn(process.execPath, [new URL('./runner.mjs', import.meta.url).pathname]);
  t.after(() => child.kill());
  let output = '';
  child.stdout.on('data', data => { output += data; });
  child.stderr.resume();
  const exited = new Promise(resolve => child.once('close', resolve));
  child.stdin.write(JSON.stringify({ type: 'run', api_base: apiBase, model: 'test', prompt: '测试' }) + '\n');
  await started;
  child.stdin.end();
  assert.equal(await exited, 1);
  assert.ok(output.split('\n').filter(Boolean).map(line => JSON.parse(line)).some(event => event.type === 'error'));
});

test('GLM 本地端点显式关闭模板 thinking，保留工具调用', async t => {
  let calls = 0;
  const apiBase = await mockModel(t, (body, res) => {
    calls++;
    assert.deepEqual(body.chat_template_kwargs, { enable_thinking: false });
    assert.equal(body.max_completion_tokens ?? body.max_tokens, 8192);
    completion(res, calls === 1 ? toolDelta : { role: 'assistant', content: '已查询' }, calls === 1 ? 'tool_calls' : 'stop');
  });
  const events = [];
  await run({ type: 'run', api_base: apiBase, model: 'GLM-5.3-Flash', prompt: '测试', tools: [tool] },
    event => events.push(event), async () => ({ success: true, output: '1' }));
  assert.equal(calls, 2);
  assert.equal(events.at(-1).stop_reason, 'stop');
});

test('opencode.ai 仅对该精确域名附加会话与客户端归属头，跨轮保持一致', async t => {
  const originalFetch = globalThis.fetch;
  t.after(() => { globalThis.fetch = originalFetch; });
  const seenSessions = [];
  let calls = 0;
  globalThis.fetch = async (input, init) => {
    const url = new URL(typeof input === 'string' ? input : input.url);
    const headers = new Headers(init?.headers || (typeof input === 'object' ? input.headers : undefined));
    if (url.hostname === 'opencode.ai') {
      const sid = headers.get('x-opencode-session');
      assert.match(sid || '', /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i);
      assert.equal(headers.get('x-opencode-client'), 'pi');
      seenSessions.push(sid);
    } else {
      assert.equal(headers.get('x-opencode-session'), null);
      assert.equal(headers.get('x-opencode-client'), null);
    }
    calls++;
    const delta = calls === 1 ? toolDelta : { role: 'assistant', content: 'OK' };
    const reason = calls === 1 ? 'tool_calls' : 'stop';
    const sse = `data: ${JSON.stringify({ id: 'test', object: 'chat.completion.chunk', model: 'glm-5.3-flash', choices: [{ index: 0, delta, finish_reason: null }] })}\n\n` +
      `data: ${JSON.stringify({ choices: [{ index: 0, delta: {}, finish_reason: reason }], usage: { prompt_tokens: 5, completion_tokens: 2, total_tokens: 7 } })}\n\ndata: [DONE]\n\n`;
    return new Response(sse, { status: 200, headers: { 'Content-Type': 'text/event-stream' } });
  };
  await run({ type: 'run', api_base: 'https://opencode.ai/inference/go/v1', model: 'glm-5.3-flash', prompt: '测试', tools: [tool] },
    () => {}, async () => ({ success: true, output: '1' }));
  assert.equal(seenSessions.length, 2);
  assert.equal(seenSessions[0], seenSessions[1]);

  await run({ type: 'run', api_base: 'https://opencode.ai/inference/go/v1', model: 'glm-5.3-flash', prompt: '第二次会话' },
    () => {});
  assert.equal(seenSessions.length, 3);
  assert.notEqual(seenSessions[2], seenSessions[0]);

  await run({ type: 'run', api_base: 'https://opencode.ai.example.invalid/v1', model: 'glm-5.3-flash', prompt: '非目标域名' },
    () => {});
});

// 沙箱桥：跑在隔离容器里，与平台 runner.mjs 说同一套 JSONL 协议（stdin 收 run / tool_result，stdout 发 event / tool_request / result / error）。
// 用 Pi SDK 驱动默认工具（bash/read/edit/write）+ Skill；沙箱里的 xdr 命令行经 unix socket 把工具请求交给桥，
// 桥再转成 tool_request 交给平台——平台照常判权、审批、审计，沙箱本身不持有任何平台凭据，也不需要访问平台网络。
import { randomUUID } from 'node:crypto';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import { createInterface } from 'node:readline';
import { pathToFileURL } from 'node:url';
import { modelFallback } from './model-fallback.mjs';
import {
  createAgentSession, DefaultResourceLoader, ModelRuntime, SessionManager, SettingsManager,
} from '@earendil-works/pi-coding-agent';

const WORK = '/home/agent/work';
const AGENT_DIR = '/home/agent/.pi/agent';
const XDR_DIR = '/tmp/xdr';
const SKILLS = new URL('./skills', import.meta.url).pathname;
// 平台只认这三种消息角色；Pi 的压缩摘要等内部消息不回传
const ROLES = new Set(['user', 'assistant', 'toolResult']);
// 回传平台的事件：消息入库，工具起止供页面展示，其余（逐字增量）不传，省带宽
const FORWARD = new Set(['message_end', 'tool_execution_start', 'tool_execution_end', 'turn_end', 'agent_end']);
const isGLM = model => /(^|\/)glm[-_.]/i.test(model);

const textOf = message => (message?.content || [])
  .filter(part => part.type === 'text').map(part => part.text).join('');

// 模型配置按请求现写：GLM 走模板思考并跨轮保留，与在工作站上直接用 Pi 时一致
function writeModels(request) {
  const glm = isGLM(request.model);
  const provider = {
    baseUrl: request.api_base, api: 'openai-completions',
    apiKey: request.api_key || 'not-required', authHeader: Boolean(request.api_key),
    compat: glm ? {
      supportsDeveloperRole: false, supportsReasoningEffort: false, thinkingFormat: 'chat-template',
      chatTemplateKwargs: {
        enable_thinking: { $var: 'thinking.enabled' },
        reasoning_effort: { $var: 'thinking.effort', omitWhenOff: true },
        preserve_thinking: true,
      },
    } : { supportsDeveloperRole: false },
    models: [{
      id: request.model, name: request.model, reasoning: glm, input: ['text'],
      contextWindow: request.context_window || 131072, maxTokens: request.max_tokens || 32768,
      cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
      ...(glm ? { thinkingLevelMap: { off: 'none', minimal: 'low', low: 'low', medium: 'high', high: 'high', xhigh: 'max', max: 'max' } } : {}),
    }],
  };
  const path = `${XDR_DIR}/models.json`;
  writeFileSync(path, JSON.stringify({ providers: { openxdr: provider } }));
  return { path, reasoning: glm };
}

// 平台存的消息还原成 Pi 会话条目：按顺序串成一条链
function entriesOf(messages) {
  let parentId = null;
  return (messages || []).map(message => {
    const id = randomUUID();
    const entry = { type: 'message', id, parentId, timestamp: new Date(message.timestamp || Date.now()).toISOString(), message };
    parentId = id;
    return entry;
  });
}

// xdr 的入口：只接受本轮允许的工具名，参数原样交给平台校验
function serveXdr(allowed, callTool, signal) {
  const socket = `${XDR_DIR}/xdr.sock`;
  rmSync(socket, { force: true });
  const server = http.createServer((req, res) => {
    const reply = (status, body) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(body)); };
    if (req.method !== 'POST' || req.url !== '/tool') return reply(404, { error: '只有 POST /tool' });
    let size = 0;
    const chunks = [];
    req.on('data', chunk => {
      size += chunk.length;
      if (size > 1024 * 1024) req.destroy();
      else chunks.push(chunk);
    });
    req.on('end', async () => {
      let call;
      try { call = JSON.parse(Buffer.concat(chunks).toString()); } catch { return reply(400, { error: '请求不是 JSON' }); }
      if (!allowed.has(call.name)) return reply(200, { error: `本轮不允许使用 xdr ${call.name}` });
      try {
        const result = await callTool(randomUUID(), call.name, call.args ?? {}, signal);
        reply(200, result.success ? { output: result.output } : { error: result.output });
      } catch (error) { reply(200, { error: String(error.message || error) }); }
    });
  });
  server.listen(socket);
  return server;
}

export async function run(request, send, callTool, signal) {
  if (request.type !== 'run' || !request.prompt?.trim() || !request.model?.trim()) throw new Error('run 必须提供 prompt 和 model');
  const endpoint = new URL(request.api_base);
  if (!['http:', 'https:'].includes(endpoint.protocol) || endpoint.username || endpoint.password) {
    throw new Error('api_base 必须是无内嵌凭据的 HTTP(S) 地址');
  }
  const maxTurns = request.max_turns ?? 32;
  if (!Number.isInteger(maxTurns) || maxTurns < 1 || maxTurns > 1000) throw new Error('max_turns 超出范围');
  const allowed = new Set((request.tools || []).map(tool => tool.name));
  mkdirSync(XDR_DIR, { recursive: true });
  mkdirSync(WORK, { recursive: true });
  mkdirSync(AGENT_DIR, { recursive: true });
  writeFileSync(`${XDR_DIR}/context.json`, JSON.stringify(request.context ?? {}));
  const models = writeModels(request);

  const modelRuntime = await ModelRuntime.create({ modelsPath: models.path, authPath: `${XDR_DIR}/auth.json`, allowModelNetwork: false });
  const model = modelRuntime.getModel('openxdr', request.model);
  if (!model) throw new Error('模型配置无效');
  const loader = new DefaultResourceLoader({
    cwd: WORK, agentDir: AGENT_DIR, noExtensions: true, noPromptTemplates: true, noThemes: true, noContextFiles: true,
    additionalSkillPaths: [SKILLS], appendSystemPrompt: request.system_prompt ? [request.system_prompt] : [],
  });
  await loader.reload();
  const { session } = await createAgentSession({
    cwd: WORK, agentDir: AGENT_DIR, modelRuntime, model,
    thinkingLevel: models.reasoning ? (request.thinking || 'high') : 'off',
    tools: ['read', 'bash', 'edit', 'write'], resourceLoader: loader,
    sessionManager: SessionManager.inMemory(WORK, {}, entriesOf(request.messages)),
    // 长对话交给 Pi 自带的压缩：接近上下文上限时把早先的工具结果总结掉
    settingsManager: SettingsManager.inMemory({ compaction: { enabled: true, reserveTokens: 16384, keepRecentTokens: 20000 } }),
  });

  const xdr = serveXdr(allowed, callTool, signal);
  // 沙箱进程只服务一次 run；仅拦截模型 completions 的精确地址。
  const originalFetch = globalThis.fetch;
  const routing = modelFallback(request, originalFetch);
  let turns = 0;
  let limited = false;
  session.subscribe(event => {
    routing.annotate(event);
    if (event.type === 'turn_end' && ++turns >= maxTurns) {
      limited = true;
      session.abort();
    }
    if (!FORWARD.has(event.type)) return;
    if (event.type === 'message_end' && !ROLES.has(event.message?.role)) return;
    send({ type: 'event', event });
  });
  const abort = () => session.abort();
  signal?.throwIfAborted();
  signal?.addEventListener('abort', abort, { once: true });
  try {
    globalThis.fetch = routing.fetch;
    await session.prompt(request.prompt);
    signal?.throwIfAborted();
    const last = session.agent.state.messages.findLast(message => message.role === 'assistant');
    if (!limited && (!last || ['error', 'aborted'].includes(last.stopReason))) {
      throw new Error(last?.errorMessage || 'Pi 未返回有效结果');
    }
    send({ type: 'result', response: textOf(last), turns, stop_reason: limited ? 'max_turns' : last.stopReason });
  } finally {
    globalThis.fetch = originalFetch;
    signal?.removeEventListener('abort', abort);
    xdr.close();
  }
}

// 协议主循环与平台 runner.mjs 相同：第一条是 run，之后只收 tool_result
async function main() {
  const input = createInterface({ input: process.stdin, crlfDelay: Infinity });
  const controller = new AbortController();
  const pending = new Map();
  let started = false;
  let finished = false;
  let task;
  const send = message => process.stdout.write(`${JSON.stringify(message)}\n`);
  const fail = error => {
    if (finished) return;
    finished = true;
    controller.abort(error);
    send({ type: 'error', error: String(error.message || error) });
    process.exitCode = 1;
    input.close();
    process.stdin.pause();
  };
  const callTool = (id, name, args, signal) => new Promise((resolve, reject) => {
    const abort = () => { pending.delete(id); reject(new Error('工具调用已取消')); };
    if (signal?.aborted) return abort();
    signal?.addEventListener('abort', abort, { once: true });
    pending.set(id, reply => {
      signal?.removeEventListener('abort', abort);
      pending.delete(id);
      resolve(reply);
    });
    send({ type: 'tool_request', call_id: id, name, args });
  });
  input.on('line', line => {
    try {
      if (Buffer.byteLength(line) > 16 * 1024 * 1024) throw new Error('输入消息过大');
      const message = JSON.parse(line);
      if (message.type === 'run' && !started) {
        started = true;
        task = run(message, send, callTool, controller.signal).then(() => {
          finished = true;
          input.close();
          process.stdin.pause();
        }).catch(fail);
      } else if (message.type === 'tool_result' && pending.has(message.call_id)) {
        pending.get(message.call_id)(message);
      } else {
        throw new Error('无效或重复的协议消息');
      }
    } catch (error) { fail(error); }
  });
  input.on('close', () => {
    if (!finished) fail(new Error('平台输入提前关闭'));
  });
  await new Promise(resolve => input.once('close', resolve));
  await task;
  // 写管道是异步的：直接退出会丢掉还在缓冲里的最后几行（往往正是 result），先等 stdout 冲刷完
  await new Promise(resolve => process.stdout.write('', resolve));
  process.exit(process.exitCode ?? 0);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}

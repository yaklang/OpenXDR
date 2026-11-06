import { randomUUID } from 'node:crypto';
import { createInterface } from 'node:readline';
import { pathToFileURL } from 'node:url';
import { Agent } from '@earendil-works/pi-agent-core';
import { createModels, createProvider } from '@earendil-works/pi-ai';
import { openAICompletionsApi } from '@earendil-works/pi-ai/api/openai-completions.lazy';
import { modelFallback } from './model-fallback.mjs';

const textOf = message => (message?.content || [])
  .filter(part => part.type === 'text').map(part => part.text).join('');

// 每个进程只处理一次 run；工具全部回调平台，不注册本机文件或 shell 工具。
export async function run(request, send, callTool, signal) {
  if (request.type !== 'run' || !request.prompt?.trim() || !request.model?.trim()) {
    throw new Error('run 必须提供 prompt 和 model');
  }
  const endpoint = new URL(request.api_base);
  if (!['http:', 'https:'].includes(endpoint.protocol) || endpoint.username || endpoint.password) {
    throw new Error('api_base 必须是无内嵌凭据的 HTTP(S) 地址');
  }
  const maxTurns = request.max_turns ?? 32;
  const maxTokens = request.max_tokens ?? 8192;
  if (!Number.isInteger(maxTurns) || maxTurns < 1 || maxTurns > 1000 ||
      !Number.isInteger(maxTokens) || maxTokens < 1 || maxTokens > 65536) {
    throw new Error('max_turns 或 max_tokens 超出范围');
  }
  const tools = request.tools ?? [];
  if (!Array.isArray(tools) || new Set(tools.map(tool => tool.name)).size !== tools.length ||
      tools.some(tool => !/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(tool.name) || tool.parameters?.type !== 'object')) {
    throw new Error('工具名称或参数 schema 无效');
  }
  const sessionHeaders = endpoint.hostname.toLowerCase() === 'opencode.ai'
    ? { 'x-opencode-session': randomUUID(), 'x-opencode-client': 'pi' }
    : undefined;
  const models = createModels();
  models.setProvider(createProvider({
    id: 'openxdr', name: 'OpenXDR', baseUrl: endpoint.href,
    auth: { apiKey: { name: 'OpenXDR', resolve: async () => ({ auth: { apiKey: request.api_key || 'not-required' } }) } },
    api: openAICompletionsApi(),
    models: [{
      id: request.model, name: request.model, api: 'openai-completions', provider: 'openxdr',
      baseUrl: endpoint.href, reasoning: false, input: ['text'],
      cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
      contextWindow: 128000, maxTokens,
      compat: { supportsDeveloperRole: false, supportsReasoningEffort: false },
      ...(sessionHeaders ? { headers: sessionHeaders } : {}),
    }],
  }));
  let turns = 0;
  const routing = modelFallback(request);
  let limited = false;
  const agent = new Agent({
    initialState: {
      model: models.getModel('openxdr', request.model),
      systemPrompt: request.system_prompt || '', thinkingLevel: 'off',
      messages: request.messages || [],
      tools: tools.map(tool => ({
        ...tool, label: tool.name,
        execute: async (id, args, abortSignal) => {
          const reply = await callTool(id, tool.name, args, abortSignal);
          if (!reply.success) throw new Error(reply.output || '平台工具执行失败');
          return { content: [{ type: 'text', text: reply.output || '' }], details: {} };
        },
      })),
    },
    toolExecution: 'sequential',
    // GLM 的本地兼容端点不会从 SDK thinkingLevel 推断模板开关。
    streamFn: (model, context, options) => models.streamSimple(model, context, {
      ...options, maxTokens, fetch: routing.fetch,
      ...(/(^|\/)glm[-_.]/i.test(request.model) ? {
        samplingParams: { ...options?.samplingParams, chat_template_kwargs: { enable_thinking: false } },
      } : {}),
    }),
    shouldStopAfterTurn: ({ message }) => {
      turns++;
      limited = turns >= maxTurns && message.content.some(part => part.type === 'toolCall');
      return limited;
    },
  });
  agent.subscribe(event => { routing.annotate(event); send({ type: 'event', event }); });
  const abort = () => agent.abort();
  signal?.throwIfAborted();
  signal?.addEventListener('abort', abort, { once: true });
  try {
    await agent.prompt(request.prompt);
    signal?.throwIfAborted();
    const last = agent.state.messages.findLast(message => message.role === 'assistant');
    if (!last || ['error', 'aborted'].includes(last.stopReason)) {
      throw new Error(last?.errorMessage || 'Pi 未返回有效结果');
    }
    send({ type: 'result', response: textOf(last), turns,
      stop_reason: limited ? 'max_turns' : last.stopReason });
  } finally {
    signal?.removeEventListener('abort', abort);
  }
}

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
      if (Buffer.byteLength(line) > 4 * 1024 * 1024) throw new Error('输入消息过大');
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
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}

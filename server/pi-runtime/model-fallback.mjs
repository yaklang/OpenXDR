import { randomUUID } from 'node:crypto';
// 只在成功 HTTP 响应建立前切换，地址、密钥与模型始终整组绑定。
export function modelFallback(request, upstream = globalThis.fetch) {
  const completionURL = base => {
    const url = new URL(base.replace(/\/+$/, '') + '/chat/completions');
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash) throw new Error('备用服务地址无效');
    return url.href;
  };
  const primary = { base_url: request.api_base, api_key: request.api_key || '', model: request.model };
  const raw = [primary, ...(request.fallback_models || '').split(',').filter(Boolean).map(model => ({ ...primary, model })), ...(request.fallback_endpoints || [])];
  const candidates = [];
  const seen = new Set();
  for (const item of raw) {
    if (typeof item.model !== 'string' || !item.model || item.model.length > 128 || /\s/.test(item.model) || typeof item.api_key !== 'string') throw new Error('备用模型配置无效');
    const candidate = { ...item, url: completionURL(item.base_url) };
    candidate.group = JSON.stringify([candidate.url, candidate.api_key]);
    candidate.id = JSON.stringify([candidate.group, candidate.model]);
    if (!seen.has(candidate.id)) { seen.add(candidate.id); candidates.push(candidate); }
  }
  if (candidates.length > 25) throw new Error('备用模型配置超出上限');
  const endpoint = completionURL(request.api_base);
  const crossService = candidates.some(c => c.group !== candidates[0].group);
  const cooldown = new Map();
  const sessions = new Map();
  let actual = request.model;
  return {
    get model() { return actual; },
    async fetch(input, init) {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
      if (url !== endpoint || !init?.body || candidates.length === 1) return upstream(input, { ...init, redirect: 'error' });
      const original = JSON.parse(init.body);
      if (original.messages?.some(m => Array.isArray(m.content) && m.content.some(p => p.type !== 'text'))) {
        actual = original.model;
        return upstream(input, { ...init, redirect: 'error' });
      }
      let last;
      for (const candidate of candidates) {
        init.signal?.throwIfAborted();
        if ((cooldown.get(candidate.id) || 0) > Date.now() || (cooldown.get(candidate.group) || 0) > Date.now()) continue;
        const model = candidate.model;
        const body = { ...original, model };
        if (model !== original.model || candidate.group !== candidates[0].group) {
          delete body.chat_template_kwargs; delete body.thinking; delete body.reasoning_effort;
          if (/(^|\/)glm[-_.]/i.test(model)) body.chat_template_kwargs = { enable_thinking: false };
          if (/(^|\/)deepseek-(v4-)?(flash|pro)$/i.test(model)) body.thinking = { type: 'disabled' };
        }
        const headers = new Headers(init.headers);
        for (const name of ['authorization', 'api-key', 'x-api-key', 'cookie', 'proxy-authorization', 'openai-organization', 'openai-project', 'content-length']) headers.delete(name);
        if (candidate.api_key) headers.set('authorization', `Bearer ${candidate.api_key}`);
        if (new URL(candidate.url).hostname.toLowerCase() !== 'opencode.ai') {
          headers.delete('x-opencode-session'); headers.delete('x-opencode-client');
        } else {
          if (!sessions.has(candidate.group)) sessions.set(candidate.group, candidate.group === candidates[0].group ? headers.get('x-opencode-session') || randomUUID() : randomUUID());
          headers.set('x-opencode-session', sessions.get(candidate.group)); headers.set('x-opencode-client', 'pi');
        }
        let response;
        try {
          response = await upstream(candidate.url, { ...init, headers, body: JSON.stringify(body), redirect: 'error' });
        } catch {
          init.signal?.throwIfAborted();
          if (!crossService) throw new Error('连接推理服务失败');
          cooldown.set(candidate.group, Date.now() + 60000); last = '连接失败'; continue;
        }
        actual = model;
        if (response.ok) return response;
        if ([401, 403].includes(response.status) && crossService) {
          cooldown.set(candidate.group, Date.now() + 300000);
        } else if ([402, 429, 500, 502, 503, 504].includes(response.status)) {
          cooldown.set(candidate.id, Date.now() + (response.status === 402 ? 900000 : response.status === 429 ? 300000 : 60000));
        } else return response;
        last = `HTTP ${response.status}`;
        await response.body?.cancel();
      }
      throw new Error(last ? `全部候选模型调用失败（${last}）` : '所有候选模型均在冷却中');
    },
    annotate(event) {
      for (const m of [event.message, event.partial]) if (m?.role === 'assistant') m.model = actual;
    },
  };
}

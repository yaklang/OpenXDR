import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { modelFallback } from './model-fallback.mjs';

test('额度失败切换、冷却、按实际模型标记且重建模板参数', async () => {
  const calls = [];
  const route = modelFallback({ model: 'glm-primary', api_base: 'http://local/v1', fallback_models: 'backup' }, async (_, init) => {
    const body = JSON.parse(init.body); calls.push(body);
    return new Response('{}', { status: body.model === 'glm-primary' ? 429 : 200 });
  });
  const init = { body: JSON.stringify({ model: 'glm-primary', messages: [], chat_template_kwargs: { enable_thinking: false } }) };
  await route.fetch('http://local/v1/chat/completions', init);
  await route.fetch('http://local/v1/chat/completions', init);
  assert.deepEqual(calls.map(c => c.model), ['glm-primary','backup','backup']);
  assert.equal(calls[1].chat_template_kwargs, undefined);
  const event = { message: { role: 'assistant', model: 'glm-primary' } }; route.annotate(event);
  assert.equal(event.message.model, 'backup');
});

test('认证失败、坏请求、网络错误以及流中断不重放', async () => {
  for (const status of [400, 401, 403, 404, 200]) {
    let calls = 0;
    const route = modelFallback({ model: 'a', api_base: 'http://local/v1', fallback_models: 'b' }, async () => {
      calls++; return new Response(status === 200 ? new ReadableStream({ start(c) { c.error(new Error('stream failed')); } }) : '{}', { status });
    });
    const response = await route.fetch('http://local/v1/chat/completions', { body: '{"model":"a"}' });
    if (status === 200) await assert.rejects(response.text());
    assert.equal(calls, 1);
  }
});

test('全部失败与取消不会返回成功，沙箱与本机策略保持一致', async () => {
  let calls=0;
  const route=modelFallback({ model:'a',api_base:'http://local/v1',fallback_models:'b' },async()=>{calls++;return new Response('{}',{status:402});});
  await assert.rejects(route.fetch('http://local/v1/chat/completions',{body:'{}'}),/402/);
  assert.equal(calls,2);
  await assert.rejects(route.fetch('http://local/v1/chat/completions',{body:'{}'}),/冷却/);
  assert.equal(calls,2);
  const abort=new AbortController();abort.abort();
  await assert.rejects(route.fetch('http://local/v1/chat/completions',{body:'{}',signal:abort.signal}));
  assert.equal(readFileSync(new URL('./model-fallback.mjs',import.meta.url),'utf8'),readFileSync(new URL('../../deploy/pi-sandbox/model-fallback.mjs',import.meta.url),'utf8'));
});

test('服务连接或认证失败跳过本服务其他模型，替换全部认证头', async () => {
  for (const status of [401,403,'network']) {
    const calls=[];
    const route=modelFallback({model:'a',api_base:'http://a/v1',api_key:'key-a',fallback_models:'a2',fallback_endpoints:[{base_url:'http://b/v1',api_key:'key-b',model:'b'}]},async(url,init)=>{
      calls.push(url);
      if(url.includes('://a/')) {if(status==='network')throw new TypeError('secret-key-a');return new Response('{}',{status});}
      assert.equal(init.headers.get('authorization'),'Bearer key-b');
      assert.equal(init.headers.get('x-api-key'),null);assert.equal(init.headers.get('cookie'),null);
      assert.equal(init.redirect,'error');return new Response('{}');
    });
    const init={body:'{"model":"a"}',headers:{authorization:'Bearer key-a','x-api-key':'key-a',cookie:'private'}};
    await route.fetch('http://a/v1/chat/completions',init);
    await route.fetch('http://a/v1/chat/completions',init);
    assert.deepEqual(calls,['http://a/v1/chat/completions','http://b/v1/chat/completions','http://b/v1/chat/completions']);
  }
});

test('跨供应商不转发 OpenCode 会话标识，切入 OpenCode 时生成专属标识', async () => {
  for (const [first, second] of [['https://opencode.ai/v1','https://other/v1'],['https://other/v1','https://opencode.ai/v1']]) {
    let calls=0;
    const route=modelFallback({model:'a',api_base:first,api_key:'a',fallback_endpoints:[{base_url:second,api_key:'b',model:'b'}]},async(url,init)=>{
      calls++;
      if(url===first+'/chat/completions')return new Response('{}',{status:402});
      if(second.includes('opencode.ai')) {assert.equal(init.headers.get('x-opencode-client'),'pi');assert.ok(init.headers.get('x-opencode-session'));assert.notEqual(init.headers.get('x-opencode-session'),'origin-session');}
      else {assert.equal(init.headers.get('x-opencode-session'),null);assert.equal(init.headers.get('x-opencode-client'),null);}
      return new Response('{}');
    });
    await route.fetch(first+'/chat/completions',{body:'{"model":"a"}',headers:{'x-opencode-session':'origin-session','x-opencode-client':'pi'}});
    assert.equal(calls,2);
  }
});

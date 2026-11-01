import { createHash, randomUUID } from 'node:crypto';
import { readFile, readdir, mkdir, lstat } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { root, revision, prepare } from '../scripts/prepare-upstream.mjs';
import { ConnectorState } from './state.mjs';
import { Platform } from './platform.mjs';

export async function releaseInfo(core) {
  const hash = createHash('sha256');
  for (const folder of [join(core, 'lib'), join(root, 'web')]) {
    for (const file of (await readdir(folder)).filter(name => /\.(m?js)$/.test(name)).sort()) {
      hash.update(file); hash.update('\0'); hash.update(await readFile(join(folder, file))); hash.update('\0');
    }
  }
  return { engine: 'dygk', version: revision, digest: 'sha256:' + hash.digest('hex'), protocol: 1, stateSchema: 'dygk-sqlite-v1' };
}

async function runtimeToken(env) {
  if (env.DECOY_RUNTIME_TOKEN && env.DECOY_TOKEN_FILE) throw new Error('令牌环境变量与凭据文件互斥');
  if (!env.DECOY_TOKEN_FILE) return env.DECOY_RUNTIME_TOKEN;
  const stat = await lstat(env.DECOY_TOKEN_FILE);
  if (process.platform === 'win32' || !stat.isFile() || stat.isSymbolicLink() || stat.size > 256 || (stat.mode & 0o177) || (stat.uid !== 0 && stat.uid !== process.getuid())) throw new Error('凭据文件权限无法确认');
  return (await readFile(env.DECOY_TOKEN_FILE, 'utf8')).trim();
}

export async function start(env = process.env) {
  const core = await prepare(undefined, false);
  const release = await releaseInfo(core);
  if (!env.DYGK_STATE_DIR) throw new Error('必须配置 DYGK_STATE_DIR 持久数据目录');
  const platform = new Platform(env.DECOY_PLATFORM_URL || (env.DYGK_CONTROL_SOCKET ? 'http://127.0.0.1' : ''), env.DECOY_DEPLOYMENT, await runtimeToken(env));
  if (env.DYGK_CONTROL_SOCKET) platform.socketPath = env.DYGK_CONTROL_SOCKET;
  if (env.DECOY_INSTANCE) { if (!/^[a-f0-9-]{36}$/.test(env.DECOY_INSTANCE)) throw new Error('平台分配实例无效'); platform.instance = env.DECOY_INSTANCE; }
  const initial = await platform.config();
  if (initial.stopRequested) throw new Error('此登记已请求停止');
  await mkdir(env.DYGK_STATE_DIR, { recursive: true, mode: 0o700 });
  const state = new ConnectorState(join(env.DYGK_STATE_DIR, 'connector.sqlite'));
  const { createGateway } = await import(pathToFileURL(join(core, 'lib/gateway.js')));
  const { clientIP, send } = await import(pathToFileURL(join(core, 'lib/server.js')));
  const config = initial.config;
  if (initial.kind !== 'http' || initial.profile !== 'decoy') throw new Error('DYGK Web 仅支持 HTTP 诱饵识别能力');
  const gateway = createGateway({ ...config, database: join(env.DYGK_STATE_DIR, 'engine.sqlite'), trace: false,
    clientChallenge: 'off', ...(config.attachment === 'gateway' ? { upstream: config.upstream } : { directory: env.DYGK_SITE_DIR || join(root, 'web/site') }) });
  gateway.server.removeAllListeners('close');
  const host = env.DYGK_LISTEN_HOST || '127.0.0.1';
  let closed = false, pumping, timer, heartbeat, fallback, stopping;
  let errorCode = '';
  platform.health = () => ({ pending: state.size(), errorCode });
  const pump = () => {
    if (closed) return Promise.resolve(true);
    if (pumping) return pumping;
    pumping = (async () => {
      for (let n = 0; n < (stopping ? 1 : 10); n++) {
        let page;
        try { page = gateway.defense.readEvents(state.cursor(), 100); }
        catch (error) { if (error.code !== 'export_gap') throw error; state.gap(error, randomUUID()); page = gateway.defense.readEvents(state.cursor(), 100); }
        state.collect(page);
        const items = state.pending();
        if (items.length) state.acknowledge(await platform.send(items));
        if (!page.items.length && !state.size()) { if (errorCode === 'delivery_failed') errorCode = ''; return true; }
      }
      return false;
    })().catch(error => { errorCode = 'delivery_failed'; throw error; }).finally(() => { pumping = undefined; });
    return pumping;
  };
  const stop = (failed = false) => stopping ??= (async () => {
    if (closed) return;
    clearInterval(timer); clearInterval(heartbeat);
    gateway.server.close(); gateway.server.closeAllConnections();
    // 先停止入口，再补传；旧修订下的事件不会归到新修订。
    try {
      if (pumping) await pumping;
      let drained = false;
      const deadline = Date.now() + 20000;
      do { drained = await pump(); } while (!drained && Date.now() < deadline);
      if (!drained || state.size()) failed = true;
    } catch { failed = true; }
    closed = true;
    if (failed && !errorCode) errorCode = 'pending_on_stop';
    try { await platform.lease(failed ? 'failed' : 'stopped'); } catch { /* 平台不可用时保留本地回执，控制台最终显示心跳过期。 */ }
    if (fallback) fallback.defense.close();
    const health = platform.health();
    gateway.defense.close(); state.close();
    return { failed, ...health };
  })();
  const degrade = async error => {
    errorCode = 'platform_unavailable';
    console.error(error.message);
    if (config.attachment !== 'gateway') { await stop(true); return; }
    if (fallback) return;
    // 平台失联后停止生成诱饵，业务请求改走同一固定 upstream。
    // 已有局部封禁在其原 TTL 内继续拒绝；不延长 TTL，不新增封禁。
    clearInterval(timer); clearInterval(heartbeat);
    fallback = createGateway({ upstream: config.upstream, mode: 'off' });
    const handler = fallback.server.listeners('request')[0];
    gateway.server.removeAllListeners('request');
    gateway.server.on('request', (req, res) => {
      const ip = clientIP(req, config.trustedProxies);
      if (gateway.defense.isBlocked(ip) || gateway.defense.isQuarantined(ip)) return send(req, res, 403, { error: 'Access denied' });
      return handler(req, res);
    });
    try { await platform.lease('failed'); } catch { /* 无法确认时由租约到期表明失联。 */ }
  };
  let confirmed = Date.now();
  try {
    const previous = state.get('revision');
    if (previous && previous !== initial.revision && (state.size() || gateway.defense.readEvents(state.cursor(), 1).items.length)) throw new Error('旧修订仍有未确认事实，拒绝将积压转到新修订');
    state.set('revision', initial.revision);
    await platform.handshake(initial, release);
    gateway.server.on('upgrade', (req, socket) => { socket.end('HTTP/1.1 501 Not Implemented\r\nConnection: close\r\n\r\n'); });
    await new Promise((resolve, reject) => { gateway.server.once('error', reject); gateway.server.listen(initial.port, host, resolve); });
    await platform.lease('running');
    await pump();
    timer = setInterval(() => { pump().catch(error => { if (error.fatal || error.status && error.status < 500 && error.status !== 429) void degrade(error); else if (state.size() >= 10000) void degrade(error); }); }, 1000);
    let checking = false;
    heartbeat = setInterval(async () => {
      if (checking || closed) return; checking = true;
      try {
        const next = await platform.config();
        if (next.stopRequested) { await stop(); return; }
        if (next.revision !== initial.revision || next.release.digest !== release.digest) throw new Error('配置修订已变化');
        await platform.lease('running'); confirmed = Date.now();
      } catch (error) {
        if ((error.status && error.status < 500) || !error.status && Date.now() - confirmed >= 60000) await degrade(error);
        else if (Date.now() - confirmed >= 60000) await degrade(error);
      } finally { checking = false; }
    }, 30000);
    return { gateway, platform, state, stop, pump, degrade, get closed() { return closed; } };
  } catch (error) { errorCode = 'startup_failed'; await stop(true); throw error; }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.includes('--print-release')) console.log(JSON.stringify(await releaseInfo(await prepare(undefined, false))));
    else {
      const runtime = await start();
      for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => { void runtime.stop(); });
      console.log('DYGK 连接器已启动');
    }
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}

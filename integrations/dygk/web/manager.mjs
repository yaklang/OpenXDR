import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { prepare } from '../scripts/prepare-upstream.mjs';
import { releaseInfo, start } from './main.mjs';
import { socketRequest } from './platform.mjs';

// 运维只启用主编排中的模块。登记、修订、端口和运行身份全部由平台下发。
export async function runManager(env = process.env) {
  if (!env.DYGK_CONTROL_SOCKET || !env.DYGK_STATE_DIR) throw new Error('主编排未提供引擎控制通道或持久卷');
  const release = await releaseInfo(await prepare(undefined, false));
  const active = new Map(), finished = new Map(); let closed = false, polling = false;
  const confirmFinished = async () => {
    for (const items of Array.from({ length: Math.ceil(finished.size / 100) }, (_, i) => [...finished.values()].slice(i * 100, (i + 1) * 100))) {
      const result = await socketRequest(env.DYGK_CONTROL_SOCKET, '/engine/finished', { release, instances: items });
      if (!Array.isArray(result.accepted)) throw new Error('实例退出确认无效');
      for (const id of result.accepted) finished.delete(id);
    }
  };
  const stopInstance = async (id, item) => {
    const result = await item.runtime.stop();
    finished.set(id, { id, instance: item.runtime.platform.instance, revision: item.revision, state: result?.failed ? 'failed' : 'stopped', pending: result?.pending, errorCode: result?.errorCode });
    active.delete(id);
  };
  const poll = async () => {
    if (closed || polling) return; polling = true;
    try {
      for (const [id, item] of active) if (item.runtime.closed) await stopInstance(id, item);
      await confirmFinished();
      const instances = [...active.entries()].map(([id, item]) => ({ id, instance: item.runtime.platform.instance, revision: item.revision }));
      const result = await socketRequest(env.DYGK_CONTROL_SOCKET, '/engine/poll', { release, instances });
      if (!Array.isArray(result.jobs) || result.jobs.length > 100) throw new Error('平台任务集合无效');
      const desired = new Set(result.jobs.map(job => job.id));
      for (const [id, item] of active) {
        if (!desired.has(id)) await stopInstance(id, item);
      }
      for (const job of result.jobs) {
        if (closed) break;
        if (!/^[a-f0-9-]{36}$/.test(job.id) || !/^[a-f0-9-]{36}$/.test(job.revision)) throw new Error('平台登记或修订格式无效');
        const current = active.get(job.id);
        if (current && (job.stop || current.revision !== job.revision)) { await stopInstance(job.id, current); continue; }
        if (current || job.stop || !job.token) continue;
        try {
          const runtime = await start({ ...env, DECOY_PLATFORM_URL: undefined, DECOY_DEPLOYMENT: job.id, DECOY_INSTANCE: job.instance, DECOY_RUNTIME_TOKEN: job.token, DECOY_TOKEN_FILE: undefined, DYGK_STATE_DIR: join(env.DYGK_STATE_DIR, job.id) });
          active.set(job.id, { revision: job.revision, runtime });
        } catch (error) { finished.set(job.id, { id: job.id, instance: job.instance, revision: job.revision, state: 'failed', errorCode: 'startup_failed' }); console.error('托管登记 ' + job.id + ' 启动失败：' + error.message); }
      }
    } catch (error) {
      if (error.status === 403) {
        for (const [id, item] of active) await stopInstance(id, item);
        try { await confirmFinished(); } catch (failure) { console.error(failure.message); }
      }
      console.error(error.message);
    } finally { polling = false; }
  };
  await poll();
  const timer = setInterval(() => { void poll(); }, 5000);
  const stop = async () => { if (closed) return; closed = true; clearInterval(timer); while (polling) await new Promise(resolve => setTimeout(resolve, 50)); await Promise.allSettled([...active.entries()].map(([id, item]) => stopInstance(id, item))); try { await confirmFinished(); } catch (error) { console.error(error.message); } };
  return { stop, poll, active };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const manager = await runManager();
    for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => { void manager.stop(); });
    console.log('DYGK 托管管理器已启动');
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}

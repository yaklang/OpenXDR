import { readFile, writeFile, appendFile, mkdir, cp } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { resolve, join, dirname } from 'node:path';
import { knownSourceKinds } from '../web/state.mjs';
import { sourceSettings, acquireSource, verifySource } from './source.mjs';

export const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
export const lock = JSON.parse(await readFile(join(root, 'upstream.lock.json'), 'utf8'));
export const revision = lock.revision || lock.commit;
if (!/^[a-zA-Z0-9][a-zA-Z0-9._+-]{0,95}$/.test(revision || '')) throw new Error('上游快照版本无效');
export async function prepare(source, allowPrepare = true, refresh = false) {
  const target = join(root, '.upstream', revision);
  let settings, contents;
  if (allowPrepare) {
    settings = await sourceSettings({ source });
    // 本地模式即使存在构建缓存，也必须核验所选源码，不能静默使用旧版本。
    if (settings.mode === 'local') contents = await verifySource(await acquireSource(settings, lock), lock.files);
  }
  const overlayHash = createHash('sha256').update(await readFile(join(root, 'web/export-feed.mjs'))).update(await readFile(fileURLToPath(import.meta.url))).digest('hex');
  try {
    if (refresh) { const error = new Error('显式重建缓存'); error.code = 'ENOENT'; throw error; }
    const stamp = JSON.parse(await readFile(join(target, '.prepared.json'), 'utf8'));
    if (stamp.patch !== overlayHash) throw new Error('导出适配变更，需要使用 prepare-upstream --refresh 重新准备上游目录');
    for (const [file, expected] of Object.entries(stamp.files)) {
      if (createHash('sha256').update(await readFile(join(target, file))).digest('hex') !== expected) throw new Error('本地上游缓存已变化：' + file);
    }
    return target;
  } catch (error) { if (error.code !== 'ENOENT') throw error; }
  if (!allowPrepare) throw new Error('运行依赖缺失，必须在构建阶段准备上游；运行时不下载代码');
  contents ??= await verifySource(await acquireSource(settings, lock), lock.files);
  await mkdir(target, { recursive: true });
  for (const [file, content] of Object.entries(contents)) {
    await mkdir(dirname(join(target, file)), { recursive: true });
    await writeFile(join(target, file), content);
  }
  for (const file of Object.keys(lock.files).filter(name => name.startsWith('lib/') && name.endsWith('.js'))) {
    const content = await readFile(join(target, file), 'utf8');
    for (const match of content.matchAll(/event\('([^']+)'/g)) if (!knownSourceKinds.has(match[1])) throw new Error('候选上游新增事实，需先适配：' + match[1]);
  }
  const serverFile = join(target, 'lib/server.js');
  let server = await readFile(serverFile, 'utf8');
  const replace = (before, after) => {
    if (server.split(before).length !== 2) throw new Error('上游事件适配位置不匹配，停止更新');
    server = server.replace(before, after);
  };
  replace("import { DatabaseSync } from 'node:sqlite';", "import { DatabaseSync } from 'node:sqlite';\nimport { createEventFeed } from './openxdr-export.js';");
  replace("  const deleteEvents = db.prepare", "  const exportFeed = createEventFeed(db, {maxEvents,retention,now,quarantineTTL:sessionTTL});\n  const deleteEvents = db.prepare");
  replace("    const item = {ts:now(), kind, ip, session, data};", "    let item; exportFeed.transaction(() => { item = {ts:now(), kind, ip, session, data};");
  replace("    try { options.onEvent?.(item); }", "    item = exportFeed.append(item);\n    });\n    try { options.onEvent?.(item); }");
  const profileUpdate = "db.prepare('UPDATE sessions SET stage=1,csrf=? WHERE id=? AND stage=0 AND csrf=?').run(csrf,s.id,s.csrf)";
  const profileEvents = "        event('profile_submitted',ip,s.id,{framework:body.framework,version:body.version,provenance:'self_reported_unverified',credential:'synthetic_compat_key'});\n        event('honeypot_triggered',ip,s.id,{stage:'profile',credential:'synthetic_compat_key'});";
  replace(profileEvents, '');
  replace('const changed=' + profileUpdate + ';', 'const changed=exportFeed.transaction(() => { const changed=' + profileUpdate + '; if(changed.changes) {\n' + profileEvents + '\n} return changed; });');
  const confirmUpdate = "db.prepare('UPDATE sessions SET stage=2,csrf=? WHERE id=? AND stage=1 AND csrf=?').run(token(),s.id,s.csrf)";
  const confirmEvent = "        event('honeypot_completed',ip,s.id,{model:body.model,provenance:'self_reported_unverified'});";
  replace(confirmEvent, '');
  replace('const changed=' + confirmUpdate + ';', 'const changed=exportFeed.transaction(() => { const changed=' + confirmUpdate + '; if(changed.changes) {\n' + confirmEvent + '\n} return changed; });');
  const banWrite = "    db.prepare('INSERT INTO bans VALUES(?,?) ON CONFLICT(ip) DO UPDATE SET until=excluded.until').run(ip,until);\n    event('ip_banned',ip,session,{until,triggerStage});";
  replace(banWrite, '    exportFeed.transaction(() => {\n' + banWrite + '\n    });');
  replace("    clear: () => { quarantine?.entries.clear(); db.exec('DELETE FROM client_challenges; DELETE FROM sessions; DELETE FROM bans; DELETE FROM events;'); },", "    readEvents: (cursor,limit) => exportFeed.read(cursor,limit),\n    clear: () => { db.exec('BEGIN IMMEDIATE'); try { quarantine?.entries.clear(); db.exec('DELETE FROM client_challenges; DELETE FROM sessions; DELETE FROM bans; DELETE FROM events;'); exportFeed.clear(); db.exec('COMMIT'); } catch(error) {db.exec('ROLLBACK');throw error;} },");
  replace('  function isBlocked(ip) {', '  if (quarantine) quarantine.restore(exportFeed.quarantineState());\n  function isBlocked(ip) {');
  await writeFile(serverFile, server);
  const quarantineFile = join(target, 'lib/quarantine.js');
  const quarantine = await readFile(quarantineFile, 'utf8');
  const before = '  return { active, activate, handle, entries };';
  if (quarantine.split(before).length !== 2) throw new Error('上游隔离状态适配位置不匹配');
  await writeFile(quarantineFile, quarantine.replace(before, `  const restore = rows => { for (const row of rows) { if (row.until > now()) entries.set(row.ip, {until:row.until,requests:row.requests,revealed:new Set(row.revealed),probes:0,label:digest(row.ip).slice(0,12)}); } };
  return { active, activate, handle, entries, restore };`));
  await cp(join(root, 'web/export-feed.mjs'), join(target, 'lib/openxdr-export.js'));
  const files = {};
  for (const file of [...Object.keys(lock.files).filter(name => name === 'package.json' || name.startsWith('lib/')), 'lib/openxdr-export.js']) files[file] = createHash('sha256').update(await readFile(join(target, file))).digest('hex');
  await writeFile(join(target, '.prepared.json'), JSON.stringify({ patch: overlayHash, files }, null, 2));
  return target;
}
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const sourceIndex = process.argv.indexOf('--source');
  if (sourceIndex >= 0 && (!process.argv[sourceIndex + 1] || process.argv[sourceIndex + 1].startsWith('--'))) throw new Error('--source 缺少源码目录');
  const source = sourceIndex < 0 ? undefined : process.argv[sourceIndex + 1];
  const ci = process.argv.includes('--ci');
  if (ci && !process.env.GITHUB_OUTPUT) throw new Error('--ci 仅用于提供 GITHUB_OUTPUT 的工作流');
  const settings = await sourceSettings({ source });
  let available = true;
  if (ci && !settings.configured && settings.mode === 'local') {
    try { await acquireSource(settings, lock); }
    catch (error) { if (error.code !== 'local_source_missing') throw error; available = false; }
  }
  if (available) console.log(await prepare(source, true, process.argv.includes('--refresh')));
  else console.log('::warning::未提供私有 DYGK 源码，跳过依赖它的集成与镜像检查；来源选择单测和原生引擎检查仍执行。显式配置来源后，缺失源码或权限将使检查失败。');
  if (ci) await appendFile(process.env.GITHUB_OUTPUT, 'available=' + available + '\n');
}

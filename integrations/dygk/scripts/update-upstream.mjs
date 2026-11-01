import { execFileSync } from 'node:child_process';
import { readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { root, lock } from './prepare-upstream.mjs';
import { sourceSettings, acquireSource, snapshotFiles } from './source.mjs';
const args = process.argv.slice(2), options = {};
let commit, requestedRevision;
for (let i = 0; i < args.length; i++) {
  if (args[i] === '--source' || args[i] === '--revision') {
    const flag = args[i], value = args[++i];
    if (!value || value.startsWith('--')) throw new Error(flag + ' 缺少值');
    if (flag === '--source') options.source = value; else requestedRevision = value;
  } else if (!args[i].startsWith('--') && !commit) { commit = args[i]; options.mode = 'remote'; }
  else throw new Error('不支持的候选更新参数');
}
if (commit && options.source) throw new Error('本地源码与远端 commit 不能同时指定');
if (commit && !/^[a-f0-9]{40}$/.test(commit)) throw new Error('远端更新必须提供完整的上游 commit');
const settings = await sourceSettings(options);
const source = await acquireSource(settings, { ...lock, commit: commit || lock.commit });
const files = await snapshotFiles(source);
const unchanged = Object.keys(files).length === Object.keys(lock.files).length && Object.entries(files).every(([name, hash]) => lock.files[name] === hash);
const contentRevision = 'local-' + createHash('sha256').update(JSON.stringify(files)).digest('hex').slice(0, 16);
const revision = requestedRevision || (settings.mode === 'remote' ? commit || lock.commit : unchanged ? lock.revision || lock.commit : contentRevision);
if (!/^[a-zA-Z0-9][a-zA-Z0-9._+-]{0,95}$/.test(revision || '')) throw new Error('候选快照版本无效');
if (!unchanged && revision === (lock.revision || lock.commit)) throw new Error('源码内容已变化，必须使用新的快照版本');
const pkg = JSON.parse(await readFile(join(source, 'package.json'), 'utf8'));
const before = await readFile(join(root, 'upstream.lock.json'));
const { commit: previousCommit, ...metadata } = lock;
const provenance = settings.mode === 'remote' ? { commit: commit || previousCommit } : unchanged && previousCommit ? { commit: previousCommit } : {};
try {
  await writeFile(join(root, 'upstream.lock.json'), JSON.stringify({ ...metadata, ...provenance, revision, version: pkg.version, license: pkg.license, files }, null, 2) + '\n');
  execFileSync(process.execPath, ['scripts/prepare-upstream.mjs', '--source', source, '--refresh'], { cwd: root, stdio: 'inherit' });
  execFileSync(process.execPath, ['scripts/test-upstream.mjs'], { cwd: root, stdio: 'inherit' });
  execFileSync(process.execPath, ['--test', '--test-force-exit', 'tests/feed.test.mjs'], { cwd: root, stdio: 'inherit' });
  console.log('候选锁文件已更新。继续运行平台端到端及兼容检查，再提交变更。');
} catch (error) { await writeFile(join(root, 'upstream.lock.json'), before); throw error; }

import { readFile, mkdir, lstat, readdir } from 'node:fs/promises';
import { parseEnv } from 'node:util';
import { createHash } from 'node:crypto';
import { resolve, join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { upstreamGit } from './upstream-git.mjs';

const moduleRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');

// 构建配置复用仓库根的 .env，环境变量优先；运行端不读取源码来源配置。
export async function sourceSettings(options = {}, env = process.env) {
  const root = options.root || moduleRoot;
  let shared = {};
  try { shared = parseEnv(await readFile(join(root, '..', '..', '.env'), 'utf8')); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  const settings = { ...shared, ...env };
  const mode = options.source ? 'local' : options.mode ?? (settings.DYGK_SOURCE || 'local');
  if (mode !== 'local' && mode !== 'remote') throw new Error('DYGK_SOURCE 只允许 local 或 remote');
  const directory = options.source ?? (settings.DYGK_LOCAL_SOURCE || 'local-source');
  if (!directory) throw new Error('DYGK_LOCAL_SOURCE 不能为空');
  const configured = Boolean(options.source || options.mode || settings.DYGK_SOURCE || settings.DYGK_LOCAL_SOURCE);
  return { root, mode, directory: resolve(root, directory), token: settings.DYGK_UPSTREAM_TOKEN, configured };
}

export async function acquireSource(settings, lock) {
  if (settings.mode === 'local') {
    let info;
    try { info = await lstat(settings.directory); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    if (!info) {
      const error = new Error('本地 DYGK 源码未提供；请配置 DYGK_LOCAL_SOURCE，或显式选择 DYGK_SOURCE=remote');
      error.code = 'local_source_missing'; throw error;
    }
    if (!info.isDirectory() || info.isSymbolicLink()) throw new Error('本地 DYGK 来源必须是普通源码目录');
    return settings.directory;
  }
  if (!/^[a-f0-9]{40}$/.test(lock.commit || '')) throw new Error('远端来源需要锁文件中的完整 commit；请先更新远端候选版本');
  const source = join(settings.root, '.downloads', lock.commit);
  await mkdir(source, { recursive: true });
  const git = args => upstreamGit(source, args, lock.repository, settings.token ?? '');
  git(['init']); git(['fetch', '--depth', '1', lock.repository, lock.commit]); git(['checkout', '--detach', 'FETCH_HEAD']);
  if (git(['rev-parse', 'HEAD']).trim() !== lock.commit) throw new Error('上游 commit 不匹配');
  return source;
}

export async function sourceText(source, name) {
  if (name.startsWith('/') || name.includes('\\') || name.split('/').some(part => part === '..' || !part)) throw new Error('上游文件路径无效');
  const file = join(source, name);
  const info = await lstat(file);
  if (!info.isFile() || info.isSymbolicLink()) throw new Error('上游文件必须是普通文件：' + name);
  return (await readFile(file, 'utf8')).replaceAll('\r\n', '\n');
}

export async function verifySource(source, files) {
  const contents = {};
  for (const [name, expected] of Object.entries(files)) {
    const content = await sourceText(source, name);
    if (createHash('sha256').update(content).digest('hex') !== expected) throw new Error('上游文件摘要不匹配：' + name);
    contents[name] = content;
  }
  return contents;
}

export async function snapshotFiles(source) {
  const paths = ['package.json'];
  const walk = async name => {
    for (const entry of await readdir(join(source, name), { withFileTypes: true })) {
      if (entry.name.startsWith('.') || ['node_modules', '__pycache__'].includes(entry.name) || /\.(?:sqlite.*|pyc)$/.test(entry.name)) continue;
      const path = name + '/' + entry.name;
      if (entry.isSymbolicLink()) throw new Error('上游快照不接受符号链接：' + path);
      if (entry.isDirectory()) await walk(path); else if (entry.isFile()) paths.push(path);
    }
  };
  for (const name of ['lib', 'tests', 'examples']) await walk(name);
  paths.push('experiments/trace_analysis.py');
  const files = {};
  for (const name of paths.sort()) files[name] = createHash('sha256').update(await sourceText(source, name)).digest('hex');
  return files;
}

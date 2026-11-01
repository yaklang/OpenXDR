import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, cp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve, dirname, basename } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { sourceSettings, acquireSource, verifySource } from '../scripts/source.mjs';

async function workspace(t) {
  const parent = resolve(tmpdir());
  const dir = await mkdtemp(join(parent, 'openxdr-source-test-'));
  t.after(() => {
    if (dirname(dir) !== parent || !basename(dir).startsWith('openxdr-source-test-')) throw new Error('测试清理目录越界');
    return rm(dir, { recursive: true, force: true });
  });
  const root = join(dir, 'integrations', 'dygk');
  await mkdir(root, { recursive: true });
  return { dir, root };
}

test('源码来源复用 .env，环境变量优先且只接受明确模式', async t => {
  const { dir, root } = await workspace(t);
  await writeFile(join(dir, '.env'), 'DYGK_SOURCE=local\nDYGK_LOCAL_SOURCE=private-source\n');
  const local = await sourceSettings({ root }, {});
  assert.equal(local.mode, 'local'); assert.equal(local.directory, join(root, 'private-source'));
  assert.equal((await sourceSettings({ root }, { DYGK_SOURCE: 'remote' })).mode, 'remote');
  assert.equal((await sourceSettings({ root, source: 'export' }, { DYGK_SOURCE: 'remote' })).mode, 'local');
  await assert.rejects(sourceSettings({ root }, { DYGK_SOURCE: 'auto' }), /只允许/);
});

test('默认本地来源无须 Git，缺失源码时拒绝且不尝试远端', async t => {
  const { root } = await workspace(t);
  const settings = await sourceSettings({ root }, {});
  assert.equal(settings.mode, 'local');
  assert.equal(settings.configured, false);
  assert.equal((await sourceSettings({ root }, { DYGK_SOURCE: 'local' })).configured, true);
  await assert.rejects(acquireSource(settings, { repository: 'https://invalid.example', commit: 'a'.repeat(40) }), /本地 DYGK 源码未提供/);
  await mkdir(settings.directory);
  const previous = process.env.PATH;
  try { process.env.PATH = ''; assert.equal(await acquireSource(settings, {}), settings.directory); }
  finally { if (previous === undefined) delete process.env.PATH; else process.env.PATH = previous; }
});

test('本地导出目录接受 CRLF 规范化，拒绝内容篡改和越界路径', async t => {
  const { root } = await workspace(t);
  const source = join(root, 'local-source'); await mkdir(source);
  await writeFile(join(source, 'package.json'), '{"private":true}\r\n');
  const files = { 'package.json': createHash('sha256').update('{"private":true}\n').digest('hex') };
  assert.equal((await verifySource(source, files))['package.json'], '{"private":true}\n');
  await writeFile(join(source, 'package.json'), '{}\n');
  await assert.rejects(verifySource(source, files), /摘要不匹配/);
  await assert.rejects(verifySource(source, { '../outside': '' }), /路径无效/);
});

test('远端来源显式选择后获取锁定 commit，并拒绝非完整版本', async t => {
  const { dir, root } = await workspace(t);
  const remote = join(dir, 'remote'); await mkdir(remote);
  const git = args => execFileSync('git', args, { cwd: remote, encoding: 'utf8', stdio: 'pipe' }).trim();
  git(['init']); await writeFile(join(remote, 'package.json'), '{}\n'); git(['add', '.']);
  git(['-c', 'user.name=source-test', '-c', 'user.email=source-test@example.invalid', 'commit', '-m', 'fixture']);
  const commit = git(['rev-parse', 'HEAD']);
  const settings = await sourceSettings({ root }, { DYGK_SOURCE: 'remote' });
  await assert.rejects(acquireSource(settings, { commit: 'main' }), /完整 commit/);
  const downloaded = await acquireSource(settings, { repository: pathToFileURL(remote).href, commit });
  assert.equal(execFileSync('git', ['rev-parse', 'HEAD'], { cwd: downloaded, encoding: 'utf8' }).trim(), commit);
  const files = { 'package.json': createHash('sha256').update('{}\n').digest('hex') };
  assert.equal((await verifySource(downloaded, files))['package.json'], '{}\n');
});

test('CI 只在来源未配置且缺失时标记跳过，显式配置错误仍失败', async t => {
  const { root } = await workspace(t);
  await cp(new URL('../scripts/', import.meta.url), join(root, 'scripts'), { recursive: true });
  await cp(new URL('../web/', import.meta.url), join(root, 'web'), { recursive: true });
  await writeFile(join(root, 'upstream.lock.json'), JSON.stringify({ revision: 'fixture', files: {} }));
  const output = join(root, 'ci-output');
  const env = { ...process.env, DYGK_SOURCE: '', DYGK_LOCAL_SOURCE: '', GITHUB_OUTPUT: output, PATH: '' };
  const skipped = spawnSync(process.execPath, ['scripts/prepare-upstream.mjs', '--ci'], { cwd: root, env, encoding: 'utf8' });
  assert.equal(skipped.status, 0, skipped.stderr);
  assert.match(skipped.stdout, /::warning::/); assert.equal(await readFile(output, 'utf8'), 'available=false\n');
  await writeFile(join(root, 'local-source'), 'invalid source directory');
  const invalid = spawnSync(process.execPath, ['scripts/prepare-upstream.mjs', '--ci'], { cwd: root, env, encoding: 'utf8' });
  assert.notEqual(invalid.status, 0); assert.match(invalid.stderr, /普通源码目录/);
  await rm(join(root, 'local-source'));
  const configured = spawnSync(process.execPath, ['scripts/prepare-upstream.mjs', '--ci'], { cwd: root, env: { ...env, DYGK_SOURCE: 'local' }, encoding: 'utf8' });
  assert.notEqual(configured.status, 0); assert.match(configured.stderr, /本地 DYGK 源码未提供/);
  assert.equal(await readFile(output, 'utf8'), 'available=false\n');
});

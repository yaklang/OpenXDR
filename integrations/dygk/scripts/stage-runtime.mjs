import { mkdir, cp, writeFile, readFile } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { root, lock, revision, prepare } from './prepare-upstream.mjs';
import { releaseInfo } from '../web/main.mjs';
if (!process.argv[2]) throw new Error('必须指定运行包输出目录');
const output = resolve(process.argv[2]);
const source = await prepare();
await mkdir(join(output, '.upstream', revision), { recursive: true });
for (const name of ['package.json', 'upstream.lock.json', 'LICENSE']) await cp(join(root, name), join(output, name));
for (const name of ['web', 'scripts']) await cp(join(root, name), join(output, name), { recursive: true });
for (const name of ['lib', 'package.json', '.prepared.json']) await cp(join(source, name), join(output, '.upstream', revision, name), { recursive: true });
await writeFile(join(output, 'engine-manifest.json'), JSON.stringify(await releaseInfo(source), null, 2) + '\n');
await writeFile(join(output, 'UPSTREAM-NOTICE'), 'DYGK ' + revision + '\nUpstream license: ' + lock.license + '\nThis runtime requires permission for redistribution.\n');
// 包内不包含研究执行器、弱密码示例、测试数据或宿主目录。
const stamp = JSON.parse(await readFile(join(source, '.prepared.json'), 'utf8'));
if (Object.keys(stamp.files).some(name => name !== 'package.json' && !name.startsWith('lib/'))) throw new Error('缓存清单包含运行包范围外文件');

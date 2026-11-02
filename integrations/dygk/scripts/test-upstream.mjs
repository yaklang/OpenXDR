import { prepare } from './prepare-upstream.mjs';
import { readdir } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
const source = await prepare();
const tests = (await readdir(join(source, 'tests'))).filter(name => name.endsWith('.test.js')).map(name => join('tests', name));
execFileSync(process.execPath, ['--test', '--test-force-exit', ...tests], { cwd: source, stdio: 'inherit' });

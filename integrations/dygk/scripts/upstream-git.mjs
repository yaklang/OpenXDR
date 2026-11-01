import { execFileSync } from 'node:child_process';

// 凭据只通过子进程环境传递，不写 Git 配置、远端 URL 或运行包。
export function upstreamGit(cwd, args, repository, suppliedToken) {
  const env = { ...process.env, GIT_TERMINAL_PROMPT: '0' };
  const token = (suppliedToken ?? env.DYGK_UPSTREAM_TOKEN)?.trim();
  delete env.DYGK_UPSTREAM_TOKEN;
  if (token) {
    const url = new URL(repository);
    if (url.protocol !== 'https:' || url.username || url.password || url.hostname !== 'github.com') throw new Error('上游凭据只允许用于 GitHub HTTPS 仓库');
    const index = Number(env.GIT_CONFIG_COUNT || 0);
    if (!Number.isSafeInteger(index) || index < 0) throw new Error('Git 环境配置无效');
    env.GIT_CONFIG_COUNT = String(index + 1);
    env['GIT_CONFIG_KEY_' + index] = 'http.' + repository.replace(/\/$/, '') + '.extraheader';
    env['GIT_CONFIG_VALUE_' + index] = 'AUTHORIZATION: Basic ' + Buffer.from('x-access-token:' + token).toString('base64');
    // 外部 Git 调试设置可能把认证头写入日志。
    for (const key of Object.keys(env)) if (key.startsWith('GIT_TRACE') || key === 'GIT_CURL_VERBOSE') delete env[key];
  }
  try {
    return execFileSync('git', args, { cwd, encoding: 'utf8', stdio: 'pipe', env });
  } catch {
    throw new Error('获取锁定的 DYGK 源码失败；请检查网络和上游读取权限，私有仓库通过构建 secret 提供 DYGK_UPSTREAM_TOKEN');
  }
}

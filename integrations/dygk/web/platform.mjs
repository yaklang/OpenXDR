import { randomUUID } from 'node:crypto';
import { isIP } from 'node:net';
import http from 'node:http';

export function socketRequest(socketPath, path, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const request = http.request({ socketPath, path, method: body === undefined ? 'GET' : 'POST', headers: { ...headers, 'content-type': 'application/json' }, timeout: 5000 }, response => {
      const chunks = []; let bytes = 0;
      response.on('data', chunk => { bytes += chunk.length; if (bytes > 262144) response.destroy(new Error('控制响应过大')); else chunks.push(chunk); });
      response.on('error', reject);
      response.on('end', () => {
        if (response.statusCode < 200 || response.statusCode >= 300) { const error = new Error('平台控制请求失败，状态码 ' + response.statusCode); error.status = response.statusCode; reject(error); return; }
        try { const raw = Buffer.concat(chunks).toString('utf8'); resolve(raw ? JSON.parse(raw) : null); } catch (error) { reject(error); }
      });
    });
    request.on('timeout', () => request.destroy(new Error('平台控制请求超时'))); request.on('error', reject);
    request.end(body === undefined ? undefined : JSON.stringify(body));
  });
}

export class Platform {
  constructor(origin, deployment, token) {
    const url = new URL(origin);
    if (url.username || url.password || url.search || url.hash || url.pathname !== '/' || !['http:', 'https:'].includes(url.protocol)) throw new Error('平台必须为独立 HTTPS origin');
    if (url.protocol !== 'https:' && !['127.0.0.1', '[::1]'].includes(url.hostname)) throw new Error('仅 IP 回环允许 HTTP');
    if (!isIP(url.hostname.replaceAll(/[\[\]]/g, '')) && url.protocol !== 'https:') throw new Error('平台地址不安全');
    if (!/^[0-9a-f-]{36}$/.test(deployment) || !/^[0-9a-f]{64}$/.test(token)) throw new Error('登记或令牌格式无效');
    this.base = url.origin + '/api/deception-runtime/v1/deployments/' + deployment;
    this.token = token; this.instance = randomUUID(); this.revision = '';
  }
  async call(path, body) {
    if (this.socketPath) return socketRequest(this.socketPath, new URL(this.base).pathname + '/' + path, body, { authorization: 'Bearer ' + this.token, 'x-decoy-instance': this.instance, 'x-decoy-revision': this.revision });
    const response = await fetch(this.base + '/' + path, { method: body === undefined ? 'GET' : 'POST', redirect: 'error', signal: AbortSignal.timeout(5000), headers: { authorization: 'Bearer ' + this.token, 'content-type': 'application/json', 'x-decoy-instance': this.instance, 'x-decoy-revision': this.revision }, body: body === undefined ? undefined : JSON.stringify(body) });
    if (!response.ok) { const error = new Error('平台拒绝请求，状态码 ' + response.status); error.status = response.status; throw error; }
    const raw = await response.text(); if (raw.length > 262144) throw new Error('平台响应过大');
    return raw ? JSON.parse(raw) : null;
  }
  async config() { return this.call('config'); }
  async handshake(config, release) {
    if (JSON.stringify(config.release) !== JSON.stringify(release)) {
      const keys = ['engine', 'version', 'digest', 'protocol', 'stateSchema'];
      if (keys.some(key => config.release[key] !== release[key])) throw new Error('本地运行产物与准入版本不一致');
    }
    this.revision = config.revision;
    await this.call('handshake', { instance: this.instance, revision: this.revision, release });
  }
  async lease(state) { await this.call('lease', { instance: this.instance, state, ...this.health?.() }); }
  async send(items) {
    const result = await this.call('observations', { items });
    if (!Array.isArray(result.accepted) || result.accepted.length !== items.length || new Set(result.accepted).size !== items.length || items.some(item => !result.accepted.includes(item.eventId))) throw new Error('平台确认集合不完整');
    return result.accepted;
  }
}

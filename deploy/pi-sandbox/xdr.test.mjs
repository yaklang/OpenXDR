import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

const XDR_BIN = new URL('./xdr', import.meta.url).pathname;
const HOST_UUID = '11111111-2222-4333-8444-555555555555';
const CMD_UUID_1 = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeee1';
const CMD_UUID_2 = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeee2';
const EVENT_UUID_1 = 'bbbbbbbb-cccc-4ddd-8eee-fffffffffff1';
const EVENT_UUID_2 = 'bbbbbbbb-cccc-4ddd-8eee-fffffffffff2';

function runXdr(sock, ctxPath, args, input) {
  return new Promise((resolve, reject) => {
    const child = spawn(XDR_BIN, args, {
      env: { ...process.env, XDR_SOCKET: sock, XDR_CONTEXT: ctxPath },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    const out = [];
    const err = [];
    child.stdout.on('data', d => out.push(d));
    child.stderr.on('data', d => err.push(d));
    child.on('error', reject);
    child.on('close', code => {
      const stdout = Buffer.concat(out).toString('utf8');
      const stderr = Buffer.concat(err).toString('utf8');
      if (code === 0) resolve(stdout);
      else {
        const e = new Error(stderr || stdout || `exit ${code}`);
        e.code = code;
        e.stderr = stderr;
        reject(e);
      }
    });
    if (input !== undefined) child.stdin.end(input);
    else child.stdin.end();
  });
}

function withMockSocket(handler, fn) {
  const dir = mkdtempSync(join(tmpdir(), 'xdr-cli-test-'));
  const sock = join(dir, 'xdr.sock');
  const ctxPath = join(dir, 'context.json');
  writeFileSync(ctxPath, JSON.stringify({
    assets: [{ id: HOST_UUID, hostname: 'pve1', role: 'hypervisor', criticality: 5, zone: { name: 'core' }, os: 'linux' }],
  }));
  const calls = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => {
      const body = JSON.parse(Buffer.concat(chunks).toString());
      calls.push(body);
      const reply = handler(body);
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(reply));
    });
  });
  return new Promise((resolve, reject) => {
    server.listen(sock, async () => {
      try {
        const execXdr = (args, input) => runXdr(sock, ctxPath, args, input);
        await fn({ execXdr, calls });
        resolve();
      } catch (err) {
        reject(err);
      } finally {
        server.close();
        rmSync(dir, { recursive: true, force: true });
      }
    });
  });
}

test('xdr exec prints command id, status, exit code and rejects invalid timeout or extra args', async () => {
  await withMockSocket(call => {
    assert.equal(call.name, 'exec');
    return {
      output: JSON.stringify({
        id: CMD_UUID_1,
        status: 'succeeded',
        exit_code: 0,
        stdout: 'active\n',
        stderr: '',
        truncated: false,
      }),
    };
  }, async ({ execXdr, calls }) => {
    const out = await execXdr(['exec', 'pve1', 'systemctl is-active openxdr-agent', '45']);
    assert.equal(calls.length, 1);
    assert.deepEqual(calls[0].args, {
      host: HOST_UUID,
      cmd: 'systemctl is-active openxdr-agent',
      timeout: 45,
    });
    assert.match(out, new RegExp(`^\\[id=${CMD_UUID_1} status=succeeded exit=0\\]\\nactive\\n+`));

    // With optional --finding <uuid>
    calls.length = 0;
    const FINDING_UUID = 'ffffffff-1111-4222-8333-444444444444';
    await execXdr(['exec', 'pve1', 'systemctl restart demo.service', '60', '--finding', FINDING_UUID.toUpperCase()]);
    assert.equal(calls.length, 1);
    assert.deepEqual(calls[0].args, {
      host: HOST_UUID,
      cmd: 'systemctl restart demo.service',
      timeout: 60,
      finding_id: FINDING_UUID,
    });

    await assert.rejects(() => execXdr(['exec', 'no-such-host', 'id']), /本组没有主机 no-such-host/);
    await assert.rejects(() => execXdr(['exec', 'pve1', 'id', '--finding', 'not-a-uuid']), /finding_id 必须是有效的 UUID/);
    await assert.rejects(() => execXdr(['exec', 'pve1', 'id', '--unknown-opt']), /xdr exec 未知选项/);
    await assert.rejects(() => execXdr(['exec', 'pve1', 'id', '0']), /timeout 必须是 1–300 的整数秒/);
    await assert.rejects(() => execXdr(['exec', 'pve1', 'id', '301']), /timeout 必须是 1–300 的整数秒/);
    await assert.rejects(() => execXdr(['exec', 'pve1', 'id', '60', 'extra']), /xdr exec 参数过多/);
  });
});

test('xdr command-status forwards normalized UUID and rejects invalid UUID or extra args', async () => {
  await withMockSocket(call => {
    assert.equal(call.name, 'command_status');
    return {
      output: JSON.stringify({
        commandId: call.args.command,
        status: 'unknown',
        effect: 'not_assessed_by_this_tool',
        retry: 'not_authorized_by_this_tool',
      }),
    };
  }, async ({ execXdr, calls }) => {
    const out = await execXdr(['command-status', CMD_UUID_1.toUpperCase()]);
    assert.equal(calls.length, 1);
    assert.deepEqual(calls[0].args, { command: CMD_UUID_1 });
    assert.equal(JSON.parse(out).status, 'unknown');

    await assert.rejects(() => execXdr(['command-status', 'not-a-uuid']), /command 必须是有效的 UUID/);
    await assert.rejects(() => execXdr(['command-status', CMD_UUID_1, 'extra']), /xdr command-status 参数过多/);
  });
});

test('xdr verify-command forwards events and context_events and rejects invalid enums/UUIDs/options', async () => {
  await withMockSocket(call => {
    assert.equal(call.name, 'verify_command');
    return {
      output: JSON.stringify({
        verificationId: 'cccccccc-dddd-4eee-8fff-000000000001',
        commandId: call.args.command,
        outcome: call.args.outcome,
      }),
    };
  }, async ({ execXdr, calls }) => {
    const out = await execXdr([
      'verify-command',
      CMD_UUID_1,
      'effective',
      'exec_probe',
      '服务恢复 active',
      'systemctl is-active 返回 active',
      '--events', `${EVENT_UUID_1},${EVENT_UUID_2.toUpperCase()}`,
      '--context-events', EVENT_UUID_1,
    ]);
    assert.equal(calls.length, 1);
    assert.deepEqual(calls[0].args, {
      command: CMD_UUID_1,
      outcome: 'effective',
      method: 'exec_probe',
      expected: '服务恢复 active',
      observed: 'systemctl is-active 返回 active',
      event_ids: [EVENT_UUID_1, EVENT_UUID_2],
      context_event_ids: [EVENT_UUID_1],
    });
    assert.equal(JSON.parse(out).outcome, 'effective');

    await assert.rejects(
      () => execXdr(['verify-command', CMD_UUID_1, 'bad_outcome', 'exec_probe', 'ex', 'ob']),
      /outcome 必须是 effective \/ ineffective \/ inconclusive/,
    );
    await assert.rejects(
      () => execXdr(['verify-command', CMD_UUID_1, 'effective', 'bad_method', 'ex', 'ob']),
      /method 必须是 telemetry_post_action/,
    );
    await assert.rejects(
      () => execXdr(['verify-command', CMD_UUID_1, 'effective', 'exec_probe', 'ex', 'ob', '--events', 'bad-uuid']),
      /event_ids 必须是有效的 UUID/,
    );
    await assert.rejects(
      () => execXdr(['verify-command', CMD_UUID_1, 'effective', 'exec_probe', 'ex', 'ob', '--unknown-flag']),
      /xdr verify-command 未知选项/,
    );
  });
});

test('xdr track supports legacy 6-arg call, full optional metadata, and strict negative validation', async () => {
  await withMockSocket(call => {
    assert.equal(call.name, 'track');
    return { output: JSON.stringify({ id: 'dddddddd-eeee-4fff-8000-111111111111', status: call.args.status }) };
  }, async ({ execXdr, calls }) => {
    // 1. Legacy 6 positional arguments
    await execXdr(['track', 'pve1', 'disk-full', 'medium', 'open', '根分区 93%', '/dev/sda1 93%']);
    assert.equal(calls.length, 1);
    assert.deepEqual(calls[0].args, {
      host: HOST_UUID,
      key: 'disk-full',
      severity: 'medium',
      status: 'open',
      title: '根分区 93%',
      detail: '/dev/sda1 93%',
    });

    // 2. Full metadata: next_step + blocker + multiple evidence UUIDs + stdin detail
    const allowedBlockers = [
      'policy_required',
      'maintenance_window_required',
      'manual_business_decision',
      'legacy_decommission_confirm',
      'external_dependency',
      'permission',
      'unsupported',
    ];
    for (const blocker of allowedBlockers) {
      calls.length = 0;
      await execXdr([
        'track', 'pve1', 'svc-check', 'high', 'open', '服务阻塞', '-',
        '--next-step', '等待策略或窗口后只读复查',
        '--blocker', blocker,
        '--evidence', `${CMD_UUID_1},${CMD_UUID_2.toUpperCase()}`,
      ], '详细回执内容');
      assert.equal(calls.length, 1);
      assert.deepEqual(calls[0].args, {
        host: HOST_UUID,
        key: 'svc-check',
        severity: 'high',
        status: 'open',
        title: '服务阻塞',
        detail: '详细回执内容',
        next_step: '等待策略或窗口后只读复查',
        blocker,
        evidence_commands: [CMD_UUID_1, CMD_UUID_2],
      });
    }

    // 3. Resolved with evidence_commands
    calls.length = 0;
    await execXdr([
      'track', 'pve1', 'disk-full', 'medium', 'resolved', '根分区已恢复 70%', 'df -h 实测 70%',
      '--evidence', CMD_UUID_1,
    ]);
    assert.equal(calls.length, 1);
    assert.deepEqual(calls[0].args, {
      host: HOST_UUID,
      key: 'disk-full',
      severity: 'medium',
      status: 'resolved',
      title: '根分区已恢复 70%',
      detail: 'df -h 实测 70%',
      evidence_commands: [CMD_UUID_1],
    });

    // 3b. 结案理由：subsided 带代表规则，authorized 不带
    calls.length = 0;
    await execXdr([
      'track', 'pve1', 'dns-noise', 'medium', 'resolved', 'DNS 噪声已消失', '近 3 天零命中',
      '--evidence', CMD_UUID_1, '--resolution', 'subsided', '--rules', 'rule-a, rule-b',
    ]);
    assert.deepEqual(calls[0].args.resolution, 'subsided');
    assert.deepEqual(calls[0].args.recurrence_rules, ['rule-a', 'rule-b']);
    calls.length = 0;
    await execXdr(['track', 'pve1', 'kei-bt', 'medium', 'resolved', '回测工具属平台维护', '已删除', '--evidence', CMD_UUID_1, '--resolution=authorized']);
    assert.equal(calls[0].args.resolution, 'authorized');
    assert.equal(calls[0].args.recurrence_rules, undefined);
    await assert.rejects(
      () => execXdr(['track', 'pve1', 'x', 'low', 'resolved', 't', 'd', '--resolution', 'fixed']),
      /resolution 必须是 repaired/,
    );

    // 4. Strict negative validations (must fail before calling socket)
    calls.length = 0;
    await assert.rejects(
      () => execXdr(['track', 'pve1', 'disk-full', 'medium', 'open', '标题', '详情', '多余未加引号参数']),
      /xdr track 参数过多/,
    );
    await assert.rejects(
      () => execXdr(['track', 'pve1', 'disk-full', 'medium', 'open', '标题', '详情', '--bad-flag']),
      /xdr track 未知选项/,
    );
    await assert.rejects(
      () => execXdr(['track', 'pve1', 'disk-full', 'medium', 'open', '标题', '详情', '--blocker', 'not_allowed']),
      /blocker 必须是 policy_required/,
    );
    await assert.rejects(
      () => execXdr(['track', 'pve1', 'disk-full', 'medium', 'open', '标题', '详情', '--next-step', '   ']),
      /next_step 不能为空/,
    );
    await assert.rejects(
      () => execXdr(['track', 'pve1', 'disk-full', 'medium', 'resolved', '标题', '详情', '--evidence', 'bad-uuid']),
      /evidence_commands 必须是有效的 UUID/,
    );
    await assert.rejects(
      () => execXdr([
        'track', 'pve1', 'disk-full', 'medium', 'resolved', '标题', '详情',
        '--evidence', [CMD_UUID_1, CMD_UUID_2, CMD_UUID_1, CMD_UUID_2, CMD_UUID_1, CMD_UUID_2].join(','),
      ]),
      /evidence_commands 最多 5 条/,
    );
    assert.equal(calls.length, 0);
  });
});

test('xdr CLI over mock /tool socket simulating platform contract: positive resolution and unknown-command negative flow', async () => {
  // Simulate platform state (commands, findings, independent reviewer) behind bridge.mjs /tool socket
  const commands = new Map();
  const findings = new Map([
    ['service-down', {
      id: 'ffffffff-1111-4222-8333-444444444444',
      host: HOST_UUID,
      key: 'service-down',
      status: 'open',
      work_owner: 'ai',
      work: { stage: 'waiting', plan: '初始计划', blocker: '', evidence_commands: [] },
    }],
  ]);
  const allowedTools = new Set(['exec', 'command_status', 'verify_command', 'track']);

  await withMockSocket(call => {
    if (!allowedTools.has(call.name)) {
      return { error: `本轮不允许使用 xdr ${call.name}` };
    }
    if (call.name === 'exec') {
      const isReadOnly = call.args.cmd.startsWith('systemctl is-active') || call.args.cmd.startsWith('df -P');
      if (!isReadOnly) {
        for (const c of commands.values()) {
          if (c.host === call.args.host && !c.readOnly && ['pending', 'sent', 'unknown'].includes(c.status)) {
            return { error: '主机存在未确认的写操作，禁止自动新增修复指令；先查回执与只读效果' };
          }
        }
      }
      const id = call.args.cmd.includes('unknown-write') ? CMD_UUID_2 : CMD_UUID_1;
      const status = call.args.cmd.includes('unknown-write') ? 'unknown' : 'succeeded';
      const cmdObj = {
        id,
        host: call.args.host,
        cmd: call.args.cmd,
        finding_id: call.args.finding_id || null,
        readOnly: isReadOnly,
        status,
        exit_code: status === 'succeeded' ? 0 : null,
        stdout: status === 'succeeded' ? 'active\n' : null,
        stderr: '',
        truncated: false,
      };
      commands.set(id, cmdObj);
      if (status === 'unknown') {
        return { error: `命令 ${id} 投递或执行结果未知，请用 command_status 查询已有指令，禁止自动重试` };
      }
      return { output: JSON.stringify(cmdObj) };
    }
    if (call.name === 'command_status') {
      const c = commands.get(call.args.command);
      if (!c) return { error: '指令不存在或不在当前组' };
      return {
        output: JSON.stringify({
          commandId: c.id,
          assetId: c.host,
          kind: 'exec',
          status: c.status,
          exitCode: c.exit_code,
          stdout: c.stdout,
          effect: 'not_assessed_by_this_tool',
          retry: 'not_authorized_by_this_tool',
        }),
      };
    }
    if (call.name === 'track') {
      const f = findings.get(call.args.key);
      if (call.args.status === 'resolved') {
        for (const c of commands.values()) {
          if (c.host === call.args.host && !c.readOnly && ['pending', 'sent', 'unknown'].includes(c.status)) {
            return { error: '存在未确认写操作，不能宣称已修复' };
          }
        }
        const ev = call.args.evidence_commands || [];
        if (ev.length === 0) {
          return { error: '复查修复或人工阻塞必须关联 1–5 条本轮真实复查指令' };
        }
        for (const id of ev) {
          const c = commands.get(id);
          if (!c || !c.readOnly || c.status !== 'succeeded' || c.exit_code !== 0 || !c.stdout?.trim()) {
            return { error: '须引用独立只读复查，不能用修复动作成功代替效果验证' };
          }
        }
        f.status = 'resolved';
        f.work = {
          stage: 'resolved',
          plan: '独立复核通过：服务已恢复 active',
          blocker: '',
          evidence_commands: ev,
        };
        return { output: JSON.stringify({ id: f.id, status: 'resolved' }) };
      }
      f.work = {
        stage: call.args.blocker ? 'blocked' : 'waiting',
        plan: call.args.next_step || f.work.plan,
        blocker: call.args.blocker || '',
        evidence_commands: call.args.evidence_commands || [],
      };
      return { output: JSON.stringify({ id: f.id, status: 'open' }) };
    }
    return { error: '未知工具' };
  }, async ({ execXdr }) => {
    // Step 1: Read-only probe via xdr exec -> extract command ID from header
    const execOut = await execXdr(['exec', 'pve1', 'systemctl is-active demo.service']);
    const match = execOut.match(/^\[id=([0-9a-f-]+) status=succeeded exit=0\]/);
    assert.ok(match, `expected command id in header, got: ${execOut}`);
    const roCmdId = match[1];
    assert.equal(roCmdId, CMD_UUID_1);

    // Step 2: Negative case — simulate an unconfirmed write command (status=unknown)
    await assert.rejects(
      () => execXdr(['exec', 'pve1', 'systemctl restart unknown-write', '60', '--finding', 'ffffffff-1111-4222-8333-444444444444']),
      /投递或执行结果未知，请用 command_status 查询已有指令，禁止自动重试/,
    );
    const statusOut = JSON.parse(await execXdr(['command-status', CMD_UUID_2]));
    assert.equal(statusOut.status, 'unknown');
    assert.equal(statusOut.retry, 'not_authorized_by_this_tool');

    // Attempting another write command or resolving while unknown write exists MUST fail
    await assert.rejects(
      () => execXdr(['exec', 'pve1', 'systemctl restart demo.service', '60', '--finding', 'ffffffff-1111-4222-8333-444444444444']),
      /主机存在未确认的写操作，禁止自动新增修复指令/,
    );
    await assert.rejects(
      () => execXdr(['track', 'pve1', 'service-down', 'high', 'resolved', '服务已恢复', 'active', '--evidence', roCmdId]),
      /存在未确认写操作，不能宣称已修复/,
    );
    assert.equal(findings.get('service-down').status, 'open');

    // Step 3: Clear unknown state (simulate receipt finally arriving as succeeded) and verify resolution requires read-only probe
    commands.get(CMD_UUID_2).status = 'succeeded';
    commands.get(CMD_UUID_2).exit_code = 0;
    // Passing the write command ID as evidence must be rejected!
    await assert.rejects(
      () => execXdr(['track', 'pve1', 'service-down', 'high', 'resolved', '服务已恢复', 'active', '--evidence', CMD_UUID_2]),
      /须引用独立只读复查，不能用修复动作成功代替效果验证/,
    );
    // Passing the fresh read-only probe ID succeeds and closes the finding!
    const resolveOut = JSON.parse(await execXdr([
      'track', 'pve1', 'service-down', 'high', 'resolved', '服务已恢复', 'systemctl is-active 返回 active',
      '--evidence', roCmdId,
    ]));
    assert.equal(resolveOut.status, 'resolved');
    assert.equal(findings.get('service-down').status, 'resolved');
    assert.deepEqual(findings.get('service-down').work.evidence_commands, [roCmdId]);
  });
});

test('repair capability lookup and conditional follow-up fields preserve exact intent', async () => {
  await withMockSocket(() => ({ output: '{}' }), async ({ execXdr, calls }) => {
    await execXdr(['repair-capabilities', CMD_UUID_1.toUpperCase(), 'apt-get clean', '/']);
    assert.deepEqual(calls[0], { name: 'repair_capabilities', args: { finding_id: CMD_UUID_1, command: 'apt-get clean', mount: '/' } });
    const at = '2026-12-01T02:00:00Z';
    await execXdr(['track', 'pve1', 'disk-full', 'high', 'open', 'disk', 'evidence', '--blocker', 'cooldown', '--repair-command', 'apt-get clean', '--repair-mount', '/', '--depends-on', CMD_UUID_1, '--wake-at', at]);
    assert.equal(calls[1].args.repair_command, 'apt-get clean');
    assert.equal(calls[1].args.repair_mount, '/');
    assert.equal(calls[1].args.blocker, 'cooldown');
    assert.equal(calls[1].args.wake_at, at);
    assert.deepEqual(calls[1].args.depends_on, [CMD_UUID_1]);
    await assert.rejects(() => execXdr(['repair-capabilities', 'not-a-uuid']), /finding_id 必须是有效的 UUID/);
    assert.equal(calls.length, 2);
  });
});

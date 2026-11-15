# 内置已知良性链（Benign Chains）

本目录存放随平台发版同步的内置已知良性进程链定义（`*.yml`）。Server 启动时由 `internal/suppress.SyncBuiltins` 加载并幂等写入 `suppressions` 表（`created_by = "builtin"`）：

- **控制台可见、可停用**：全局管理员可在「抑制规则」页随时停用或重新启用，启停状态与累计命中计数在重启和升级后保留；
- **不可被 AI 修改或硬删除**：AI 会话仅能提议单主机短期草案，无法改动或删除内置链；
- **硬性安全闸门**：
  1. 仅放行低/中危（`severity <= 3`）规则；`high`（4）与 `critical`（5）永远不放行；
  2. 威胁情报命中（`intel:*`）、诱饵命中（`decoy:*`）以及高危类别（凭据窃取、清痕、削弱防御、破坏、持久化、容器逃逸）永远不放行；
  3. 每条链必须同时约束当前进程可执行路径（`process.file.path`）、命令行模式与父进程/多跳祖先血缘（`process.parent_process.*` / `ancestor.*`），禁止仅按命令名或注释放行。

## 字段约定

- `id`：唯一短标识（`^[a-z0-9][a-z0-9-]{2,63}$`），对应 `suppressions.builtin_key`。
- `title`：控制台展示名称。
- `description`：良性依据说明。
- `sample`：生产真实进程链样例。
- `rules`：`["*"]`（匹配所有通过低危与非高危闸门的规则）或显式规则 ID 列表。
- `conditions`：2–12 条 AND 条件；`ancestor.<path>` 在 `events` 表沿 `parent_process_guid` 回溯的祖先链上匹配，相同正整数 `group` 的条件必须同时命中同一个祖先进程。

## 验证与回测

- 回归对拍：`go run ./cmd/detectcheck --strict`（对照语料见 `validation/benign_chains.yml`，同时覆盖良性放行与仿冒血缘告警）。
- 生产数据回测：`DATABASE_URL=... go run ./cmd/backtest -days 7 -rules ../rules`（输出各内置良性链吸收的命中数及扣减后的规则噪声排行）。

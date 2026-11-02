# 证据摘录组件浏览器验收

范围：本地构建真实 `VerdictCard`、i18n 与样式，以脱敏合成数据在 Chromium 中验证。没有连接生产 API，没有启动 HTTP 服务（Playwright 路由直接返回构建产物）。不代表整页、认证链路、英文布局或真实模型语义已验收。

30 条摘录全部展开使摘要被推离首屏。修复为默认三条、其余原生 details 展开；单条超过三行可展开全文。文案不会因折叠而丢弃。

| 宽度 / 高度 | 修复前摘要顶部 | 修复后摘要顶部 |
| --- | ---: | ---: |
| 390 / 900 | 2457.5px | 512.5px |
| 1440 / 900 | 983.5px | 424.5px |

`before.json`、`after.json` 为相同合成输入的测量；`interactive.json` 另外验证默认三条可见、展开三十条、收起恢复三条。`excerptItems` 统计 DOM 中所有条目（含折叠内容），不代表可见数量。手机长字段的全文按钮可展开/收起；桌面该字段刚好能完整显示三行，无按钮是预期行为。初版验证脚本误要求桌面也显示按钮而超时，已按实际是否截断修正断言，没有放宽内容完整性检查。

两种宽度均验证多条摘录、旧版无摘录、等待、解析错误四种状态；无 pageerror、无横向溢出。前后截图一并保留。产品 Web build 和 lint 完成，仍有 chunk 大小与 Fast Refresh 非阻断警告。未部署。

`source-sha256.json` 对应最终组件、类型、词典与样式。`fixture-main.tsx` 与 `fixture-index.html` 是合成入口；原临时目录 `web/.triage-acceptance/` 已删除。复现时将这两个文件恢复为该目录的 `main.tsx` 与 `index.html`，按当前环境调整 `build.mjs` 与 `check.cjs` 的工作目录、Playwright 路径和浏览器路径，执行构建后运行 `check.cjs interactive`。脚本的绝对路径仅记录本次验证环境，不属于产品配置。

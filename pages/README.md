# OpenXDR 项目主页

本目录是 OpenXDR 的公开项目主页，与 `web/` 管理控制台相互独立。技术栈为
React、TypeScript、Vite 与 Tailwind CSS，由 `.github/workflows/pages.yml`
构建并发布到 GitHub Pages。

## 本地开发

```bash
npm ci
npm run dev
```

提交前至少运行：

```bash
npm run build
```

构建命令先执行 TypeScript 类型检查，再生成 `dist/` 静态文件。

## 国际化

主页目前支持简体中文和英文，入口位于 `src/i18n.tsx`：

- 浏览器首选语言列表中存在 `zh*` 时显示简体中文；
- 其他语言统一回退英文；
- 浏览器语言在页面打开期间发生变化时，页面会响应 `languagechange` 事件；
- 切换语言时同步更新 `<html lang>`、页面标题、description、可见文案和无障碍文案；
- 不使用 cookie、localStorage 或服务端状态保存语言偏好。

新增或修改主页文案时，必须同时维护中英文版本。品牌名、协议名、代码标识符和
GitHub 等专有名词可以保留原文。页面语言选择应继续由 `useLocale()` 提供，避免各组件
自行读取 `navigator.language` 后产生不一致状态。

## 发布

推送到 `master` 且改动命中 `pages/**` 或 `.github/workflows/pages.yml` 时，
GitHub Actions 会自动构建并部署主页。发布完成后应验证：

1. Pages workflow 成功；
2. 中英文浏览器语言分别渲染对应文案与 metadata；
3. `https://yaklang.io/OpenXDR/` 返回 200；
4. `https://openxdr.yuzhian.com.cn/` 正常跳转到 Pages 地址。

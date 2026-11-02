# OpenXDR 管理控制台

React、TypeScript、Vite、Ant Design 与 TanStack Query 构建的产品前端。
`pages/` 是独立的项目主页，不属于控制台。

## 开发与构建

在本目录执行：

```bash
npm ci
npm run dev
npm run build
npm run lint
```

开发服务默认转发 API 到本机 8080；可用 `OPENXDR_API=http://localhost:8082 npm run dev` 指定后端。
`build` 先运行 TypeScript 检查，再生成 `dist/`。生产部署由 Web 镜像中的 nginx 提供静态文件并转发 API，见 [部署文档](../docs/deployment.md)。

## 修改约定

- 路由页面位于 `src/pages/`，公共交互组件位于 `src/components/`，接口类型与调用集中在 `src/api.ts`。
- 可见文案在 `src/i18n.tsx` 同时维护中英文；页面沿用公共布局、主题和错误组件。
- 列表总数使用 API 的 `X-Total-Count`，不能把当前页长度当作总数。分页与筛选必须保持同一查询范围。
- 查询失败与空结果分开呈现；未知计数不能当成零，也不能据此显示“全部处理完毕”。
- 资产详情的局部状态按资产 ID 重置；可分享的筛选与标签状态使用 URL，保持刷新和浏览器历史一致。

## 验证

基础检查是 `npm run build` 与 `npm run lint`。涉及跳转、分页、窄屏或错误恢复时，补跑
[离线浏览器回归](../validation/web/README.md)。它以本地固定 API 数据测试构建产物，不会连接生产或真实模型。
目前 CI 的 Web 关卡执行构建，离线浏览器脚本需单独运行；真实后端与部署验收仍需另做。

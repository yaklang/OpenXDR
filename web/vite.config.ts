import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  build: {
    rollupOptions: {
      output: {
        // 只手动拆核心块：three 是懒加载页面（欢迎页 / 资产图谱）的大块，
        // react 与 motion/query 独立成块利于长期缓存，图标独立成块。
        // markdown 不手动分组：分组会把它依赖的 react/jsx-runtime 一起拉进来，入口就得静态加载整块；
        // 交给默认拆分，它只跟着懒加载的 Markdown 组件走。
        manualChunks(id) {
          if (!id.includes('node_modules')) return
          if (/node_modules\/(three|@react-three)\//.test(id)) return 'three'
          if (/node_modules\/(react|react-dom|react-router|scheduler)\//.test(id)) return 'react'
          if (/node_modules\/@ant-design\/icons/.test(id)) return 'icons'
          if (/node_modules\/@rc-component\/(table|select|picker|tree)/.test(id)) return 'rc-data'
          if (/node_modules\/(@rc-component|rc-)/.test(id)) return 'rc-vendor'
          if (/node_modules\/(motion|framer-motion|@tanstack)\//.test(id)) return 'vendor-motion'
        },
      },
    },
  },
  server: {
    proxy: {
      // 本机 8080 被占时可用 OPENXDR_API=http://localhost:18080 npm run dev
      '/api': process.env.OPENXDR_API ?? 'http://localhost:8080',
    },
  },
})

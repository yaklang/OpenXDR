import {build} from '/home/Kei/OpenXDR/web/node_modules/vite/dist/node/index.js';
await build({root:'/home/Kei/OpenXDR/web',build:{outDir:'/tmp/openxdr-observations-ui/dist',emptyOutDir:true,rollupOptions:{input:'/home/Kei/OpenXDR/web/.triage-acceptance/index.html'}}});

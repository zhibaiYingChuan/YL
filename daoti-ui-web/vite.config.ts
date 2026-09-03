import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// 玄镜前端构建配置。
// - base: './' 使产物可被 Tauri 静态加载（file:// 相对路径）。
// - outDir: 'dist' 与 Tauri frontendDist（../../daoti-ui-web/dist）对齐。
export default defineConfig({
  plugins: [react()],
  base: './',
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    strictPort: true,
  },
});
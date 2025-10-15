import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    host: true,
    strictPort: true,
    hmr: {
      clientPort: 3000,
    },
    // Proxy API requests to the backend during development. This avoids CORS and
    // works with Codespaces and other remote dev environments where the browser
    // can't reach localhost:8000 directly.
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
        secure: false,
      },
      '/health': {
        target: 'http://localhost:8000',
        changeOrigin: true,
        secure: false,
      },
      '/tor': {
        target: 'http://localhost:8000',
        changeOrigin: true,
        secure: false,
      },
      '/ws': {
        target: 'ws://localhost:8000',
        ws: true,
      }
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
    rollupOptions: {
      output: {
        manualChunks: {
          // Vendor chunk: React ecosystem
          'vendor-react': ['react', 'react-dom', 'react/jsx-runtime'],
          // Animation and UI libraries
          'vendor-animation': ['framer-motion'],
          // Icons
          'vendor-icons': ['lucide-react'],
          // Utilities
          'vendor-utils': ['axios', 'clsx', 'react-hot-toast', 'nprogress'],
        }
      }
    },
    chunkSizeWarningLimit: 600
  }
})
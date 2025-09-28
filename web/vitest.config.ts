import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./vitest.setup.ts'],
    // Vitest 3.x compatibility
    server: {
      deps: {
        inline: ['@testing-library/jest-dom']
      }
    }
  }
});
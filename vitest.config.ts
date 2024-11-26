import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    restoreMocks: true,
    environment: 'happy-dom',
    environmentOptions: {
      happyDOM: {
        url: 'http://www.example.com',
      },
    },
    coverage: {
      enabled: true,
      include: [
        'src/**',
      ],
      reporter: [
        'text-summary',
        'html',
      ],
    },
    setupFiles: ['./tests/setup.ts'],
  },
});

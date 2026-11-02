import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['tests/**/*.test.js'],
    env: {
      // TEST-ONLY value, committed on purpose. It is NOT a real secret and must never be used outside the test suite.
      JWT_SECRET: '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff',
    },
  },
});

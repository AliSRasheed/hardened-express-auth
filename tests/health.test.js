import { describe, expect, it } from 'vitest';
import { createTestApp, get } from './helpers.js';

describe('GET /health', () => {
  it('answers 200 without signing in', async () => {
    const res = await get(createTestApp(), '/health');

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ data: { status: 'ok' } });
  });
});

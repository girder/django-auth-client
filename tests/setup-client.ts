import { vi, beforeEach, afterEach } from 'vitest';
import { Window as HappyDomWindow } from 'happy-dom';

import OAuthClient from '../src/index.js';

// HappyDOM has its own version of Window with a few extra properties,
// so make them known to TypeScript
declare global {
  interface Window extends HappyDomWindow {}
}

// Add additional properties to Vitest context
declare module 'vitest' {
  interface TestContext {
    client: OAuthClient
  }
}

export function buildClient(scopes: string[] = []): OAuthClient {
  return new OAuthClient(new URL('https://api.example.com'), 'resonant-client-id', { scopes });
}

beforeEach((context) => {
  context.client = buildClient();
});

afterEach(async () => {
  // DOM must be manually reset between tests: https://github.com/vitest-dev/vitest/issues/682
  window.localStorage.clear();
  window.location.replace('http://www.example.com');
});

// Allow usage outside of a true HTTPS environment
vi.stubGlobal('isSecureContext', true);

import { vi, describe, expect, test, beforeAll, beforeEach, onTestFinished } from 'vitest';
import { buildClient } from './setup-client.js';
import { model as oauth2Model } from './oauth2.js';
import { AuthorizationFailureError, TokenFailureError } from '../src/index.js';

beforeAll(() => {
  // This can be useful for debugging, but it clobbers test progress,
  // so leave it off except for local use
  // import { setFlag } from '@openid/appauth';
  // setFlag('IS_LOG', true);
});

describe('API structure', () => {
  test('property types', ({ client }) => {
    expect(client.authHeaders).toBeInstanceOf(Object);
    expect(client.isLoggedIn).toBeTypeOf('boolean');

    expect(client.maybeRestoreLogin).toBeInstanceOf(Function);
    expect(client.redirectToLogin).toBeInstanceOf(Function);
    expect(client.logout).toBeInstanceOf(Function);
  });

  test('HTTPS enforcement', () => {
    onTestFinished(() => {
      vi.stubGlobal('isSecureContext', true);
    });
    vi.stubGlobal('isSecureContext', false);

    expect(() => buildClient()).toThrowError(/cannot operate within insecure contexts/);
  });
});

describe('not logged in', () => {
  test('initial state', ({ client }) => {
    expect(client.isLoggedIn).toEqual(false);
    expect(client.authHeaders).toEqual({});
  });

  test('no-op maybeRestoreLogin', async ({ client }) => {
    await client.maybeRestoreLogin();

    expect(client.isLoggedIn).toEqual(false);
    expect(client.authHeaders).toEqual({});
  });

  test('logout', async ({ client }) => {
    await client.logout();

    expect(client.isLoggedIn).toEqual(false);
    expect(client.authHeaders).toEqual({});
  });

  test('full login flow', async () => {
    let client = buildClient();
    // Test outbound redirect to authorization
    // const loaded = pEvent(window, 'load');
    await client.redirectToLogin();
    // The redirect is executed at the end of an un-awaited promise chain in
    // "RedirectRequestHandler.performAuthorizationRequest".
    // Unfortunately, the "window.happyDOM.waitUntilComplete()" API doesn't seem to always wait
    // for the unsettled promise chain to complete.
    await vi.waitUntil(() => window.location.href.startsWith('https://api.example.com'));

    expect(window.localStorage.length).toEqual(3);
    expect(window.localStorage.getItem('appauth_current_authorization_request')).not.toBeNull();
    const redirectUrl = new URL(window.location.href);
    expect(redirectUrl.hostname).toEqual('api.example.com');
    expect(redirectUrl.pathname).toEqual('/authorize/');
    expect(redirectUrl.searchParams.has('client_id')).toEqual(true);
    // Ensure PKCE is being used
    expect(redirectUrl.searchParams.has('code_challenge')).toEqual(true);
    expect(redirectUrl.searchParams.get('code_challenge_method')).toEqual('S256');

    // Execute inbound redirect from authorization
    const resp = await fetch(redirectUrl, { method: 'GET', redirect: 'manual' });

    expect(resp.status).toEqual(302);
    window.location.assign(resp.headers.get('Location')!);
    // Re-create the client, as this would happen after the redirect
    client = buildClient();

    // Test token exchange after inbound redirect
    await client.maybeRestoreLogin();

    expect(client.isLoggedIn).toEqual(true);
    expect(client.authHeaders).toHaveProperty('Authorization');
  });
});

describe('failed login', () => {
  test('invalid scope', async () => {
    // Use an invalid scope, as oauth2-server doesn't return a proper error response with
    // an invalid client ID
    let client = buildClient(['invalid-scope']);

    await client.redirectToLogin();
    await vi.waitUntil(() => window.location.href.startsWith('https://api.example.com'));

    const resp = await fetch(window.location.href, { method: 'GET', redirect: 'manual' });
    window.location.assign(resp.headers.get('Location')!);
    client = buildClient(['invalid-scope']);

    const maybeRestoreLoginRejection = expect(client.maybeRestoreLogin()).rejects;
    await maybeRestoreLoginRejection.toBeInstanceOf(AuthorizationFailureError);
    await maybeRestoreLoginRejection.toThrowError(/^OAuth2 error: invalid_scope/);

    expect(client.isLoggedIn).toEqual(false);
    expect(client.authHeaders).toEqual({});
    expect(window.localStorage).toHaveLength(0);
  });

  test('failed token exchange', async () => {
    let client = buildClient();
    await client.redirectToLogin();
    await vi.waitUntil(() => window.location.href.startsWith('https://api.example.com'));
    const resp = await fetch(window.location.href, { method: 'GET', redirect: 'manual' });
    window.location.assign(resp.headers.get('Location')!);
    client = buildClient();

    // Simulate a race condition where the client is disabled before token exchange
    vi.spyOn(oauth2Model, 'getClient').mockResolvedValueOnce(false);

    const maybeRestoreLoginRejection = expect(client.maybeRestoreLogin()).rejects;
    await maybeRestoreLoginRejection.toBeInstanceOf(TokenFailureError);
    await maybeRestoreLoginRejection.toThrowError(/^OAuth2 error: invalid_client/);
  });
});

describe('already logged in', () => {
  beforeEach(async (context) => {
    await context.client.redirectToLogin();
    await vi.waitUntil(() => window.location.href.startsWith('https://api.example.com'));
    const resp = await fetch(window.location.href, { method: 'GET', redirect: 'manual' });
    window.location.assign(resp.headers.get('Location')!);
    context.client = buildClient();
    await context.client.maybeRestoreLogin();
  });

  test('initial state', async ({ client }) => {
    expect(client.isLoggedIn).toEqual(true);
    expect(client.authHeaders).toHaveProperty('Authorization');
  });

  test('no-op maybeRestoreLogin', async ({ client }) => {
    await client.maybeRestoreLogin();

    expect(client.isLoggedIn).toEqual(true);
    expect(client.authHeaders).toHaveProperty('Authorization');
  });

  test('restore existing login with a new client', async () => {
    const newClient = buildClient();
    await newClient.maybeRestoreLogin();

    expect(newClient.isLoggedIn).toEqual(true);
    expect(newClient.authHeaders).toHaveProperty('Authorization');
  });

  test('logout', async ({ client }) => {
    await client.logout();

    expect(client.isLoggedIn).toEqual(false);
    expect(client.authHeaders).toEqual({});
    expect(window.localStorage).toHaveLength(0);
  });
});

// TODO: test auto-refresh of expired token

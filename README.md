# resonant-oauth-client
[![npm (scoped)](https://img.shields.io/npm/v/@resonant/oauth-client)](https://www.npmjs.com/package/@resonant/oauth-client)

A TypeScript library for performing OAuth login to a Resonant server.

## Description
This provides support for authenticating with Resonant servers,
using the OAuth2.0 Authorization Code Grant with PKCE flow.

## Usage
* Install the library:

  ```bash
  npm install @resonant/oauth-client
  ```

* Instantiate an `OauthClient` with your application-specific configuration:
  ```js
  import OauthClient from '@resonant/oauth-client';

  const oauthClient = new OauthClient(
    new URL(process.env.OAUTH_API_ROOT), // e.g. 'http://localhost:8000/oauth/'
    process.env.OAUTH_CLIENT_ID, // e.g. 'Qir0Aq7AKIsAkMDLQe9MEfORbHEBKsViNhAKJf1A'
  );
  ```

* Call `redirectToLogin` when it's time to start a login flow:
  ```js
  document.querySelector('#sign-in-link').addEventListener('click', (event) => {
    event.preventDefault();
    oauthClient.redirectToLogin();
    // This will redirect away from the current page
  });
  ```

* At the start of *every* page load, unconditionally call `maybeRestoreLogin`, to attempt to
  restore a login state; this will no-op if no login is present. Afterwards, get and store HTTP
  headers for authentication from `authHeaders`.
  ```js
  let authHeaders;
  oauthClient.maybeRestoreLogin()
    .then(() => {
      authHeaders = oauthClient.authHeaders;
    });
  ```

  or, if using ES6 and `async`/`await`:
  ```js
  await oauthClient.maybeRestoreLogin();
  const { authHeaders } = oauthClient;
  ```

* Include these headers with every Ajax API request:
  ```js
  fetch('http://localhost:8000/api/files', {
    headers: authHeaders,
  });
  ```

* The login state will persist across page refreshes. Call `logout` to clear any active login:
  ```js
  document.querySelector('#sign-out-link').addEventListener('click', (event) => {
    event.preventDefault();
    oauthClient.logout()
      .then(() => {
        authHeaders = oauthClient.authHeaders;
      });
  });
  ```

## Development
To develop the library using the example app:
```bash
# From the root of the repository
npm install
npm run watch
```
In another terminal:
```bash
# From the root of the repository
cd example
npm install
npm run serve
```

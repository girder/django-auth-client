import { http, HttpResponse, StrictRequest, DefaultBodyType } from 'msw';
import { setupServer } from 'msw/node';
import OAuth2Server from '@node-oauth/oauth2-server';

import oauth from './oauth2.js';

async function mswRequestToOauth(request: StrictRequest<DefaultBodyType>): Promise<OAuth2Server.Request> {
  // happy-dom has weird behavior whereby if a Request was created from a string, it will
  // have an internal Content-Type of "text/plain" and fail to support "request.formData", even
  // if the "Content-Type" header was set to "application/x-www-form-urlencoded". So, extract
  // the form data manually.
  const bodyText = await request.text();
  const bodyFormData = Object.fromEntries(new URLSearchParams(bodyText));

  const headers = {
    ...Object.fromEntries(request.headers),
    // TODO: Either happy-dom or jQuery is failing to add Content-Length headers, so the internals
    // of "@node-oauth/oauth2-server" are refusing to allow POST bodies
    'Content-Length': bodyText.length,
  };

  return new OAuth2Server.Request({
    body: bodyFormData,
    headers,
    method: request.method,
    query: Object.fromEntries(new URL(request.url).searchParams),
  });
}

function oauthResponseToMsw(oauthResponse: OAuth2Server.Response): HttpResponse {
  return HttpResponse.json(oauthResponse.body, {
    status: oauthResponse.status,
    headers: oauthResponse.headers,
  });
}

export default setupServer(
  // Define a route for the test URL, so navigations to load it don't trigger unknown route errors
  http.get('http://www.example.com/', () => new HttpResponse()),
  http.get('https://api.example.com/authorize/', async ({ request }) => {
    const oauthRequest = await mswRequestToOauth(request);
    const oauthResponse = new OAuth2Server.Response();
    try {
      await oauth.authorize(
        oauthRequest,
        oauthResponse,
        {
          authenticateHandler: {
            handle() {
              // Always assume the user is logged in with the authorization server.
              // Return a trivial user object.
              return {};
            },
          },
        },
      );
    } catch (error) {
      // Failed attempts will throw errors, but oauthResponse should be updated with the error code,
      // with is a redirect for authorization
      if (oauthResponse.status !== 302) {
        // Under some circumstances, the oauthResponse will not be updated.
        // Ideally, a redirect with the error code in the query string should be set, but
        // just make this an internal error.
        oauthResponse.status = 500;
        if (error instanceof Error) {
          oauthResponse.body = error.message;
        }
      }
    }
    return oauthResponseToMsw(oauthResponse);
  }),

  http.post('https://api.example.com/token/', async ({ request }) => {
    const oauthRequest = await mswRequestToOauth(request);
    const oauthResponse = new OAuth2Server.Response();
    try {
      await oauth.token(
        oauthRequest,
        oauthResponse,
      );
    } catch (error) {
      // Failed attempts will throw errors, but oauthResponse should be updated with the error code,
      // which is 400 for tokens
      if (oauthResponse.status !== 400) {
        oauthResponse.status = 500;
        if (error instanceof Error) {
          oauthResponse.body = error.message;
        }
      }
    }
    return oauthResponseToMsw(oauthResponse);
  }),

  http.post('https://api.example.com/revoke_token/', async ({ request }) => {
    const oauthRequest = await mswRequestToOauth(request);
    const oauthResponse = new OAuth2Server.Response({
      // RFC 7009 states that this has no body ann some servers send a non-JSON content type.
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
      },
      body: '',
    });
    // TODO: The test environment doesn't actually throw an error if `.json()` is called on this
    // response, but a real browser does.

    // The oauth2-server library doesn't implement revoking an "access_token".
    // Revoking a "refresh_token" is implemented internally, but not via a distinctly callable
    // mechanism. See RFC7009 for more information about token revocation.
    // TODO: Revoke the access token manually.

    return oauthResponseToMsw(oauthResponse);
  }),
);

import {
  AuthorizationNotifier,
  AuthorizationRequest,
  AuthorizationServiceConfiguration,
  BaseTokenRequestHandler,
  FetchRequestor,
  GRANT_TYPE_AUTHORIZATION_CODE,
  GRANT_TYPE_REFRESH_TOKEN,
  LocalStorageBackend,
  RevokeTokenRequest,
  TokenRequest,
  TokenResponse,
} from '@openid/appauth';

import { TokenRequestHandler } from '@openid/appauth/src/token_request_handler';
import NoHashQueryStringUtils from './query-string-utils';
import ResolvingRedirectRequestHandler from './resolving-redirect-request-handler';

export { TokenResponse };

/**
 * A stateless manager for OAuth server interaction.
 *
 * This wraps some messy details of low-level library usage.
 */
export default class OauthFacade {
  protected readonly config: AuthorizationServiceConfiguration;

  protected readonly authHandler = new ResolvingRedirectRequestHandler(
    new LocalStorageBackend(),
    new NoHashQueryStringUtils(),
  );

  protected readonly tokenHandler: TokenRequestHandler = new BaseTokenRequestHandler(
    new FetchRequestor(),
  );

  /**
   * Create an OauthFacade.
   *
   * @param authorizationServerBaseUrl The common base URL for Authorization Server endpoints,
   *                                   without a trailing slash.
   * @param redirectUrl The URL of the current page, to be redirected back to after authorization.
   * @param clientId The Client ID for this application.
   * @param scopes An array of scopes to request access to.
   */
  constructor(
    protected readonly authorizationServerBaseUrl: string,
    protected readonly redirectUrl: string,
    protected readonly clientId: string,
    protected readonly scopes: string[],
  ) {
    this.config = new AuthorizationServiceConfiguration({
      authorization_endpoint: this.authorizationEndpoint,
      token_endpoint: this.tokenEndpoint,
      revocation_endpoint: this.revocationEndpoint,
    });
  }

  protected get authorizationEndpoint(): string {
    return `${this.authorizationServerBaseUrl}/authorize/`;
  }

  protected get tokenEndpoint(): string {
    return `${this.authorizationServerBaseUrl}/token/`;
  }

  protected get revocationEndpoint(): string {
    return `${this.authorizationServerBaseUrl}/revoke_token/`;
  }

  /**
   * Start the Authorization Code flow, redirecting to the Authorization Server.
   *
   * This will trigger a page redirect.
   */
  public async startLogin(): Promise<void> {
    const authRequest = new AuthorizationRequest({
      client_id: this.clientId,
      redirect_uri: this.redirectUrl,
      scope: this.scopes.join(' '),
      response_type: AuthorizationRequest.RESPONSE_TYPE_CODE,
      extras: {
        response_mode: 'query',
      },
    });
    await authRequest.setupCodeVerifier();
    this.authHandler.performAuthorizationRequest(this.config, authRequest);
  }

  /**
   * Finish the Authorization Code flow, following a return from the Authorization Server.
   *
   * This will return a Promise, which will resolve with the access token if the page is in a valid
   * post-login state. Otherwise, the Promise will reject.
   */
  public async finishLogin(): Promise<TokenResponse> {
    const notifier = new AuthorizationNotifier();
    this.authHandler.setAuthorizationNotifier(notifier);

    // Fetch a valid auth response (or throw)
    const authRequestResponse = await this.authHandler.resolveAuthorizationRequest();

    // We have discovered in practice that @openid/appauth fails to properly clean up its
    // storage entries in some cases. We add this hack to manually garbage collect all
    // outstanding storage entries that the upstream library has left behind. Note that this
    // depends on implementation details of both this class (namely the use of LocalStorageBackend)
    // as well as of @openid/appauth (namely its storage key name conventions).
    Object.keys(localStorage).filter((key) => key.includes('appauth_authorization')).forEach((key) => {
      localStorage.removeItem(key);
    });

    // Exchange for an access token and return tokenResponse
    const tokenRequest = new TokenRequest({
      client_id: this.clientId,
      redirect_uri: this.redirectUrl,
      grant_type: GRANT_TYPE_AUTHORIZATION_CODE,
      code: authRequestResponse.response.code,
      extras: {
        // code_verifier should always be specified, but this is a safer runtime check
        code_verifier: authRequestResponse.request.internal?.code_verifier ?? '',
      },
    });
    return this.tokenHandler.performTokenRequest(this.config, tokenRequest);
  }

  public async refresh(token: TokenResponse): Promise<TokenResponse> {
    const tokenRequest = new TokenRequest({
      client_id: this.clientId,
      redirect_uri: this.redirectUrl,
      grant_type: GRANT_TYPE_REFRESH_TOKEN,
      refresh_token: token.refreshToken,
      // Don't specify a new scope, which will implicitly request the same scope as the old token
    });
    // Return the new token
    return this.tokenHandler.performTokenRequest(this.config, tokenRequest);
  }

  /**
   * Revoke an Access Token from the Authorization Server.
   *
   * This will return a Promise, which will resolve when the operation successfully completes.
   * In case of an error, the Promise will reject.
   */
  public async logout(token: TokenResponse): Promise<void> {
    const revokeTokenRequest = new RevokeTokenRequest({
      token: token.accessToken,
      token_type_hint: 'access_token',
      client_id: this.clientId,
    });
    await this.tokenHandler.performRevokeTokenRequest(this.config, revokeTokenRequest);
  }

  /**
   * Determine whether a given token is expired.
   */
  public static tokenIsExpired(token: TokenResponse): boolean {
    if (token.expiresIn !== undefined) {
      // Token has a known expiration
      const expirationDate = new Date((token.issuedAt + token.expiresIn) * 1000);
      const currentDate = new Date();
      if (expirationDate <= currentDate) {
        return true;
      }
    }
    // Not expired, or unknowable.
    return false;
  }
}

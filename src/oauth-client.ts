import OauthFacade, { TokenResponse, type TokenResponseJson } from './oauth-facade/index.js';

export type Headers = Record<string, string>;

export type OauthClientOptions = {
  scopes?: string[];
  redirectUrl?: URL;
};

export default class OauthClient {
  protected token: TokenResponse | null = null;

  protected readonly oauthFacade: OauthFacade;

  constructor(
    authorizationServerBaseUrl: URL,
    protected readonly clientId: string,
    {
      scopes = [],
      redirectUrl = new URL(window.location.toString()),
    }: OauthClientOptions = {},
  ) {
    if (!window.isSecureContext) {
      throw new Error('OAuth Client cannot operate within insecure contexts.');
    }

    const cleanedAuthorizationServerBaseUrl = new URL(authorizationServerBaseUrl);
    // A URL base cannot have query string or fragment components
    cleanedAuthorizationServerBaseUrl.search = '';
    cleanedAuthorizationServerBaseUrl.hash = '';

    // RFC6749 3.1.2 requires that the Redirection URI must not include a fragment component
    const cleanedRedirectUrl = new URL(redirectUrl);
    cleanedRedirectUrl.hash = '';

    this.oauthFacade = new OauthFacade(
      cleanedAuthorizationServerBaseUrl,
      cleanedRedirectUrl,
      this.clientId,
      scopes,
    );
  }

  public get isLoggedIn(): boolean {
    return this.token !== null;
  }

  public async redirectToLogin(): Promise<void> {
    await this.oauthFacade.startLogin();
  }

  public async maybeRestoreLogin(): Promise<void> {
    // Returning from an Authorization flow should trump any other source of token recovery.
    try {
      this.token = await this.oauthFacade.finishLogin();
    } catch {
      // Most likely, there is no pending Authorization flow.
      // Possibly, there is an Authorization failure, which will be emitted to the
      // console, but doesn't need to be fatal, since this can just proceed with no token.
    }
    // Regardless of the outcome, remove any Authorization parameters, since the flow is now
    // concluded.
    this.removeUrlParameters();

    if (!this.token) {
      // Try restoring from a locally saved token.
      this.loadToken();
    }

    if (this.token && OauthFacade.tokenIsExpired(this.token)) {
      // Need to refresh
      try {
        this.token = await this.oauthFacade.refresh(this.token);
      } catch (error) {
        console.error('Error refreshing token: %o', error);
        this.token = null;
      }
    }

    // Store the token value (which might be null).
    this.storeToken();
  }

  public async logout(): Promise<void> {
    if (this.token) {
      try {
        await this.oauthFacade.logout(this.token);
      } catch (error) {
        console.error('Error logging out token: %o', error);
      }
    }

    // As a guard against stateful weirdness, always to clear the token.
    this.token = null;
    this.storeToken();
  }

  public get authHeaders(): Headers {
    const headers: Headers = {};
    if (this.token) {
      headers.Authorization = `${this.token.tokenType} ${this.token.accessToken}`;
    }
    return headers;
  }

  protected get tokenStorageKey(): string {
    return `oauth-token-${this.clientId}`;
  }

  protected loadToken(): void {
    const serializedToken = window.localStorage.getItem(this.tokenStorageKey);
    this.token = serializedToken
      ? new TokenResponse(JSON.parse(serializedToken) as TokenResponseJson)
      : null;
  }

  protected storeToken(): void {
    if (this.token) {
      const serializedToken = JSON.stringify(this.token.toJson());
      window.localStorage.setItem(this.tokenStorageKey, serializedToken);
    } else {
      window.localStorage.removeItem(this.tokenStorageKey);
    }
  }

  /**
   * Remove Authorization Response parameters from the URL query string.
   */
  // eslint-disable-next-line class-methods-use-this
  protected removeUrlParameters(): void {
    const currentUrl = window.location.toString();

    const url = new URL(currentUrl);
    // Possible parameters in an Authorization Response
    const oauthParameters = [
      'code',
      'state',
      'error',
      'error_description',
      'error_uri',
    ];
    for (const oauthParameter of oauthParameters) {
      url.searchParams.delete(oauthParameter);
    }
    const newUrl = url.toString();

    if (currentUrl !== newUrl) {
      window.history.replaceState(null, '', newUrl);
    }
  }
}

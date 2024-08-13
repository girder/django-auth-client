import {
  type AuthorizationRequest,
  type AuthorizationResponse,
  RedirectRequestHandler,
} from '@openid/appauth';

export type SuccessfulAuthorizationRequestResponse = {
  request: AuthorizationRequest;
  response: AuthorizationResponse;
};

export default class ResolvingRedirectRequestHandler extends RedirectRequestHandler {
  /**
   * Return a Promise, guaranteed to always resolve with valid AuthorizationRequest and
   * AuthorizationResponse data, or reject.
   *
   * This fulfills the same role as completeAuthorizationRequestIfPossible, but returns data
   * via a Promise instead of a callback and provides additional error handling.
   */
  public async resolveAuthorizationRequest(): Promise<SuccessfulAuthorizationRequestResponse> {
    let authorizationRequestResponse;
    try {
      authorizationRequestResponse = await this.completeAuthorizationRequest();
      if (!authorizationRequestResponse) {
        // This is potentially a normal case of no auth flow, but could be an error with
        // mismatched internal and URL-returned state
        throw new Error('Authorization incomplete.');
      }
    } finally {
      ResolvingRedirectRequestHandler.purgeStorage();
    }

    const { response } = authorizationRequestResponse;
    if (!response) {
      // Based on the implementation of completeAuthorizationRequest, the error is
      // typically available at this point, but it cannot be structurally guaranteed
      const errorCode = authorizationRequestResponse.error?.error;
      const errorDescription = authorizationRequestResponse.error?.errorDescription;

      // This is an explicit server-provided error, so log it
      const error = new Error(`Authorization error: ${errorCode}${errorDescription ? `: ${errorDescription}` : ''}.`);
      console.error(error);
      throw error;
    }

    const { request } = authorizationRequestResponse;

    return {
      request,
      response,
    };
  }

  protected static purgeStorage(): void {
    // We have discovered in practice that @openid/appauth fails to properly clean up its
    // storage entries in some cases, namely anytime there is an error in the OAuth flow. We
    // add this hack to manually garbage collect all outstanding storage entries that the
    // upstream library may have left behind. Note that this fix violates modularity in two
    // relevant ways:
    // 1. The abstraction of StorageBackends should be respected by accessing "this.storageBackend",
    //    but that class provides no way to enumerate its keys, and it can't be easily extended
    //    (due to private instead of protected fields), so this accesses "localStorage" directly.
    // 2. The key names are private symbols from this module:
    //    https://github.com/openid/AppAuth-JS/blob/c30f85e490ab41c9f1e8f8ee05bfdfe964e08626/src/redirect_based_handler.ts
    const oldKeys = [
      'appauth_current_authorization_request',
      // We want to clean up entries that may have been left behind by potentially multiple
      // previous failed attempts, so we go nuclear and destroy any appauth_authorization items.
      ...Object.keys(localStorage)
        .filter((key) => key.includes('appauth_authorization')),
    ];
    oldKeys.forEach((key) => {
      localStorage.removeItem(key);
    });
  }
}

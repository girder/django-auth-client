import { FetchRequestor, AppAuthError } from '@openid/appauth';

// Unlike the upstream FetchRequestor, this returns the full response body on 400 or 401 status,
// which is how RFC 6749 5.2 requires Access Token Error Responses to be sent.
export default class OauthFetchRequestor extends FetchRequestor {
  private static toHeaders(settings: JQueryAjaxSettings) {
    const newHeaders = new Headers();
    for (const [key, value] of Object.entries(settings.headers ?? {})) {
      // Using != also removes undefined
      if (value != null) {
        newHeaders.append(key, value);
      }
    }
    return newHeaders;
  }

  private static toFormData(settings: JQueryAjaxSettings): FormData | string | undefined {
    if (!settings.data) {
      return undefined;
    }
    if (typeof settings.data === 'string') {
      return settings.data;
    }
    const formData = new FormData();
    for (const [key, value] of Object.entries(settings.data)) {
      formData.append(key, value);
    }
    return formData;
  }

  // eslint-disable-next-line class-methods-use-this
  public async xhr<T>(settings: JQueryAjaxSettings): Promise<T> {
    if (!settings.url) {
      // eslint-disable-next-line @typescript-eslint/no-throw-literal
      throw new AppAuthError('A URL must be provided.');
    }
    if (settings.method?.toUpperCase() !== 'POST') {
      // RFC 6749 3.2: The client MUST use the HTTP "POST" method when making access token
      // requests.
      // eslint-disable-next-line @typescript-eslint/no-throw-literal
      throw new AppAuthError('Only POST is allowed for token requests.');
    }

    const response = await fetch(settings.url, {
      method: settings.method,
      headers: OauthFetchRequestor.toHeaders(settings),
      body: OauthFetchRequestor.toFormData(settings),
    });
    if (response.status >= 500) {
      // eslint-disable-next-line @typescript-eslint/no-throw-literal
      throw new AppAuthError(`${response.statusText}: ${await response.text()}`);
    }
    return response.json();
  }
}

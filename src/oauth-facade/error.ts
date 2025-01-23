export abstract class OAuthFacadeError extends Error {
  constructor(message: string) {
    super(message);
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class NoAuthInProgressError extends OAuthFacadeError {
  constructor() {
    super('No authorization flow in progress.');
  }
}

export class ServerError extends OAuthFacadeError {
  constructor(message: string) {
    super(`Server error: ${message}.`);
  }
}

export abstract class OAuthFailureError extends OAuthFacadeError {
  constructor(
    public readonly errorCode: string,
    public readonly errorDescription: string | null = null,
    public readonly errorUri: URL | null = null,
  ) {
    const message = `OAuth2 error: ${errorCode}${errorDescription ? `: ${errorDescription}` : ''}.`;
    super(message);
  }
}

export class AuthorizationFailureError extends OAuthFailureError {}

export class TokenFailureError extends OAuthFailureError {}

export class LogoutFailureError extends OAuthFailureError {}

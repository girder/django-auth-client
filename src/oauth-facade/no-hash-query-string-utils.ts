import { BasicQueryStringUtils, type LocationLike, type StringMap } from '@openid/appauth';

export default class NoHashQueryStringUtils extends BasicQueryStringUtils {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  parse(input: LocationLike, useHash?: boolean): StringMap {
    // Even though it's not explicitly specified by a "response_mode=fragment" parameter, the
    // RedirectRequestHandler expects response parameter to be encoded in the fragment, instead
    // of the query string (which is the specification default).
    // See https://github.com/openid/AppAuth-JS/pull/167

    // Ignore useHash parameter, always use the query string instead
    return super.parse(input, false);
  }
}

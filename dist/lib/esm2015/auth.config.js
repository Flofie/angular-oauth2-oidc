export class AuthConfig {
    constructor(json) {
        /**
         * The client's id as registered with the auth server
         */
        this.clientId = '';
        /**
         * The client's redirectUri as registered with the auth server
         */
        this.redirectUri = '';
        /**
         * An optional second redirectUri where the auth server
         * redirects the user to after logging out.
         */
        this.postLogoutRedirectUri = '';
        /**
         * The auth server's endpoint that allows to log
         * the user in when using implicit flow.
         */
        this.loginUrl = '';
        /**
         * The requested scopes
         */
        this.scope = 'openid profile';
        this.resource = '';
        this.rngUrl = '';
        /**
         * Defines whether to use OpenId Connect during
         * implicit flow.
         */
        this.oidc = true;
        /**
         * Defines whether to request an access token during
         * implicit flow.
         */
        this.requestAccessToken = true;
        this.options = null;
        /**
         * The issuer's uri.
         */
        this.issuer = '';
        /**
         * The logout url.
         */
        this.logoutUrl = '';
        /**
         * Defines whether to clear the hash fragment after logging in.
         */
        this.clearHashAfterLogin = true;
        /**
         * Url of the token endpoint as defined by OpenId Connect and OAuth 2.
         */
        this.tokenEndpoint = null;
        /**
         * Url of the revocation endpoint as defined by OpenId Connect and OAuth 2.
         */
        this.revocationEndpoint = null;
        /**
         * Names of known parameters sent out in the TokenResponse. https://tools.ietf.org/html/rfc6749#section-5.1
         */
        this.customTokenParameters = [];
        /**
         * Url of the userinfo endpoint as defined by OpenId Connect.
         */
        this.userinfoEndpoint = null;
        this.responseType = '';
        /**
         * Defines whether additional debug information should
         * be shown at the console. Note that in certain browsers
         * the verbosity of the console needs to be explicitly set
         * to include Debug level messages.
         */
        this.showDebugInformation = false;
        /**
         * The redirect uri used when doing silent refresh.
         */
        this.silentRefreshRedirectUri = '';
        this.silentRefreshMessagePrefix = '';
        /**
         * Set this to true to display the iframe used for
         * silent refresh for debugging.
         */
        this.silentRefreshShowIFrame = false;
        /**
         * Timeout for silent refresh.
         * @internal
         * depreacted b/c of typo, see silentRefreshTimeout
         */
        this.siletRefreshTimeout = 1000 * 20;
        /**
         * Timeout for silent refresh.
         */
        this.silentRefreshTimeout = 1000 * 20;
        /**
         * Some auth servers don't allow using password flow
         * w/o a client secret while the standards do not
         * demand for it. In this case, you can set a password
         * here. As this password is exposed to the public
         * it does not bring additional security and is therefore
         * as good as using no password.
         */
        this.dummyClientSecret = null;
        /**
         * Defines whether https is required.
         * The default value is remoteOnly which only allows
         * http for localhost, while every other domains need
         * to be used with https.
         */
        this.requireHttps = 'remoteOnly';
        /**
         * Defines whether every url provided by the discovery
         * document has to start with the issuer's url.
         */
        this.strictDiscoveryDocumentValidation = true;
        /**
         * JSON Web Key Set (https://tools.ietf.org/html/rfc7517)
         * with keys used to validate received id_tokens.
         * This is taken out of the disovery document. Can be set manually too.
         */
        this.jwks = null;
        /**
         * Map with additional query parameter that are appended to
         * the request when initializing implicit flow.
         */
        this.customQueryParams = null;
        this.silentRefreshIFrameName = 'angular-oauth-oidc-silent-refresh-iframe';
        /**
         * Defines when the token_timeout event should be raised.
         * If you set this to the default value 0.75, the event
         * is triggered after 75% of the token's life time.
         */
        this.timeoutFactor = 0.75;
        /**
         * If true, the lib will try to check whether the user
         * is still logged in on a regular basis as described
         * in http://openid.net/specs/openid-connect-session-1_0.html#ChangeNotification
         */
        this.sessionChecksEnabled = false;
        /**
         * Interval in msec for checking the session
         * according to http://openid.net/specs/openid-connect-session-1_0.html#ChangeNotification
         */
        this.sessionCheckIntervall = 3 * 1000;
        /**
         * Url for the iframe used for session checks
         */
        this.sessionCheckIFrameUrl = null;
        /**
         * Name of the iframe to use for session checks
         */
        this.sessionCheckIFrameName = 'angular-oauth-oidc-check-session-iframe';
        /**
         * This property has been introduced to disable at_hash checks
         * and is indented for Identity Provider that does not deliver
         * an at_hash EVEN THOUGH its recommended by the OIDC specs.
         * Of course, when disabling these checks the we are bypassing
         * a security check which means we are more vulnerable.
         */
        this.disableAtHashCheck = false;
        /**
         * Defines wether to check the subject of a refreshed token after silent refresh.
         * Normally, it should be the same as before.
         */
        this.skipSubjectCheck = false;
        this.useIdTokenHintForSilentRefresh = false;
        /**
         * Defined whether to skip the validation of the issuer in the discovery document.
         * Normally, the discovey document's url starts with the url of the issuer.
         */
        this.skipIssuerCheck = false;
        /**
         * final state sent to issuer is built as follows:
         * state = nonce + nonceStateSeparator + additional state
         * Default separator is ';' (encoded %3B).
         * In rare cases, this character might be forbidden or inconvenient to use by the issuer so it can be customized.
         */
        this.nonceStateSeparator = ';';
        /**
         * Set this to true to use HTTP BASIC auth for AJAX calls
         */
        this.useHttpBasicAuth = false;
        /**
         * The interceptors waits this time span if there is no token
         */
        this.waitForTokenInMsec = 0;
        /**
         * Code Flow is by defauld used together with PKCI which is also higly recommented.
         * You can disbale it here by setting this flag to true.
         * https://tools.ietf.org/html/rfc7636#section-1.1
         */
        this.disablePKCE = false;
        /**
         * This property allows you to override the method that is used to open the login url,
         * allowing a way for implementations to specify their own method of routing to new
         * urls.
         */
        this.openUri = uri => {
            location.href = uri;
        };
        if (json) {
            Object.assign(this, json);
        }
    }
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYXV0aC5jb25maWcuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi8uLi9wcm9qZWN0cy9saWIvc3JjL2F1dGguY29uZmlnLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUFBLE1BQU0sT0FBTyxVQUFVO0lBNlByQixZQUFZLElBQTBCO1FBNVB0Qzs7V0FFRztRQUNJLGFBQVEsR0FBSSxFQUFFLENBQUM7UUFFdEI7O1dBRUc7UUFDSSxnQkFBVyxHQUFJLEVBQUUsQ0FBQztRQUV6Qjs7O1dBR0c7UUFDSSwwQkFBcUIsR0FBSSxFQUFFLENBQUM7UUFFbkM7OztXQUdHO1FBQ0ksYUFBUSxHQUFJLEVBQUUsQ0FBQztRQUV0Qjs7V0FFRztRQUNJLFVBQUssR0FBSSxnQkFBZ0IsQ0FBQztRQUUxQixhQUFRLEdBQUksRUFBRSxDQUFDO1FBRWYsV0FBTSxHQUFJLEVBQUUsQ0FBQztRQUVwQjs7O1dBR0c7UUFDSSxTQUFJLEdBQUksSUFBSSxDQUFDO1FBRXBCOzs7V0FHRztRQUNJLHVCQUFrQixHQUFJLElBQUksQ0FBQztRQUUzQixZQUFPLEdBQVMsSUFBSSxDQUFDO1FBRTVCOztXQUVHO1FBQ0ksV0FBTSxHQUFJLEVBQUUsQ0FBQztRQUVwQjs7V0FFRztRQUNJLGNBQVMsR0FBSSxFQUFFLENBQUM7UUFFdkI7O1dBRUc7UUFDSSx3QkFBbUIsR0FBSSxJQUFJLENBQUM7UUFFbkM7O1dBRUc7UUFDSSxrQkFBYSxHQUFZLElBQUksQ0FBQztRQUVyQzs7V0FFRztRQUNJLHVCQUFrQixHQUFZLElBQUksQ0FBQztRQUUxQzs7V0FFRztRQUNJLDBCQUFxQixHQUFjLEVBQUUsQ0FBQztRQUU3Qzs7V0FFRztRQUNJLHFCQUFnQixHQUFZLElBQUksQ0FBQztRQUVqQyxpQkFBWSxHQUFJLEVBQUUsQ0FBQztRQUUxQjs7Ozs7V0FLRztRQUNJLHlCQUFvQixHQUFJLEtBQUssQ0FBQztRQUVyQzs7V0FFRztRQUNJLDZCQUF3QixHQUFJLEVBQUUsQ0FBQztRQUUvQiwrQkFBMEIsR0FBSSxFQUFFLENBQUM7UUFFeEM7OztXQUdHO1FBQ0ksNEJBQXVCLEdBQUksS0FBSyxDQUFDO1FBRXhDOzs7O1dBSUc7UUFDSSx3QkFBbUIsR0FBWSxJQUFJLEdBQUcsRUFBRSxDQUFDO1FBRWhEOztXQUVHO1FBQ0kseUJBQW9CLEdBQVksSUFBSSxHQUFHLEVBQUUsQ0FBQztRQUVqRDs7Ozs7OztXQU9HO1FBQ0ksc0JBQWlCLEdBQVksSUFBSSxDQUFDO1FBRXpDOzs7OztXQUtHO1FBQ0ksaUJBQVksR0FBNEIsWUFBWSxDQUFDO1FBRTVEOzs7V0FHRztRQUNJLHNDQUFpQyxHQUFJLElBQUksQ0FBQztRQUVqRDs7OztXQUlHO1FBQ0ksU0FBSSxHQUFZLElBQUksQ0FBQztRQUU1Qjs7O1dBR0c7UUFDSSxzQkFBaUIsR0FBWSxJQUFJLENBQUM7UUFFbEMsNEJBQXVCLEdBQUksMENBQTBDLENBQUM7UUFFN0U7Ozs7V0FJRztRQUNJLGtCQUFhLEdBQUksSUFBSSxDQUFDO1FBRTdCOzs7O1dBSUc7UUFDSSx5QkFBb0IsR0FBSSxLQUFLLENBQUM7UUFFckM7OztXQUdHO1FBQ0ksMEJBQXFCLEdBQUksQ0FBQyxHQUFHLElBQUksQ0FBQztRQUV6Qzs7V0FFRztRQUNJLDBCQUFxQixHQUFZLElBQUksQ0FBQztRQUU3Qzs7V0FFRztRQUNJLDJCQUFzQixHQUFJLHlDQUF5QyxDQUFDO1FBRTNFOzs7Ozs7V0FNRztRQUNJLHVCQUFrQixHQUFJLEtBQUssQ0FBQztRQUVuQzs7O1dBR0c7UUFDSSxxQkFBZ0IsR0FBSSxLQUFLLENBQUM7UUFFMUIsbUNBQThCLEdBQUksS0FBSyxDQUFDO1FBRS9DOzs7V0FHRztRQUNJLG9CQUFlLEdBQUksS0FBSyxDQUFDO1FBU2hDOzs7OztXQUtHO1FBQ0ksd0JBQW1CLEdBQUksR0FBRyxDQUFDO1FBRWxDOztXQUVHO1FBQ0kscUJBQWdCLEdBQUksS0FBSyxDQUFDO1FBT2pDOztXQUVHO1FBQ0ksdUJBQWtCLEdBQUksQ0FBQyxDQUFDO1FBVS9COzs7O1dBSUc7UUFDSSxnQkFBVyxHQUFJLEtBQUssQ0FBQztRQVE1Qjs7OztXQUlHO1FBQ0ksWUFBTyxHQUEyQixHQUFHLENBQUMsRUFBRTtZQUM3QyxRQUFRLENBQUMsSUFBSSxHQUFHLEdBQUcsQ0FBQztRQUN0QixDQUFDLENBQUM7UUFaQSxJQUFJLElBQUksRUFBRTtZQUNSLE1BQU0sQ0FBQyxNQUFNLENBQUMsSUFBSSxFQUFFLElBQUksQ0FBQyxDQUFDO1NBQzNCO0lBQ0gsQ0FBQztDQVVGIiwic291cmNlc0NvbnRlbnQiOlsiZXhwb3J0IGNsYXNzIEF1dGhDb25maWcge1xuICAvKipcbiAgICogVGhlIGNsaWVudCdzIGlkIGFzIHJlZ2lzdGVyZWQgd2l0aCB0aGUgYXV0aCBzZXJ2ZXJcbiAgICovXG4gIHB1YmxpYyBjbGllbnRJZD8gPSAnJztcblxuICAvKipcbiAgICogVGhlIGNsaWVudCdzIHJlZGlyZWN0VXJpIGFzIHJlZ2lzdGVyZWQgd2l0aCB0aGUgYXV0aCBzZXJ2ZXJcbiAgICovXG4gIHB1YmxpYyByZWRpcmVjdFVyaT8gPSAnJztcblxuICAvKipcbiAgICogQW4gb3B0aW9uYWwgc2Vjb25kIHJlZGlyZWN0VXJpIHdoZXJlIHRoZSBhdXRoIHNlcnZlclxuICAgKiByZWRpcmVjdHMgdGhlIHVzZXIgdG8gYWZ0ZXIgbG9nZ2luZyBvdXQuXG4gICAqL1xuICBwdWJsaWMgcG9zdExvZ291dFJlZGlyZWN0VXJpPyA9ICcnO1xuXG4gIC8qKlxuICAgKiBUaGUgYXV0aCBzZXJ2ZXIncyBlbmRwb2ludCB0aGF0IGFsbG93cyB0byBsb2dcbiAgICogdGhlIHVzZXIgaW4gd2hlbiB1c2luZyBpbXBsaWNpdCBmbG93LlxuICAgKi9cbiAgcHVibGljIGxvZ2luVXJsPyA9ICcnO1xuXG4gIC8qKlxuICAgKiBUaGUgcmVxdWVzdGVkIHNjb3Blc1xuICAgKi9cbiAgcHVibGljIHNjb3BlPyA9ICdvcGVuaWQgcHJvZmlsZSc7XG5cbiAgcHVibGljIHJlc291cmNlPyA9ICcnO1xuXG4gIHB1YmxpYyBybmdVcmw/ID0gJyc7XG5cbiAgLyoqXG4gICAqIERlZmluZXMgd2hldGhlciB0byB1c2UgT3BlbklkIENvbm5lY3QgZHVyaW5nXG4gICAqIGltcGxpY2l0IGZsb3cuXG4gICAqL1xuICBwdWJsaWMgb2lkYz8gPSB0cnVlO1xuXG4gIC8qKlxuICAgKiBEZWZpbmVzIHdoZXRoZXIgdG8gcmVxdWVzdCBhbiBhY2Nlc3MgdG9rZW4gZHVyaW5nXG4gICAqIGltcGxpY2l0IGZsb3cuXG4gICAqL1xuICBwdWJsaWMgcmVxdWVzdEFjY2Vzc1Rva2VuPyA9IHRydWU7XG5cbiAgcHVibGljIG9wdGlvbnM/OiBhbnkgPSBudWxsO1xuXG4gIC8qKlxuICAgKiBUaGUgaXNzdWVyJ3MgdXJpLlxuICAgKi9cbiAgcHVibGljIGlzc3Vlcj8gPSAnJztcblxuICAvKipcbiAgICogVGhlIGxvZ291dCB1cmwuXG4gICAqL1xuICBwdWJsaWMgbG9nb3V0VXJsPyA9ICcnO1xuXG4gIC8qKlxuICAgKiBEZWZpbmVzIHdoZXRoZXIgdG8gY2xlYXIgdGhlIGhhc2ggZnJhZ21lbnQgYWZ0ZXIgbG9nZ2luZyBpbi5cbiAgICovXG4gIHB1YmxpYyBjbGVhckhhc2hBZnRlckxvZ2luPyA9IHRydWU7XG5cbiAgLyoqXG4gICAqIFVybCBvZiB0aGUgdG9rZW4gZW5kcG9pbnQgYXMgZGVmaW5lZCBieSBPcGVuSWQgQ29ubmVjdCBhbmQgT0F1dGggMi5cbiAgICovXG4gIHB1YmxpYyB0b2tlbkVuZHBvaW50Pzogc3RyaW5nID0gbnVsbDtcblxuICAvKipcbiAgICogVXJsIG9mIHRoZSByZXZvY2F0aW9uIGVuZHBvaW50IGFzIGRlZmluZWQgYnkgT3BlbklkIENvbm5lY3QgYW5kIE9BdXRoIDIuXG4gICAqL1xuICBwdWJsaWMgcmV2b2NhdGlvbkVuZHBvaW50Pzogc3RyaW5nID0gbnVsbDtcblxuICAvKipcbiAgICogTmFtZXMgb2Yga25vd24gcGFyYW1ldGVycyBzZW50IG91dCBpbiB0aGUgVG9rZW5SZXNwb25zZS4gaHR0cHM6Ly90b29scy5pZXRmLm9yZy9odG1sL3JmYzY3NDkjc2VjdGlvbi01LjFcbiAgICovXG4gIHB1YmxpYyBjdXN0b21Ub2tlblBhcmFtZXRlcnM/OiBzdHJpbmdbXSA9IFtdO1xuXG4gIC8qKlxuICAgKiBVcmwgb2YgdGhlIHVzZXJpbmZvIGVuZHBvaW50IGFzIGRlZmluZWQgYnkgT3BlbklkIENvbm5lY3QuXG4gICAqL1xuICBwdWJsaWMgdXNlcmluZm9FbmRwb2ludD86IHN0cmluZyA9IG51bGw7XG5cbiAgcHVibGljIHJlc3BvbnNlVHlwZT8gPSAnJztcblxuICAvKipcbiAgICogRGVmaW5lcyB3aGV0aGVyIGFkZGl0aW9uYWwgZGVidWcgaW5mb3JtYXRpb24gc2hvdWxkXG4gICAqIGJlIHNob3duIGF0IHRoZSBjb25zb2xlLiBOb3RlIHRoYXQgaW4gY2VydGFpbiBicm93c2Vyc1xuICAgKiB0aGUgdmVyYm9zaXR5IG9mIHRoZSBjb25zb2xlIG5lZWRzIHRvIGJlIGV4cGxpY2l0bHkgc2V0XG4gICAqIHRvIGluY2x1ZGUgRGVidWcgbGV2ZWwgbWVzc2FnZXMuXG4gICAqL1xuICBwdWJsaWMgc2hvd0RlYnVnSW5mb3JtYXRpb24/ID0gZmFsc2U7XG5cbiAgLyoqXG4gICAqIFRoZSByZWRpcmVjdCB1cmkgdXNlZCB3aGVuIGRvaW5nIHNpbGVudCByZWZyZXNoLlxuICAgKi9cbiAgcHVibGljIHNpbGVudFJlZnJlc2hSZWRpcmVjdFVyaT8gPSAnJztcblxuICBwdWJsaWMgc2lsZW50UmVmcmVzaE1lc3NhZ2VQcmVmaXg/ID0gJyc7XG5cbiAgLyoqXG4gICAqIFNldCB0aGlzIHRvIHRydWUgdG8gZGlzcGxheSB0aGUgaWZyYW1lIHVzZWQgZm9yXG4gICAqIHNpbGVudCByZWZyZXNoIGZvciBkZWJ1Z2dpbmcuXG4gICAqL1xuICBwdWJsaWMgc2lsZW50UmVmcmVzaFNob3dJRnJhbWU/ID0gZmFsc2U7XG5cbiAgLyoqXG4gICAqIFRpbWVvdXQgZm9yIHNpbGVudCByZWZyZXNoLlxuICAgKiBAaW50ZXJuYWxcbiAgICogZGVwcmVhY3RlZCBiL2Mgb2YgdHlwbywgc2VlIHNpbGVudFJlZnJlc2hUaW1lb3V0XG4gICAqL1xuICBwdWJsaWMgc2lsZXRSZWZyZXNoVGltZW91dD86IG51bWJlciA9IDEwMDAgKiAyMDtcblxuICAvKipcbiAgICogVGltZW91dCBmb3Igc2lsZW50IHJlZnJlc2guXG4gICAqL1xuICBwdWJsaWMgc2lsZW50UmVmcmVzaFRpbWVvdXQ/OiBudW1iZXIgPSAxMDAwICogMjA7XG5cbiAgLyoqXG4gICAqIFNvbWUgYXV0aCBzZXJ2ZXJzIGRvbid0IGFsbG93IHVzaW5nIHBhc3N3b3JkIGZsb3dcbiAgICogdy9vIGEgY2xpZW50IHNlY3JldCB3aGlsZSB0aGUgc3RhbmRhcmRzIGRvIG5vdFxuICAgKiBkZW1hbmQgZm9yIGl0LiBJbiB0aGlzIGNhc2UsIHlvdSBjYW4gc2V0IGEgcGFzc3dvcmRcbiAgICogaGVyZS4gQXMgdGhpcyBwYXNzd29yZCBpcyBleHBvc2VkIHRvIHRoZSBwdWJsaWNcbiAgICogaXQgZG9lcyBub3QgYnJpbmcgYWRkaXRpb25hbCBzZWN1cml0eSBhbmQgaXMgdGhlcmVmb3JlXG4gICAqIGFzIGdvb2QgYXMgdXNpbmcgbm8gcGFzc3dvcmQuXG4gICAqL1xuICBwdWJsaWMgZHVtbXlDbGllbnRTZWNyZXQ/OiBzdHJpbmcgPSBudWxsO1xuXG4gIC8qKlxuICAgKiBEZWZpbmVzIHdoZXRoZXIgaHR0cHMgaXMgcmVxdWlyZWQuXG4gICAqIFRoZSBkZWZhdWx0IHZhbHVlIGlzIHJlbW90ZU9ubHkgd2hpY2ggb25seSBhbGxvd3NcbiAgICogaHR0cCBmb3IgbG9jYWxob3N0LCB3aGlsZSBldmVyeSBvdGhlciBkb21haW5zIG5lZWRcbiAgICogdG8gYmUgdXNlZCB3aXRoIGh0dHBzLlxuICAgKi9cbiAgcHVibGljIHJlcXVpcmVIdHRwcz86IGJvb2xlYW4gfCAncmVtb3RlT25seScgPSAncmVtb3RlT25seSc7XG5cbiAgLyoqXG4gICAqIERlZmluZXMgd2hldGhlciBldmVyeSB1cmwgcHJvdmlkZWQgYnkgdGhlIGRpc2NvdmVyeVxuICAgKiBkb2N1bWVudCBoYXMgdG8gc3RhcnQgd2l0aCB0aGUgaXNzdWVyJ3MgdXJsLlxuICAgKi9cbiAgcHVibGljIHN0cmljdERpc2NvdmVyeURvY3VtZW50VmFsaWRhdGlvbj8gPSB0cnVlO1xuXG4gIC8qKlxuICAgKiBKU09OIFdlYiBLZXkgU2V0IChodHRwczovL3Rvb2xzLmlldGYub3JnL2h0bWwvcmZjNzUxNylcbiAgICogd2l0aCBrZXlzIHVzZWQgdG8gdmFsaWRhdGUgcmVjZWl2ZWQgaWRfdG9rZW5zLlxuICAgKiBUaGlzIGlzIHRha2VuIG91dCBvZiB0aGUgZGlzb3ZlcnkgZG9jdW1lbnQuIENhbiBiZSBzZXQgbWFudWFsbHkgdG9vLlxuICAgKi9cbiAgcHVibGljIGp3a3M/OiBvYmplY3QgPSBudWxsO1xuXG4gIC8qKlxuICAgKiBNYXAgd2l0aCBhZGRpdGlvbmFsIHF1ZXJ5IHBhcmFtZXRlciB0aGF0IGFyZSBhcHBlbmRlZCB0b1xuICAgKiB0aGUgcmVxdWVzdCB3aGVuIGluaXRpYWxpemluZyBpbXBsaWNpdCBmbG93LlxuICAgKi9cbiAgcHVibGljIGN1c3RvbVF1ZXJ5UGFyYW1zPzogb2JqZWN0ID0gbnVsbDtcblxuICBwdWJsaWMgc2lsZW50UmVmcmVzaElGcmFtZU5hbWU/ID0gJ2FuZ3VsYXItb2F1dGgtb2lkYy1zaWxlbnQtcmVmcmVzaC1pZnJhbWUnO1xuXG4gIC8qKlxuICAgKiBEZWZpbmVzIHdoZW4gdGhlIHRva2VuX3RpbWVvdXQgZXZlbnQgc2hvdWxkIGJlIHJhaXNlZC5cbiAgICogSWYgeW91IHNldCB0aGlzIHRvIHRoZSBkZWZhdWx0IHZhbHVlIDAuNzUsIHRoZSBldmVudFxuICAgKiBpcyB0cmlnZ2VyZWQgYWZ0ZXIgNzUlIG9mIHRoZSB0b2tlbidzIGxpZmUgdGltZS5cbiAgICovXG4gIHB1YmxpYyB0aW1lb3V0RmFjdG9yPyA9IDAuNzU7XG5cbiAgLyoqXG4gICAqIElmIHRydWUsIHRoZSBsaWIgd2lsbCB0cnkgdG8gY2hlY2sgd2hldGhlciB0aGUgdXNlclxuICAgKiBpcyBzdGlsbCBsb2dnZWQgaW4gb24gYSByZWd1bGFyIGJhc2lzIGFzIGRlc2NyaWJlZFxuICAgKiBpbiBodHRwOi8vb3BlbmlkLm5ldC9zcGVjcy9vcGVuaWQtY29ubmVjdC1zZXNzaW9uLTFfMC5odG1sI0NoYW5nZU5vdGlmaWNhdGlvblxuICAgKi9cbiAgcHVibGljIHNlc3Npb25DaGVja3NFbmFibGVkPyA9IGZhbHNlO1xuXG4gIC8qKlxuICAgKiBJbnRlcnZhbCBpbiBtc2VjIGZvciBjaGVja2luZyB0aGUgc2Vzc2lvblxuICAgKiBhY2NvcmRpbmcgdG8gaHR0cDovL29wZW5pZC5uZXQvc3BlY3Mvb3BlbmlkLWNvbm5lY3Qtc2Vzc2lvbi0xXzAuaHRtbCNDaGFuZ2VOb3RpZmljYXRpb25cbiAgICovXG4gIHB1YmxpYyBzZXNzaW9uQ2hlY2tJbnRlcnZhbGw/ID0gMyAqIDEwMDA7XG5cbiAgLyoqXG4gICAqIFVybCBmb3IgdGhlIGlmcmFtZSB1c2VkIGZvciBzZXNzaW9uIGNoZWNrc1xuICAgKi9cbiAgcHVibGljIHNlc3Npb25DaGVja0lGcmFtZVVybD86IHN0cmluZyA9IG51bGw7XG5cbiAgLyoqXG4gICAqIE5hbWUgb2YgdGhlIGlmcmFtZSB0byB1c2UgZm9yIHNlc3Npb24gY2hlY2tzXG4gICAqL1xuICBwdWJsaWMgc2Vzc2lvbkNoZWNrSUZyYW1lTmFtZT8gPSAnYW5ndWxhci1vYXV0aC1vaWRjLWNoZWNrLXNlc3Npb24taWZyYW1lJztcblxuICAvKipcbiAgICogVGhpcyBwcm9wZXJ0eSBoYXMgYmVlbiBpbnRyb2R1Y2VkIHRvIGRpc2FibGUgYXRfaGFzaCBjaGVja3NcbiAgICogYW5kIGlzIGluZGVudGVkIGZvciBJZGVudGl0eSBQcm92aWRlciB0aGF0IGRvZXMgbm90IGRlbGl2ZXJcbiAgICogYW4gYXRfaGFzaCBFVkVOIFRIT1VHSCBpdHMgcmVjb21tZW5kZWQgYnkgdGhlIE9JREMgc3BlY3MuXG4gICAqIE9mIGNvdXJzZSwgd2hlbiBkaXNhYmxpbmcgdGhlc2UgY2hlY2tzIHRoZSB3ZSBhcmUgYnlwYXNzaW5nXG4gICAqIGEgc2VjdXJpdHkgY2hlY2sgd2hpY2ggbWVhbnMgd2UgYXJlIG1vcmUgdnVsbmVyYWJsZS5cbiAgICovXG4gIHB1YmxpYyBkaXNhYmxlQXRIYXNoQ2hlY2s/ID0gZmFsc2U7XG5cbiAgLyoqXG4gICAqIERlZmluZXMgd2V0aGVyIHRvIGNoZWNrIHRoZSBzdWJqZWN0IG9mIGEgcmVmcmVzaGVkIHRva2VuIGFmdGVyIHNpbGVudCByZWZyZXNoLlxuICAgKiBOb3JtYWxseSwgaXQgc2hvdWxkIGJlIHRoZSBzYW1lIGFzIGJlZm9yZS5cbiAgICovXG4gIHB1YmxpYyBza2lwU3ViamVjdENoZWNrPyA9IGZhbHNlO1xuXG4gIHB1YmxpYyB1c2VJZFRva2VuSGludEZvclNpbGVudFJlZnJlc2g/ID0gZmFsc2U7XG5cbiAgLyoqXG4gICAqIERlZmluZWQgd2hldGhlciB0byBza2lwIHRoZSB2YWxpZGF0aW9uIG9mIHRoZSBpc3N1ZXIgaW4gdGhlIGRpc2NvdmVyeSBkb2N1bWVudC5cbiAgICogTm9ybWFsbHksIHRoZSBkaXNjb3ZleSBkb2N1bWVudCdzIHVybCBzdGFydHMgd2l0aCB0aGUgdXJsIG9mIHRoZSBpc3N1ZXIuXG4gICAqL1xuICBwdWJsaWMgc2tpcElzc3VlckNoZWNrPyA9IGZhbHNlO1xuXG4gIC8qKlxuICAgKiBBY2NvcmRpbmcgdG8gcmZjNjc0OSBpdCBpcyByZWNvbW1lbmRlZCAoYnV0IG5vdCByZXF1aXJlZCkgdGhhdCB0aGUgYXV0aFxuICAgKiBzZXJ2ZXIgZXhwb3NlcyB0aGUgYWNjZXNzX3Rva2VuJ3MgbGlmZSB0aW1lIGluIHNlY29uZHMuXG4gICAqIFRoaXMgaXMgYSBmYWxsYmFjayB2YWx1ZSBmb3IgdGhlIGNhc2UgdGhpcyB2YWx1ZSBpcyBub3QgZXhwb3NlZC5cbiAgICovXG4gIHB1YmxpYyBmYWxsYmFja0FjY2Vzc1Rva2VuRXhwaXJhdGlvblRpbWVJblNlYz86IG51bWJlcjtcblxuICAvKipcbiAgICogZmluYWwgc3RhdGUgc2VudCB0byBpc3N1ZXIgaXMgYnVpbHQgYXMgZm9sbG93czpcbiAgICogc3RhdGUgPSBub25jZSArIG5vbmNlU3RhdGVTZXBhcmF0b3IgKyBhZGRpdGlvbmFsIHN0YXRlXG4gICAqIERlZmF1bHQgc2VwYXJhdG9yIGlzICc7JyAoZW5jb2RlZCAlM0IpLlxuICAgKiBJbiByYXJlIGNhc2VzLCB0aGlzIGNoYXJhY3RlciBtaWdodCBiZSBmb3JiaWRkZW4gb3IgaW5jb252ZW5pZW50IHRvIHVzZSBieSB0aGUgaXNzdWVyIHNvIGl0IGNhbiBiZSBjdXN0b21pemVkLlxuICAgKi9cbiAgcHVibGljIG5vbmNlU3RhdGVTZXBhcmF0b3I/ID0gJzsnO1xuXG4gIC8qKlxuICAgKiBTZXQgdGhpcyB0byB0cnVlIHRvIHVzZSBIVFRQIEJBU0lDIGF1dGggZm9yIEFKQVggY2FsbHNcbiAgICovXG4gIHB1YmxpYyB1c2VIdHRwQmFzaWNBdXRoPyA9IGZhbHNlO1xuXG4gIC8qKlxuICAgKiBUaGUgd2luZG93IG9mIHRpbWUgKGluIHNlY29uZHMpIHRvIGFsbG93IHRoZSBjdXJyZW50IHRpbWUgdG8gZGV2aWF0ZSB3aGVuIHZhbGlkYXRpbmcgaWRfdG9rZW4ncyBpYXQgYW5kIGV4cCB2YWx1ZXMuXG4gICAqL1xuICBwdWJsaWMgY2xvY2tTa2V3SW5TZWM/OiBudW1iZXI7XG5cbiAgLyoqXG4gICAqIFRoZSBpbnRlcmNlcHRvcnMgd2FpdHMgdGhpcyB0aW1lIHNwYW4gaWYgdGhlcmUgaXMgbm8gdG9rZW5cbiAgICovXG4gIHB1YmxpYyB3YWl0Rm9yVG9rZW5Jbk1zZWM/ID0gMDtcblxuICAvKipcbiAgICogU2V0IHRoaXMgdG8gdHJ1ZSBpZiB5b3Ugd2FudCB0byB1c2Ugc2lsZW50IHJlZnJlc2ggdG9nZXRoZXIgd2l0aFxuICAgKiBjb2RlIGZsb3cuIEFzIHNpbGVudCByZWZyZXNoIGlzIHRoZSBvbmx5IG9wdGlvbiBmb3IgcmVmcmVzaGluZ1xuICAgKiB3aXRoIGltcGxpY2l0IGZsb3csIHlvdSBkb24ndCBuZWVkIHRvIGV4cGxpY2l0bHkgdHVybiBpdCBvbiBpblxuICAgKiB0aGlzIGNhc2UuXG4gICAqL1xuICBwdWJsaWMgdXNlU2lsZW50UmVmcmVzaD87XG5cbiAgLyoqXG4gICAqIENvZGUgRmxvdyBpcyBieSBkZWZhdWxkIHVzZWQgdG9nZXRoZXIgd2l0aCBQS0NJIHdoaWNoIGlzIGFsc28gaGlnbHkgcmVjb21tZW50ZWQuXG4gICAqIFlvdSBjYW4gZGlzYmFsZSBpdCBoZXJlIGJ5IHNldHRpbmcgdGhpcyBmbGFnIHRvIHRydWUuXG4gICAqIGh0dHBzOi8vdG9vbHMuaWV0Zi5vcmcvaHRtbC9yZmM3NjM2I3NlY3Rpb24tMS4xXG4gICAqL1xuICBwdWJsaWMgZGlzYWJsZVBLQ0U/ID0gZmFsc2U7XG5cbiAgY29uc3RydWN0b3IoanNvbj86IFBhcnRpYWw8QXV0aENvbmZpZz4pIHtcbiAgICBpZiAoanNvbikge1xuICAgICAgT2JqZWN0LmFzc2lnbih0aGlzLCBqc29uKTtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgICogVGhpcyBwcm9wZXJ0eSBhbGxvd3MgeW91IHRvIG92ZXJyaWRlIHRoZSBtZXRob2QgdGhhdCBpcyB1c2VkIHRvIG9wZW4gdGhlIGxvZ2luIHVybCxcbiAgICogYWxsb3dpbmcgYSB3YXkgZm9yIGltcGxlbWVudGF0aW9ucyB0byBzcGVjaWZ5IHRoZWlyIG93biBtZXRob2Qgb2Ygcm91dGluZyB0byBuZXdcbiAgICogdXJscy5cbiAgICovXG4gIHB1YmxpYyBvcGVuVXJpPzogKHVyaTogc3RyaW5nKSA9PiB2b2lkID0gdXJpID0+IHtcbiAgICBsb2NhdGlvbi5ocmVmID0gdXJpO1xuICB9O1xufVxuIl19
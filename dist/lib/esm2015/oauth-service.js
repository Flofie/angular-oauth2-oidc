import { __awaiter } from "tslib";
import { Injectable, NgZone, Optional, Inject } from '@angular/core';
import { HttpClient, HttpHeaders, HttpParams } from '@angular/common/http';
import { Subject, of, race, from, combineLatest, throwError } from 'rxjs';
import { filter, delay, first, tap, map, switchMap, debounceTime, catchError } from 'rxjs/operators';
import { DOCUMENT } from '@angular/common';
import { ValidationHandler } from './token-validation/validation-handler';
import { UrlHelperService } from './url-helper.service';
import { OAuthInfoEvent, OAuthErrorEvent, OAuthSuccessEvent } from './events';
import { OAuthLogger, OAuthStorage } from './types';
import { b64DecodeUnicode, base64UrlEncode } from './base64-helper';
import { AuthConfig } from './auth.config';
import { WebHttpUrlEncodingCodec } from './encoder';
import { HashHandler } from './token-validation/hash-handler';
/**
 * Service for logging in and logging out with
 * OIDC and OAuth2. Supports implicit flow and
 * password flow.
 */
export class OAuthService extends AuthConfig {
    constructor(ngZone, http, storage, tokenValidationHandler, config, urlHelper, logger, crypto, document) {
        var _a;
        super();
        this.ngZone = ngZone;
        this.http = http;
        this.config = config;
        this.urlHelper = urlHelper;
        this.logger = logger;
        this.crypto = crypto;
        /**
         * @internal
         * Deprecated:  use property events instead
         */
        this.discoveryDocumentLoaded = false;
        /**
         * The received (passed around) state, when logging
         * in with implicit flow.
         */
        this.state = '';
        this.eventsSubject = new Subject();
        this.discoveryDocumentLoadedSubject = new Subject();
        this.grantTypesSupported = [];
        this.inImplicitFlow = false;
        this.saveNoncesInLocalStorage = false;
        this.debug('angular-oauth2-oidc v8-beta');
        // See https://github.com/manfredsteyer/angular-oauth2-oidc/issues/773 for why this is needed
        this.document = document;
        this.discoveryDocumentLoaded$ = this.discoveryDocumentLoadedSubject.asObservable();
        this.events = this.eventsSubject.asObservable();
        if (tokenValidationHandler) {
            this.tokenValidationHandler = tokenValidationHandler;
        }
        if (config) {
            this.configure(config);
        }
        try {
            if (storage) {
                this.setStorage(storage);
            }
            else if (typeof sessionStorage !== 'undefined') {
                this.setStorage(sessionStorage);
            }
        }
        catch (e) {
            console.error('No OAuthStorage provided and cannot access default (sessionStorage).' +
                'Consider providing a custom OAuthStorage implementation in your module.', e);
        }
        // in IE, sessionStorage does not always survive a redirect
        if (typeof window !== 'undefined' &&
            typeof window['localStorage'] !== 'undefined') {
            const ua = (_a = window === null || window === void 0 ? void 0 : window.navigator) === null || _a === void 0 ? void 0 : _a.userAgent;
            const msie = (ua === null || ua === void 0 ? void 0 : ua.includes('MSIE ')) || (ua === null || ua === void 0 ? void 0 : ua.includes('Trident'));
            if (msie) {
                this.saveNoncesInLocalStorage = true;
            }
        }
        this.setupRefreshTimer();
    }
    /**
     * Use this method to configure the service
     * @param config the configuration
     */
    configure(config) {
        // For the sake of downward compatibility with
        // original configuration API
        Object.assign(this, new AuthConfig(), config);
        this.config = Object.assign({}, new AuthConfig(), config);
        if (this.sessionChecksEnabled) {
            this.setupSessionCheck();
        }
        this.configChanged();
    }
    configChanged() {
        this.setupRefreshTimer();
    }
    restartSessionChecksIfStillLoggedIn() {
        if (this.hasValidIdToken()) {
            this.initSessionCheck();
        }
    }
    restartRefreshTimerIfStillLoggedIn() {
        this.setupExpirationTimers();
    }
    setupSessionCheck() {
        this.events.pipe(filter(e => e.type === 'token_received')).subscribe(e => {
            this.initSessionCheck();
        });
    }
    /**
     * Will setup up silent refreshing for when the token is
     * about to expire. When the user is logged out via this.logOut method, the
     * silent refreshing will pause and not refresh the tokens until the user is
     * logged back in via receiving a new token.
     * @param params Additional parameter to pass
     * @param listenTo Setup automatic refresh of a specific token type
     */
    setupAutomaticSilentRefresh(params = {}, listenTo, noPrompt = true) {
        let shouldRunSilentRefresh = true;
        this.events
            .pipe(tap(e => {
            if (e.type === 'token_received') {
                shouldRunSilentRefresh = true;
            }
            else if (e.type === 'logout') {
                shouldRunSilentRefresh = false;
            }
        }), filter(e => e.type === 'token_expires'), debounceTime(1000))
            .subscribe(e => {
            const event = e;
            if ((listenTo == null || listenTo === 'any' || event.info === listenTo) &&
                shouldRunSilentRefresh) {
                // this.silentRefresh(params, noPrompt).catch(_ => {
                this.refreshInternal(params, noPrompt).catch(_ => {
                    this.debug('Automatic silent refresh did not work');
                });
            }
        });
        this.restartRefreshTimerIfStillLoggedIn();
    }
    refreshInternal(params, noPrompt) {
        if (!this.useSilentRefresh && this.responseType === 'code') {
            return this.refreshToken();
        }
        else {
            return this.silentRefresh(params, noPrompt);
        }
    }
    /**
     * Convenience method that first calls `loadDiscoveryDocument(...)` and
     * directly chains using the `then(...)` part of the promise to call
     * the `tryLogin(...)` method.
     *
     * @param options LoginOptions to pass through to `tryLogin(...)`
     */
    loadDiscoveryDocumentAndTryLogin(options = null) {
        return this.loadDiscoveryDocument().then(doc => {
            return this.tryLogin(options);
        });
    }
    /**
     * Convenience method that first calls `loadDiscoveryDocumentAndTryLogin(...)`
     * and if then chains to `initLoginFlow()`, but only if there is no valid
     * IdToken or no valid AccessToken.
     *
     * @param options LoginOptions to pass through to `tryLogin(...)`
     */
    loadDiscoveryDocumentAndLogin(options = null) {
        options = options || {};
        return this.loadDiscoveryDocumentAndTryLogin(options).then(_ => {
            if (!this.hasValidIdToken() || !this.hasValidAccessToken()) {
                const state = typeof options.state === 'string' ? options.state : '';
                this.initLoginFlow(state);
                return false;
            }
            else {
                return true;
            }
        });
    }
    debug(...args) {
        if (this.showDebugInformation) {
            this.logger.debug.apply(this.logger, args);
        }
    }
    validateUrlFromDiscoveryDocument(url) {
        const errors = [];
        const httpsCheck = this.validateUrlForHttps(url);
        const issuerCheck = this.validateUrlAgainstIssuer(url);
        if (!httpsCheck) {
            errors.push('https for all urls required. Also for urls received by discovery.');
        }
        if (!issuerCheck) {
            errors.push('Every url in discovery document has to start with the issuer url.' +
                'Also see property strictDiscoveryDocumentValidation.');
        }
        return errors;
    }
    validateUrlForHttps(url) {
        if (!url) {
            return true;
        }
        const lcUrl = url.toLowerCase();
        if (this.requireHttps === false) {
            return true;
        }
        if ((lcUrl.match(/^http:\/\/localhost($|[:\/])/) ||
            lcUrl.match(/^http:\/\/localhost($|[:\/])/)) &&
            this.requireHttps === 'remoteOnly') {
            return true;
        }
        return lcUrl.startsWith('https://');
    }
    assertUrlNotNullAndCorrectProtocol(url, description) {
        if (!url) {
            throw new Error(`'${description}' should not be null`);
        }
        if (!this.validateUrlForHttps(url)) {
            throw new Error(`'${description}' must use HTTPS (with TLS), or config value for property 'requireHttps' must be set to 'false' and allow HTTP (without TLS).`);
        }
    }
    validateUrlAgainstIssuer(url) {
        if (!this.strictDiscoveryDocumentValidation) {
            return true;
        }
        if (!url) {
            return true;
        }
        return url.toLowerCase().startsWith(this.issuer.toLowerCase());
    }
    setupRefreshTimer() {
        if (typeof window === 'undefined') {
            this.debug('timer not supported on this plattform');
            return;
        }
        if (this.hasValidIdToken() || this.hasValidAccessToken()) {
            this.clearAccessTokenTimer();
            this.clearIdTokenTimer();
            this.setupExpirationTimers();
        }
        if (this.tokenReceivedSubscription)
            this.tokenReceivedSubscription.unsubscribe();
        this.tokenReceivedSubscription = this.events
            .pipe(filter(e => e.type === 'token_received'))
            .subscribe(_ => {
            this.clearAccessTokenTimer();
            this.clearIdTokenTimer();
            this.setupExpirationTimers();
        });
    }
    setupExpirationTimers() {
        if (this.hasValidAccessToken()) {
            this.setupAccessTokenTimer();
        }
        if (this.hasValidIdToken()) {
            this.setupIdTokenTimer();
        }
    }
    setupAccessTokenTimer() {
        const expiration = this.getAccessTokenExpiration();
        const storedAt = this.getAccessTokenStoredAt();
        const timeout = this.calcTimeout(storedAt, expiration);
        this.ngZone.runOutsideAngular(() => {
            this.accessTokenTimeoutSubscription = of(new OAuthInfoEvent('token_expires', 'access_token'))
                .pipe(delay(timeout))
                .subscribe(e => {
                this.ngZone.run(() => {
                    this.eventsSubject.next(e);
                });
            });
        });
    }
    setupIdTokenTimer() {
        const expiration = this.getIdTokenExpiration();
        const storedAt = this.getIdTokenStoredAt();
        const timeout = this.calcTimeout(storedAt, expiration);
        this.ngZone.runOutsideAngular(() => {
            this.idTokenTimeoutSubscription = of(new OAuthInfoEvent('token_expires', 'id_token'))
                .pipe(delay(timeout))
                .subscribe(e => {
                this.ngZone.run(() => {
                    this.eventsSubject.next(e);
                });
            });
        });
    }
    /**
     * Stops timers for automatic refresh.
     * To restart it, call setupAutomaticSilentRefresh again.
     */
    stopAutomaticRefresh() {
        this.clearAccessTokenTimer();
        this.clearIdTokenTimer();
    }
    clearAccessTokenTimer() {
        if (this.accessTokenTimeoutSubscription) {
            this.accessTokenTimeoutSubscription.unsubscribe();
        }
    }
    clearIdTokenTimer() {
        if (this.idTokenTimeoutSubscription) {
            this.idTokenTimeoutSubscription.unsubscribe();
        }
    }
    calcTimeout(storedAt, expiration) {
        const now = Date.now();
        const delta = (expiration - storedAt) * this.timeoutFactor - (now - storedAt);
        return Math.max(0, delta);
    }
    /**
     * DEPRECATED. Use a provider for OAuthStorage instead:
     *
     * { provide: OAuthStorage, useFactory: oAuthStorageFactory }
     * export function oAuthStorageFactory(): OAuthStorage { return localStorage; }
     * Sets a custom storage used to store the received
     * tokens on client side. By default, the browser's
     * sessionStorage is used.
     * @ignore
     *
     * @param storage
     */
    setStorage(storage) {
        this._storage = storage;
        this.configChanged();
    }
    /**
     * Loads the discovery document to configure most
     * properties of this service. The url of the discovery
     * document is infered from the issuer's url according
     * to the OpenId Connect spec. To use another url you
     * can pass it to to optional parameter fullUrl.
     *
     * @param fullUrl
     */
    loadDiscoveryDocument(fullUrl = null) {
        return new Promise((resolve, reject) => {
            if (!fullUrl) {
                fullUrl = this.issuer || '';
                if (!fullUrl.endsWith('/')) {
                    fullUrl += '/';
                }
                fullUrl += '.well-known/openid-configuration';
            }
            if (!this.validateUrlForHttps(fullUrl)) {
                reject("issuer  must use HTTPS (with TLS), or config value for property 'requireHttps' must be set to 'false' and allow HTTP (without TLS).");
                return;
            }
            this.http.get(fullUrl).subscribe(doc => {
                if (!this.validateDiscoveryDocument(doc)) {
                    this.eventsSubject.next(new OAuthErrorEvent('discovery_document_validation_error', null));
                    reject('discovery_document_validation_error');
                    return;
                }
                this.loginUrl = doc.authorization_endpoint;
                this.logoutUrl = doc.end_session_endpoint || this.logoutUrl;
                this.grantTypesSupported = doc.grant_types_supported;
                this.issuer = doc.issuer;
                this.tokenEndpoint = doc.token_endpoint;
                this.userinfoEndpoint =
                    doc.userinfo_endpoint || this.userinfoEndpoint;
                this.jwksUri = doc.jwks_uri;
                this.sessionCheckIFrameUrl =
                    doc.check_session_iframe || this.sessionCheckIFrameUrl;
                this.discoveryDocumentLoaded = true;
                this.discoveryDocumentLoadedSubject.next(doc);
                this.revocationEndpoint = doc.revocation_endpoint;
                if (this.sessionChecksEnabled) {
                    this.restartSessionChecksIfStillLoggedIn();
                }
                this.loadJwks()
                    .then(jwks => {
                    const result = {
                        discoveryDocument: doc,
                        jwks: jwks
                    };
                    const event = new OAuthSuccessEvent('discovery_document_loaded', result);
                    this.eventsSubject.next(event);
                    resolve(event);
                    return;
                })
                    .catch(err => {
                    this.eventsSubject.next(new OAuthErrorEvent('discovery_document_load_error', err));
                    reject(err);
                    return;
                });
            }, err => {
                this.logger.error('error loading discovery document', err);
                this.eventsSubject.next(new OAuthErrorEvent('discovery_document_load_error', err));
                reject(err);
            });
        });
    }
    loadJwks() {
        return new Promise((resolve, reject) => {
            if (this.jwksUri) {
                this.http.get(this.jwksUri).subscribe(jwks => {
                    this.jwks = jwks;
                    this.eventsSubject.next(new OAuthSuccessEvent('discovery_document_loaded'));
                    resolve(jwks);
                }, err => {
                    this.logger.error('error loading jwks', err);
                    this.eventsSubject.next(new OAuthErrorEvent('jwks_load_error', err));
                    reject(err);
                });
            }
            else {
                resolve(null);
            }
        });
    }
    validateDiscoveryDocument(doc) {
        let errors;
        if (!this.skipIssuerCheck && doc.issuer !== this.issuer) {
            this.logger.error('invalid issuer in discovery document', 'expected: ' + this.issuer, 'current: ' + doc.issuer);
            return false;
        }
        errors = this.validateUrlFromDiscoveryDocument(doc.authorization_endpoint);
        if (errors.length > 0) {
            this.logger.error('error validating authorization_endpoint in discovery document', errors);
            return false;
        }
        errors = this.validateUrlFromDiscoveryDocument(doc.end_session_endpoint);
        if (errors.length > 0) {
            this.logger.error('error validating end_session_endpoint in discovery document', errors);
            return false;
        }
        errors = this.validateUrlFromDiscoveryDocument(doc.token_endpoint);
        if (errors.length > 0) {
            this.logger.error('error validating token_endpoint in discovery document', errors);
        }
        errors = this.validateUrlFromDiscoveryDocument(doc.revocation_endpoint);
        if (errors.length > 0) {
            this.logger.error('error validating revocation_endpoint in discovery document', errors);
        }
        errors = this.validateUrlFromDiscoveryDocument(doc.userinfo_endpoint);
        if (errors.length > 0) {
            this.logger.error('error validating userinfo_endpoint in discovery document', errors);
            return false;
        }
        errors = this.validateUrlFromDiscoveryDocument(doc.jwks_uri);
        if (errors.length > 0) {
            this.logger.error('error validating jwks_uri in discovery document', errors);
            return false;
        }
        if (this.sessionChecksEnabled && !doc.check_session_iframe) {
            this.logger.warn('sessionChecksEnabled is activated but discovery document' +
                ' does not contain a check_session_iframe field');
        }
        return true;
    }
    /**
     * Uses password flow to exchange userName and password for an
     * access_token. After receiving the access_token, this method
     * uses it to query the userinfo endpoint in order to get information
     * about the user in question.
     *
     * When using this, make sure that the property oidc is set to false.
     * Otherwise stricter validations take place that make this operation
     * fail.
     *
     * @param userName
     * @param password
     * @param headers Optional additional http-headers.
     */
    fetchTokenUsingPasswordFlowAndLoadUserProfile(userName, password, headers = new HttpHeaders()) {
        return this.fetchTokenUsingPasswordFlow(userName, password, headers).then(() => this.loadUserProfile());
    }
    /**
     * Loads the user profile by accessing the user info endpoint defined by OpenId Connect.
     *
     * When using this with OAuth2 password flow, make sure that the property oidc is set to false.
     * Otherwise stricter validations take place that make this operation fail.
     */
    loadUserProfile() {
        if (!this.hasValidAccessToken()) {
            throw new Error('Can not load User Profile without access_token');
        }
        if (!this.validateUrlForHttps(this.userinfoEndpoint)) {
            throw new Error("userinfoEndpoint must use HTTPS (with TLS), or config value for property 'requireHttps' must be set to 'false' and allow HTTP (without TLS).");
        }
        return new Promise((resolve, reject) => {
            const headers = new HttpHeaders().set('Authorization', 'Bearer ' + this.getAccessToken());
            this.http
                .get(this.userinfoEndpoint, { headers })
                .subscribe(info => {
                this.debug('userinfo received', info);
                const existingClaims = this.getIdentityClaims() || {};
                if (!this.skipSubjectCheck) {
                    if (this.oidc &&
                        (!existingClaims['sub'] || info.sub !== existingClaims['sub'])) {
                        const err = 'if property oidc is true, the received user-id (sub) has to be the user-id ' +
                            'of the user that has logged in with oidc.\n' +
                            'if you are not using oidc but just oauth2 password flow set oidc to false';
                        reject(err);
                        return;
                    }
                }
                info = Object.assign({}, existingClaims, info);
                this._storage.setItem('id_token_claims_obj', JSON.stringify(info));
                this.eventsSubject.next(new OAuthSuccessEvent('user_profile_loaded'));
                resolve(info);
            }, err => {
                this.logger.error('error loading user info', err);
                this.eventsSubject.next(new OAuthErrorEvent('user_profile_load_error', err));
                reject(err);
            });
        });
    }
    /**
     * Uses password flow to exchange userName and password for an access_token.
     * @param userName
     * @param password
     * @param headers Optional additional http-headers.
     */
    fetchTokenUsingPasswordFlow(userName, password, headers = new HttpHeaders()) {
        this.assertUrlNotNullAndCorrectProtocol(this.tokenEndpoint, 'tokenEndpoint');
        return new Promise((resolve, reject) => {
            /**
             * A `HttpParameterCodec` that uses `encodeURIComponent` and `decodeURIComponent` to
             * serialize and parse URL parameter keys and values.
             *
             * @stable
             */
            let params = new HttpParams({ encoder: new WebHttpUrlEncodingCodec() })
                .set('grant_type', 'password')
                .set('scope', this.scope)
                .set('username', userName)
                .set('password', password);
            if (this.useHttpBasicAuth) {
                const header = btoa(`${this.clientId}:${this.dummyClientSecret}`);
                headers = headers.set('Authorization', 'Basic ' + header);
            }
            if (!this.useHttpBasicAuth) {
                params = params.set('client_id', this.clientId);
            }
            if (!this.useHttpBasicAuth && this.dummyClientSecret) {
                params = params.set('client_secret', this.dummyClientSecret);
            }
            if (this.customQueryParams) {
                for (const key of Object.getOwnPropertyNames(this.customQueryParams)) {
                    params = params.set(key, this.customQueryParams[key]);
                }
            }
            headers = headers.set('Content-Type', 'application/x-www-form-urlencoded');
            this.http
                .post(this.tokenEndpoint, params, { headers })
                .subscribe(tokenResponse => {
                this.debug('tokenResponse', tokenResponse);
                this.storeAccessTokenResponse(tokenResponse.access_token, tokenResponse.refresh_token, tokenResponse.expires_in ||
                    this.fallbackAccessTokenExpirationTimeInSec, tokenResponse.scope, this.extractRecognizedCustomParameters(tokenResponse));
                this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
                resolve(tokenResponse);
            }, err => {
                this.logger.error('Error performing password flow', err);
                this.eventsSubject.next(new OAuthErrorEvent('token_error', err));
                reject(err);
            });
        });
    }
    /**
     * Refreshes the token using a refresh_token.
     * This does not work for implicit flow, b/c
     * there is no refresh_token in this flow.
     * A solution for this is provided by the
     * method silentRefresh.
     */
    refreshToken() {
        this.assertUrlNotNullAndCorrectProtocol(this.tokenEndpoint, 'tokenEndpoint');
        return new Promise((resolve, reject) => {
            let params = new HttpParams()
                .set('grant_type', 'refresh_token')
                .set('scope', this.scope)
                .set('refresh_token', this._storage.getItem('refresh_token'));
            let headers = new HttpHeaders().set('Content-Type', 'application/x-www-form-urlencoded');
            if (this.useHttpBasicAuth) {
                const header = btoa(`${this.clientId}:${this.dummyClientSecret}`);
                headers = headers.set('Authorization', 'Basic ' + header);
            }
            if (!this.useHttpBasicAuth) {
                params = params.set('client_id', this.clientId);
            }
            if (!this.useHttpBasicAuth && this.dummyClientSecret) {
                params = params.set('client_secret', this.dummyClientSecret);
            }
            if (this.customQueryParams) {
                for (const key of Object.getOwnPropertyNames(this.customQueryParams)) {
                    params = params.set(key, this.customQueryParams[key]);
                }
            }
            this.http
                .post(this.tokenEndpoint, params, { headers })
                .pipe(switchMap(tokenResponse => {
                if (tokenResponse.id_token) {
                    return from(this.processIdToken(tokenResponse.id_token, tokenResponse.access_token, true)).pipe(tap(result => this.storeIdToken(result)), map(_ => tokenResponse));
                }
                else {
                    return of(tokenResponse);
                }
            }))
                .subscribe(tokenResponse => {
                this.debug('refresh tokenResponse', tokenResponse);
                this.storeAccessTokenResponse(tokenResponse.access_token, tokenResponse.refresh_token, tokenResponse.expires_in ||
                    this.fallbackAccessTokenExpirationTimeInSec, tokenResponse.scope, this.extractRecognizedCustomParameters(tokenResponse));
                this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
                this.eventsSubject.next(new OAuthSuccessEvent('token_refreshed'));
                resolve(tokenResponse);
            }, err => {
                this.logger.error('Error refreshing token', err);
                this.eventsSubject.next(new OAuthErrorEvent('token_refresh_error', err));
                reject(err);
            });
        });
    }
    removeSilentRefreshEventListener() {
        if (this.silentRefreshPostMessageEventListener) {
            window.removeEventListener('message', this.silentRefreshPostMessageEventListener);
            this.silentRefreshPostMessageEventListener = null;
        }
    }
    setupSilentRefreshEventListener() {
        this.removeSilentRefreshEventListener();
        this.silentRefreshPostMessageEventListener = (e) => {
            const message = this.processMessageEventMessage(e);
            this.tryLogin({
                customHashFragment: message,
                preventClearHashAfterLogin: true,
                customRedirectUri: this.silentRefreshRedirectUri || this.redirectUri
            }).catch(err => this.debug('tryLogin during silent refresh failed', err));
        };
        window.addEventListener('message', this.silentRefreshPostMessageEventListener);
    }
    /**
     * Performs a silent refresh for implicit flow.
     * Use this method to get new tokens when/before
     * the existing tokens expire.
     */
    silentRefresh(params = {}, noPrompt = true) {
        const claims = this.getIdentityClaims() || {};
        if (this.useIdTokenHintForSilentRefresh && this.hasValidIdToken()) {
            params['id_token_hint'] = this.getIdToken();
        }
        if (!this.validateUrlForHttps(this.loginUrl)) {
            throw new Error("loginUrl  must use HTTPS (with TLS), or config value for property 'requireHttps' must be set to 'false' and allow HTTP (without TLS).");
        }
        if (typeof this.document === 'undefined') {
            throw new Error('silent refresh is not supported on this platform');
        }
        const existingIframe = this.document.getElementById(this.silentRefreshIFrameName);
        if (existingIframe) {
            this.document.body.removeChild(existingIframe);
        }
        this.silentRefreshSubject = claims['sub'];
        const iframe = this.document.createElement('iframe');
        iframe.id = this.silentRefreshIFrameName;
        this.setupSilentRefreshEventListener();
        const redirectUri = this.silentRefreshRedirectUri || this.redirectUri;
        this.createLoginUrl(null, null, redirectUri, noPrompt, params).then(url => {
            iframe.setAttribute('src', url);
            if (!this.silentRefreshShowIFrame) {
                iframe.style['display'] = 'none';
            }
            this.document.body.appendChild(iframe);
        });
        const errors = this.events.pipe(filter(e => e instanceof OAuthErrorEvent), first());
        const success = this.events.pipe(filter(e => e.type === 'token_received'), first());
        const timeout = of(new OAuthErrorEvent('silent_refresh_timeout', null)).pipe(delay(this.silentRefreshTimeout));
        return race([errors, success, timeout])
            .pipe(map(e => {
            if (e instanceof OAuthErrorEvent) {
                if (e.type === 'silent_refresh_timeout') {
                    this.eventsSubject.next(e);
                }
                else {
                    e = new OAuthErrorEvent('silent_refresh_error', e);
                    this.eventsSubject.next(e);
                }
                throw e;
            }
            else if (e.type === 'token_received') {
                e = new OAuthSuccessEvent('silently_refreshed');
                this.eventsSubject.next(e);
            }
            return e;
        }))
            .toPromise();
    }
    /**
     * This method exists for backwards compatibility.
     * {@link OAuthService#initLoginFlowInPopup} handles both code
     * and implicit flows.
     */
    initImplicitFlowInPopup(options) {
        return this.initLoginFlowInPopup(options);
    }
    initLoginFlowInPopup(options) {
        options = options || {};
        return this.createLoginUrl(null, null, this.silentRefreshRedirectUri, false, {
            display: 'popup'
        }).then(url => {
            return new Promise((resolve, reject) => {
                /**
                 * Error handling section
                 */
                const checkForPopupClosedInterval = 500;
                let windowRef = window.open(url, '_blank', this.calculatePopupFeatures(options));
                let checkForPopupClosedTimer;
                const checkForPopupClosed = () => {
                    if (!windowRef || windowRef.closed) {
                        cleanup();
                        reject(new OAuthErrorEvent('popup_closed', {}));
                    }
                };
                if (!windowRef) {
                    reject(new OAuthErrorEvent('popup_blocked', {}));
                }
                else {
                    checkForPopupClosedTimer = window.setInterval(checkForPopupClosed, checkForPopupClosedInterval);
                }
                const cleanup = () => {
                    window.clearInterval(checkForPopupClosedTimer);
                    window.removeEventListener('message', listener);
                    if (windowRef !== null) {
                        windowRef.close();
                    }
                    windowRef = null;
                };
                const listener = (e) => {
                    const message = this.processMessageEventMessage(e);
                    if (message && message !== null) {
                        this.tryLogin({
                            customHashFragment: message,
                            preventClearHashAfterLogin: true,
                            customRedirectUri: this.silentRefreshRedirectUri
                        }).then(() => {
                            cleanup();
                            resolve();
                        }, err => {
                            cleanup();
                            reject(err);
                        });
                    }
                    else {
                        console.log('false event firing');
                    }
                };
                window.addEventListener('message', listener);
            });
        });
    }
    calculatePopupFeatures(options) {
        // Specify an static height and width and calculate centered position
        const height = options.height || 470;
        const width = options.width || 500;
        const left = window.screenLeft + (window.outerWidth - width) / 2;
        const top = window.screenTop + (window.outerHeight - height) / 2;
        return `location=no,toolbar=no,width=${width},height=${height},top=${top},left=${left}`;
    }
    processMessageEventMessage(e) {
        let expectedPrefix = '#';
        if (this.silentRefreshMessagePrefix) {
            expectedPrefix += this.silentRefreshMessagePrefix;
        }
        if (!e || !e.data || typeof e.data !== 'string') {
            return;
        }
        const prefixedMessage = e.data;
        if (!prefixedMessage.startsWith(expectedPrefix)) {
            return;
        }
        return '#' + prefixedMessage.substr(expectedPrefix.length);
    }
    canPerformSessionCheck() {
        if (!this.sessionChecksEnabled) {
            return false;
        }
        if (!this.sessionCheckIFrameUrl) {
            console.warn('sessionChecksEnabled is activated but there is no sessionCheckIFrameUrl');
            return false;
        }
        const sessionState = this.getSessionState();
        if (!sessionState) {
            console.warn('sessionChecksEnabled is activated but there is no session_state');
            return false;
        }
        if (typeof this.document === 'undefined') {
            return false;
        }
        return true;
    }
    setupSessionCheckEventListener() {
        this.removeSessionCheckEventListener();
        this.sessionCheckEventListener = (e) => {
            const origin = e.origin.toLowerCase();
            const issuer = this.issuer.toLowerCase();
            this.debug('sessionCheckEventListener');
            if (!issuer.startsWith(origin)) {
                this.debug('sessionCheckEventListener', 'wrong origin', origin, 'expected', issuer, 'event', e);
                return;
            }
            // only run in Angular zone if it is 'changed' or 'error'
            switch (e.data) {
                case 'unchanged':
                    this.handleSessionUnchanged();
                    break;
                case 'changed':
                    this.ngZone.run(() => {
                        this.handleSessionChange();
                    });
                    break;
                case 'error':
                    this.ngZone.run(() => {
                        this.handleSessionError();
                    });
                    break;
            }
            this.debug('got info from session check inframe', e);
        };
        // prevent Angular from refreshing the view on every message (runs in intervals)
        this.ngZone.runOutsideAngular(() => {
            window.addEventListener('message', this.sessionCheckEventListener);
        });
    }
    handleSessionUnchanged() {
        this.debug('session check', 'session unchanged');
    }
    handleSessionChange() {
        this.eventsSubject.next(new OAuthInfoEvent('session_changed'));
        this.stopSessionCheckTimer();
        if (!this.useSilentRefresh && this.responseType === 'code') {
            this.refreshToken()
                .then(_ => {
                this.debug('token refresh after session change worked');
            })
                .catch(_ => {
                this.debug('token refresh did not work after session changed');
                this.eventsSubject.next(new OAuthInfoEvent('session_terminated'));
                this.logOut(true);
            });
        }
        else if (this.silentRefreshRedirectUri) {
            this.silentRefresh().catch(_ => this.debug('silent refresh failed after session changed'));
            this.waitForSilentRefreshAfterSessionChange();
        }
        else {
            this.eventsSubject.next(new OAuthInfoEvent('session_terminated'));
            this.logOut(true);
        }
    }
    waitForSilentRefreshAfterSessionChange() {
        this.events
            .pipe(filter((e) => e.type === 'silently_refreshed' ||
            e.type === 'silent_refresh_timeout' ||
            e.type === 'silent_refresh_error'), first())
            .subscribe(e => {
            if (e.type !== 'silently_refreshed') {
                this.debug('silent refresh did not work after session changed');
                this.eventsSubject.next(new OAuthInfoEvent('session_terminated'));
                this.logOut(true);
            }
        });
    }
    handleSessionError() {
        this.stopSessionCheckTimer();
        this.eventsSubject.next(new OAuthInfoEvent('session_error'));
    }
    removeSessionCheckEventListener() {
        if (this.sessionCheckEventListener) {
            window.removeEventListener('message', this.sessionCheckEventListener);
            this.sessionCheckEventListener = null;
        }
    }
    initSessionCheck() {
        if (!this.canPerformSessionCheck()) {
            return;
        }
        const existingIframe = this.document.getElementById(this.sessionCheckIFrameName);
        if (existingIframe) {
            this.document.body.removeChild(existingIframe);
        }
        const iframe = this.document.createElement('iframe');
        iframe.id = this.sessionCheckIFrameName;
        this.setupSessionCheckEventListener();
        const url = this.sessionCheckIFrameUrl;
        iframe.setAttribute('src', url);
        iframe.style.display = 'none';
        this.document.body.appendChild(iframe);
        this.startSessionCheckTimer();
    }
    startSessionCheckTimer() {
        this.stopSessionCheckTimer();
        this.ngZone.runOutsideAngular(() => {
            this.sessionCheckTimer = setInterval(this.checkSession.bind(this), this.sessionCheckIntervall);
        });
    }
    stopSessionCheckTimer() {
        if (this.sessionCheckTimer) {
            clearInterval(this.sessionCheckTimer);
            this.sessionCheckTimer = null;
        }
    }
    checkSession() {
        const iframe = this.document.getElementById(this.sessionCheckIFrameName);
        if (!iframe) {
            this.logger.warn('checkSession did not find iframe', this.sessionCheckIFrameName);
        }
        const sessionState = this.getSessionState();
        if (!sessionState) {
            this.stopSessionCheckTimer();
        }
        const message = this.clientId + ' ' + sessionState;
        iframe.contentWindow.postMessage(message, this.issuer);
    }
    createLoginUrl(state = '', loginHint = '', customRedirectUri = '', noPrompt = false, params = {}) {
        return __awaiter(this, void 0, void 0, function* () {
            const that = this;
            let redirectUri;
            if (customRedirectUri) {
                redirectUri = customRedirectUri;
            }
            else {
                redirectUri = this.redirectUri;
            }
            const nonce = yield this.createAndSaveNonce();
            if (state) {
                state =
                    nonce + this.config.nonceStateSeparator + encodeURIComponent(state);
            }
            else {
                state = nonce;
            }
            if (!this.requestAccessToken && !this.oidc) {
                throw new Error('Either requestAccessToken or oidc or both must be true');
            }
            if (this.config.responseType) {
                this.responseType = this.config.responseType;
            }
            else {
                if (this.oidc && this.requestAccessToken) {
                    this.responseType = 'id_token token';
                }
                else if (this.oidc && !this.requestAccessToken) {
                    this.responseType = 'id_token';
                }
                else {
                    this.responseType = 'token';
                }
            }
            const seperationChar = that.loginUrl.indexOf('?') > -1 ? '&' : '?';
            let scope = that.scope;
            if (this.oidc && !scope.match(/(^|\s)openid($|\s)/)) {
                scope = 'openid ' + scope;
            }
            let url = that.loginUrl +
                seperationChar +
                'response_type=' +
                encodeURIComponent(that.responseType) +
                '&client_id=' +
                encodeURIComponent(that.clientId) +
                '&state=' +
                encodeURIComponent(state) +
                '&redirect_uri=' +
                encodeURIComponent(redirectUri) +
                '&scope=' +
                encodeURIComponent(scope);
            if (this.responseType.includes('code') && !this.disablePKCE) {
                const [challenge, verifier] = yield this.createChallangeVerifierPairForPKCE();
                if (this.saveNoncesInLocalStorage &&
                    typeof window['localStorage'] !== 'undefined') {
                    localStorage.setItem('PKCE_verifier', verifier);
                }
                else {
                    this._storage.setItem('PKCE_verifier', verifier);
                }
                url += '&code_challenge=' + challenge;
                url += '&code_challenge_method=S256';
            }
            if (loginHint) {
                url += '&login_hint=' + encodeURIComponent(loginHint);
            }
            if (that.resource) {
                url += '&resource=' + encodeURIComponent(that.resource);
            }
            if (that.oidc) {
                url += '&nonce=' + encodeURIComponent(nonce);
            }
            if (noPrompt) {
                url += '&prompt=none';
            }
            for (const key of Object.keys(params)) {
                url +=
                    '&' + encodeURIComponent(key) + '=' + encodeURIComponent(params[key]);
            }
            if (this.customQueryParams) {
                for (const key of Object.getOwnPropertyNames(this.customQueryParams)) {
                    url +=
                        '&' + key + '=' + encodeURIComponent(this.customQueryParams[key]);
                }
            }
            return url;
        });
    }
    initImplicitFlowInternal(additionalState = '', params = '') {
        if (this.inImplicitFlow) {
            return;
        }
        this.inImplicitFlow = true;
        if (!this.validateUrlForHttps(this.loginUrl)) {
            throw new Error("loginUrl  must use HTTPS (with TLS), or config value for property 'requireHttps' must be set to 'false' and allow HTTP (without TLS).");
        }
        let addParams = {};
        let loginHint = null;
        if (typeof params === 'string') {
            loginHint = params;
        }
        else if (typeof params === 'object') {
            addParams = params;
        }
        this.createLoginUrl(additionalState, loginHint, null, false, addParams)
            .then(this.config.openUri)
            .catch(error => {
            console.error('Error in initImplicitFlow', error);
            this.inImplicitFlow = false;
        });
    }
    /**
     * Starts the implicit flow and redirects to user to
     * the auth servers' login url.
     *
     * @param additionalState Optional state that is passed around.
     *  You'll find this state in the property `state` after `tryLogin` logged in the user.
     * @param params Hash with additional parameter. If it is a string, it is used for the
     *               parameter loginHint (for the sake of compatibility with former versions)
     */
    initImplicitFlow(additionalState = '', params = '') {
        if (this.loginUrl !== '') {
            this.initImplicitFlowInternal(additionalState, params);
        }
        else {
            this.events
                .pipe(filter(e => e.type === 'discovery_document_loaded'))
                .subscribe(_ => this.initImplicitFlowInternal(additionalState, params));
        }
    }
    /**
     * Reset current implicit flow
     *
     * @description This method allows resetting the current implict flow in order to be initialized again.
     */
    resetImplicitFlow() {
        this.inImplicitFlow = false;
    }
    callOnTokenReceivedIfExists(options) {
        const that = this;
        if (options.onTokenReceived) {
            const tokenParams = {
                idClaims: that.getIdentityClaims(),
                idToken: that.getIdToken(),
                accessToken: that.getAccessToken(),
                state: that.state
            };
            options.onTokenReceived(tokenParams);
        }
    }
    storeAccessTokenResponse(accessToken, refreshToken, expiresIn, grantedScopes, customParameters) {
        this._storage.setItem('access_token', accessToken);
        if (grantedScopes && !Array.isArray(grantedScopes)) {
            this._storage.setItem('granted_scopes', JSON.stringify(grantedScopes.split('+')));
        }
        else if (grantedScopes && Array.isArray(grantedScopes)) {
            this._storage.setItem('granted_scopes', JSON.stringify(grantedScopes));
        }
        this._storage.setItem('access_token_stored_at', '' + Date.now());
        if (expiresIn) {
            const expiresInMilliSeconds = expiresIn * 1000;
            const now = new Date();
            const expiresAt = now.getTime() + expiresInMilliSeconds;
            this._storage.setItem('expires_at', '' + expiresAt);
        }
        if (refreshToken) {
            this._storage.setItem('refresh_token', refreshToken);
        }
        if (customParameters) {
            customParameters.forEach((value, key) => {
                this._storage.setItem(key, value);
            });
        }
    }
    /**
     * Delegates to tryLoginImplicitFlow for the sake of competability
     * @param options Optional options.
     */
    tryLogin(options = null) {
        if (this.config.responseType === 'code') {
            return this.tryLoginCodeFlow(options).then(_ => true);
        }
        else {
            return this.tryLoginImplicitFlow(options);
        }
    }
    parseQueryString(queryString) {
        if (!queryString || queryString.length === 0) {
            return {};
        }
        if (queryString.charAt(0) === '?') {
            queryString = queryString.substr(1);
        }
        return this.urlHelper.parseQueryString(queryString);
    }
    tryLoginCodeFlow(options = null) {
        options = options || {};
        const querySource = options.customHashFragment
            ? options.customHashFragment.substring(1)
            : window.location.search;
        const parts = this.getCodePartsFromUrl(querySource);
        const code = parts['code'];
        const state = parts['state'];
        const sessionState = parts['session_state'];
        if (!options.preventClearHashAfterLogin) {
            const href = location.href
                .replace(/[&\?]code=[^&\$]*/, '')
                .replace(/[&\?]scope=[^&\$]*/, '')
                .replace(/[&\?]state=[^&\$]*/, '')
                .replace(/[&\?]session_state=[^&\$]*/, '');
            history.replaceState(null, window.name, href);
        }
        let [nonceInState, userState] = this.parseState(state);
        this.state = userState;
        if (parts['error']) {
            this.debug('error trying to login');
            this.handleLoginError({}, parts);
            const err = new OAuthErrorEvent('code_error', {}, parts);
            this.eventsSubject.next(err);
            return Promise.reject(err);
        }
        if (!nonceInState) {
            return Promise.resolve();
        }
        const success = this.validateNonce(nonceInState);
        if (!success) {
            const event = new OAuthErrorEvent('invalid_nonce_in_state', null);
            this.eventsSubject.next(event);
            return Promise.reject(event);
        }
        this.storeSessionState(sessionState);
        if (code) {
            return this.getTokenFromCode(code, options).then(_ => null);
        }
        else {
            return Promise.resolve();
        }
    }
    /**
     * Retrieve the returned auth code from the redirect uri that has been called.
     * If required also check hash, as we could use hash location strategy.
     */
    getCodePartsFromUrl(queryString) {
        if (!queryString || queryString.length === 0) {
            return this.urlHelper.getHashFragmentParams();
        }
        // normalize query string
        if (queryString.charAt(0) === '?') {
            queryString = queryString.substr(1);
        }
        return this.urlHelper.parseQueryString(queryString);
    }
    /**
     * Get token using an intermediate code. Works for the Authorization Code flow.
     */
    getTokenFromCode(code, options) {
        let params = new HttpParams()
            .set('grant_type', 'authorization_code')
            .set('code', code)
            .set('redirect_uri', options.customRedirectUri || this.redirectUri);
        if (!this.disablePKCE) {
            let PKCEVerifier;
            if (this.saveNoncesInLocalStorage &&
                typeof window['localStorage'] !== 'undefined') {
                PKCEVerifier = localStorage.getItem('PKCE_verifier');
            }
            else {
                PKCEVerifier = this._storage.getItem('PKCE_verifier');
            }
            if (!PKCEVerifier) {
                console.warn('No PKCE verifier found in oauth storage!');
            }
            else {
                params = params.set('code_verifier', PKCEVerifier);
            }
        }
        return this.fetchAndProcessToken(params);
    }
    fetchAndProcessToken(params) {
        this.assertUrlNotNullAndCorrectProtocol(this.tokenEndpoint, 'tokenEndpoint');
        let headers = new HttpHeaders().set('Content-Type', 'application/x-www-form-urlencoded');
        if (this.useHttpBasicAuth) {
            const header = btoa(`${this.clientId}:${this.dummyClientSecret}`);
            headers = headers.set('Authorization', 'Basic ' + header);
        }
        if (!this.useHttpBasicAuth) {
            params = params.set('client_id', this.clientId);
        }
        if (!this.useHttpBasicAuth && this.dummyClientSecret) {
            params = params.set('client_secret', this.dummyClientSecret);
        }
        return new Promise((resolve, reject) => {
            if (this.customQueryParams) {
                for (let key of Object.getOwnPropertyNames(this.customQueryParams)) {
                    params = params.set(key, this.customQueryParams[key]);
                }
            }
            this.http
                .post(this.tokenEndpoint, params, { headers })
                .subscribe(tokenResponse => {
                this.debug('refresh tokenResponse', tokenResponse);
                this.storeAccessTokenResponse(tokenResponse.access_token, tokenResponse.refresh_token, tokenResponse.expires_in ||
                    this.fallbackAccessTokenExpirationTimeInSec, tokenResponse.scope, this.extractRecognizedCustomParameters(tokenResponse));
                if (this.oidc && tokenResponse.id_token) {
                    this.processIdToken(tokenResponse.id_token, tokenResponse.access_token)
                        .then(result => {
                        this.storeIdToken(result);
                        this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
                        this.eventsSubject.next(new OAuthSuccessEvent('token_refreshed'));
                        resolve(tokenResponse);
                    })
                        .catch(reason => {
                        this.eventsSubject.next(new OAuthErrorEvent('token_validation_error', reason));
                        console.error('Error validating tokens');
                        console.error(reason);
                        reject(reason);
                    });
                }
                else {
                    this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
                    this.eventsSubject.next(new OAuthSuccessEvent('token_refreshed'));
                    resolve(tokenResponse);
                }
            }, err => {
                console.error('Error getting token', err);
                this.eventsSubject.next(new OAuthErrorEvent('token_refresh_error', err));
                reject(err);
            });
        });
    }
    /**
     * Checks whether there are tokens in the hash fragment
     * as a result of the implicit flow. These tokens are
     * parsed, validated and used to sign the user in to the
     * current client.
     *
     * @param options Optional options.
     */
    tryLoginImplicitFlow(options = null) {
        options = options || {};
        let parts;
        if (options.customHashFragment) {
            parts = this.urlHelper.getHashFragmentParams(options.customHashFragment);
        }
        else {
            parts = this.urlHelper.getHashFragmentParams();
        }
        this.debug('parsed url', parts);
        const state = parts['state'];
        let [nonceInState, userState] = this.parseState(state);
        this.state = userState;
        if (parts['error']) {
            this.debug('error trying to login');
            this.handleLoginError(options, parts);
            const err = new OAuthErrorEvent('token_error', {}, parts);
            this.eventsSubject.next(err);
            return Promise.reject(err);
        }
        const accessToken = parts['access_token'];
        const idToken = parts['id_token'];
        const sessionState = parts['session_state'];
        const grantedScopes = parts['scope'];
        if (!this.requestAccessToken && !this.oidc) {
            return Promise.reject('Either requestAccessToken or oidc (or both) must be true.');
        }
        if (this.requestAccessToken && !accessToken) {
            return Promise.resolve(false);
        }
        if (this.requestAccessToken && !options.disableOAuth2StateCheck && !state) {
            return Promise.resolve(false);
        }
        if (this.oidc && !idToken) {
            return Promise.resolve(false);
        }
        if (this.sessionChecksEnabled && !sessionState) {
            this.logger.warn('session checks (Session Status Change Notification) ' +
                'were activated in the configuration but the id_token ' +
                'does not contain a session_state claim');
        }
        if (this.requestAccessToken && !options.disableOAuth2StateCheck) {
            const success = this.validateNonce(nonceInState);
            if (!success) {
                const event = new OAuthErrorEvent('invalid_nonce_in_state', null);
                this.eventsSubject.next(event);
                return Promise.reject(event);
            }
        }
        if (this.requestAccessToken) {
            this.storeAccessTokenResponse(accessToken, null, parts['expires_in'] || this.fallbackAccessTokenExpirationTimeInSec, grantedScopes);
        }
        if (!this.oidc) {
            this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
            if (this.clearHashAfterLogin && !options.preventClearHashAfterLogin) {
                location.hash = '';
            }
            this.callOnTokenReceivedIfExists(options);
            return Promise.resolve(true);
        }
        return this.processIdToken(idToken, accessToken)
            .then(result => {
            if (options.validationHandler) {
                return options
                    .validationHandler({
                    accessToken: accessToken,
                    idClaims: result.idTokenClaims,
                    idToken: result.idToken,
                    state: state
                })
                    .then(_ => result);
            }
            return result;
        })
            .then(result => {
            this.storeIdToken(result);
            this.storeSessionState(sessionState);
            if (this.clearHashAfterLogin && !options.preventClearHashAfterLogin) {
                location.hash = '';
            }
            this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
            this.callOnTokenReceivedIfExists(options);
            this.inImplicitFlow = false;
            return true;
        })
            .catch(reason => {
            this.eventsSubject.next(new OAuthErrorEvent('token_validation_error', reason));
            this.logger.error('Error validating tokens');
            this.logger.error(reason);
            return Promise.reject(reason);
        });
    }
    parseState(state) {
        let nonce = state;
        let userState = '';
        if (state) {
            const idx = state.indexOf(this.config.nonceStateSeparator);
            if (idx > -1) {
                nonce = state.substr(0, idx);
                userState = state.substr(idx + this.config.nonceStateSeparator.length);
            }
        }
        return [nonce, userState];
    }
    validateNonce(nonceInState) {
        let savedNonce;
        if (this.saveNoncesInLocalStorage &&
            typeof window['localStorage'] !== 'undefined') {
            savedNonce = localStorage.getItem('nonce');
        }
        else {
            savedNonce = this._storage.getItem('nonce');
        }
        if (savedNonce !== nonceInState) {
            const err = 'Validating access_token failed, wrong state/nonce.';
            console.error(err, savedNonce, nonceInState);
            return false;
        }
        return true;
    }
    storeIdToken(idToken) {
        this._storage.setItem('id_token', idToken.idToken);
        this._storage.setItem('id_token_claims_obj', idToken.idTokenClaimsJson);
        this._storage.setItem('id_token_expires_at', '' + idToken.idTokenExpiresAt);
        this._storage.setItem('id_token_stored_at', '' + Date.now());
    }
    storeSessionState(sessionState) {
        this._storage.setItem('session_state', sessionState);
    }
    getSessionState() {
        return this._storage.getItem('session_state');
    }
    handleLoginError(options, parts) {
        if (options.onLoginError) {
            options.onLoginError(parts);
        }
        if (this.clearHashAfterLogin && !options.preventClearHashAfterLogin) {
            location.hash = '';
        }
    }
    /**
     * @ignore
     */
    processIdToken(idToken, accessToken, skipNonceCheck = false) {
        const tokenParts = idToken.split('.');
        const headerBase64 = this.padBase64(tokenParts[0]);
        const headerJson = b64DecodeUnicode(headerBase64);
        const header = JSON.parse(headerJson);
        const claimsBase64 = this.padBase64(tokenParts[1]);
        const claimsJson = b64DecodeUnicode(claimsBase64);
        const claims = JSON.parse(claimsJson);
        let savedNonce;
        if (this.saveNoncesInLocalStorage &&
            typeof window['localStorage'] !== 'undefined') {
            savedNonce = localStorage.getItem('nonce');
        }
        else {
            savedNonce = this._storage.getItem('nonce');
        }
        if (Array.isArray(claims.aud)) {
            if (claims.aud.every(v => v !== this.clientId)) {
                const err = 'Wrong audience: ' + claims.aud.join(',');
                this.logger.warn(err);
                return Promise.reject(err);
            }
        }
        else {
            if (claims.aud !== this.clientId) {
                const err = 'Wrong audience: ' + claims.aud;
                this.logger.warn(err);
                return Promise.reject(err);
            }
        }
        if (!claims.sub) {
            const err = 'No sub claim in id_token';
            this.logger.warn(err);
            return Promise.reject(err);
        }
        /* For now, we only check whether the sub against
         * silentRefreshSubject when sessionChecksEnabled is on
         * We will reconsider in a later version to do this
         * in every other case too.
         */
        if (this.sessionChecksEnabled &&
            this.silentRefreshSubject &&
            this.silentRefreshSubject !== claims['sub']) {
            const err = 'After refreshing, we got an id_token for another user (sub). ' +
                `Expected sub: ${this.silentRefreshSubject}, received sub: ${claims['sub']}`;
            this.logger.warn(err);
            return Promise.reject(err);
        }
        if (!claims.iat) {
            const err = 'No iat claim in id_token';
            this.logger.warn(err);
            return Promise.reject(err);
        }
        if (!this.skipIssuerCheck && claims.iss !== this.issuer) {
            const err = 'Wrong issuer: ' + claims.iss;
            this.logger.warn(err);
            return Promise.reject(err);
        }
        if (!skipNonceCheck && claims.nonce !== savedNonce) {
            const err = 'Wrong nonce: ' + claims.nonce;
            this.logger.warn(err);
            return Promise.reject(err);
        }
        // at_hash is not applicable to authorization code flow
        // addressing https://github.com/manfredsteyer/angular-oauth2-oidc/issues/661
        // i.e. Based on spec the at_hash check is only true for implicit code flow on Ping Federate
        // https://www.pingidentity.com/developer/en/resources/openid-connect-developers-guide.html
        if (this.hasOwnProperty('responseType') &&
            (this.responseType === 'code' || this.responseType === 'id_token')) {
            this.disableAtHashCheck = true;
        }
        if (!this.disableAtHashCheck &&
            this.requestAccessToken &&
            !claims['at_hash']) {
            const err = 'An at_hash is needed!';
            this.logger.warn(err);
            return Promise.reject(err);
        }
        const now = Date.now();
        const issuedAtMSec = claims.iat * 1000;
        const expiresAtMSec = claims.exp * 1000;
        const clockSkewInMSec = (this.clockSkewInSec || 600) * 1000;
        if (issuedAtMSec - clockSkewInMSec >= now ||
            expiresAtMSec + clockSkewInMSec <= now) {
            const err = 'Token has expired';
            console.error(err);
            console.error({
                now: now,
                issuedAtMSec: issuedAtMSec,
                expiresAtMSec: expiresAtMSec
            });
            return Promise.reject(err);
        }
        const validationParams = {
            accessToken: accessToken,
            idToken: idToken,
            jwks: this.jwks,
            idTokenClaims: claims,
            idTokenHeader: header,
            loadKeys: () => this.loadJwks()
        };
        if (this.disableAtHashCheck) {
            return this.checkSignature(validationParams).then(_ => {
                const result = {
                    idToken: idToken,
                    idTokenClaims: claims,
                    idTokenClaimsJson: claimsJson,
                    idTokenHeader: header,
                    idTokenHeaderJson: headerJson,
                    idTokenExpiresAt: expiresAtMSec
                };
                return result;
            });
        }
        return this.checkAtHash(validationParams).then(atHashValid => {
            if (!this.disableAtHashCheck && this.requestAccessToken && !atHashValid) {
                const err = 'Wrong at_hash';
                this.logger.warn(err);
                return Promise.reject(err);
            }
            return this.checkSignature(validationParams).then(_ => {
                const atHashCheckEnabled = !this.disableAtHashCheck;
                const result = {
                    idToken: idToken,
                    idTokenClaims: claims,
                    idTokenClaimsJson: claimsJson,
                    idTokenHeader: header,
                    idTokenHeaderJson: headerJson,
                    idTokenExpiresAt: expiresAtMSec
                };
                if (atHashCheckEnabled) {
                    return this.checkAtHash(validationParams).then(atHashValid => {
                        if (this.requestAccessToken && !atHashValid) {
                            const err = 'Wrong at_hash';
                            this.logger.warn(err);
                            return Promise.reject(err);
                        }
                        else {
                            return result;
                        }
                    });
                }
                else {
                    return result;
                }
            });
        });
    }
    /**
     * Returns the received claims about the user.
     */
    getIdentityClaims() {
        const claims = this._storage.getItem('id_token_claims_obj');
        if (!claims) {
            return null;
        }
        return JSON.parse(claims);
    }
    /**
     * Returns the granted scopes from the server.
     */
    getGrantedScopes() {
        const scopes = this._storage.getItem('granted_scopes');
        if (!scopes) {
            return null;
        }
        return JSON.parse(scopes);
    }
    /**
     * Returns the current id_token.
     */
    getIdToken() {
        return this._storage ? this._storage.getItem('id_token') : null;
    }
    padBase64(base64data) {
        while (base64data.length % 4 !== 0) {
            base64data += '=';
        }
        return base64data;
    }
    /**
     * Returns the current access_token.
     */
    getAccessToken() {
        return this._storage ? this._storage.getItem('access_token') : null;
    }
    getRefreshToken() {
        return this._storage ? this._storage.getItem('refresh_token') : null;
    }
    /**
     * Returns the expiration date of the access_token
     * as milliseconds since 1970.
     */
    getAccessTokenExpiration() {
        if (!this._storage.getItem('expires_at')) {
            return null;
        }
        return parseInt(this._storage.getItem('expires_at'), 10);
    }
    getAccessTokenStoredAt() {
        return parseInt(this._storage.getItem('access_token_stored_at'), 10);
    }
    getIdTokenStoredAt() {
        return parseInt(this._storage.getItem('id_token_stored_at'), 10);
    }
    /**
     * Returns the expiration date of the id_token
     * as milliseconds since 1970.
     */
    getIdTokenExpiration() {
        if (!this._storage.getItem('id_token_expires_at')) {
            return null;
        }
        return parseInt(this._storage.getItem('id_token_expires_at'), 10);
    }
    /**
     * Checkes, whether there is a valid access_token.
     */
    hasValidAccessToken() {
        if (this.getAccessToken()) {
            const expiresAt = this._storage.getItem('expires_at');
            const now = new Date();
            if (expiresAt && parseInt(expiresAt, 10) < now.getTime()) {
                return false;
            }
            return true;
        }
        return false;
    }
    /**
     * Checks whether there is a valid id_token.
     */
    hasValidIdToken() {
        if (this.getIdToken()) {
            const expiresAt = this._storage.getItem('id_token_expires_at');
            const now = new Date();
            if (expiresAt && parseInt(expiresAt, 10) < now.getTime()) {
                return false;
            }
            return true;
        }
        return false;
    }
    /**
     * Retrieve a saved custom property of the TokenReponse object. Only if predefined in authconfig.
     */
    getCustomTokenResponseProperty(requestedProperty) {
        return this._storage &&
            this.config.customTokenParameters &&
            this.config.customTokenParameters.indexOf(requestedProperty) >= 0 &&
            this._storage.getItem(requestedProperty) !== null
            ? JSON.parse(this._storage.getItem(requestedProperty))
            : null;
    }
    /**
     * Returns the auth-header that can be used
     * to transmit the access_token to a service
     */
    authorizationHeader() {
        return 'Bearer ' + this.getAccessToken();
    }
    logOut(customParameters = {}, state = '') {
        let noRedirectToLogoutUrl = false;
        if (typeof customParameters === 'boolean') {
            noRedirectToLogoutUrl = customParameters;
            customParameters = {};
        }
        const id_token = this.getIdToken();
        this._storage.removeItem('access_token');
        this._storage.removeItem('id_token');
        this._storage.removeItem('refresh_token');
        if (this.saveNoncesInLocalStorage) {
            localStorage.removeItem('nonce');
            localStorage.removeItem('PKCE_verifier');
        }
        else {
            this._storage.removeItem('nonce');
            this._storage.removeItem('PKCE_verifier');
        }
        this._storage.removeItem('expires_at');
        this._storage.removeItem('id_token_claims_obj');
        this._storage.removeItem('id_token_expires_at');
        this._storage.removeItem('id_token_stored_at');
        this._storage.removeItem('access_token_stored_at');
        this._storage.removeItem('granted_scopes');
        this._storage.removeItem('session_state');
        if (this.config.customTokenParameters) {
            this.config.customTokenParameters.forEach(customParam => this._storage.removeItem(customParam));
        }
        this.silentRefreshSubject = null;
        this.eventsSubject.next(new OAuthInfoEvent('logout'));
        if (!this.logoutUrl) {
            return;
        }
        if (noRedirectToLogoutUrl) {
            return;
        }
        if (!id_token && !this.postLogoutRedirectUri) {
            return;
        }
        let logoutUrl;
        if (!this.validateUrlForHttps(this.logoutUrl)) {
            throw new Error("logoutUrl  must use HTTPS (with TLS), or config value for property 'requireHttps' must be set to 'false' and allow HTTP (without TLS).");
        }
        // For backward compatibility
        if (this.logoutUrl.indexOf('{{') > -1) {
            logoutUrl = this.logoutUrl
                .replace(/\{\{id_token\}\}/, id_token)
                .replace(/\{\{client_id\}\}/, this.clientId);
        }
        else {
            let params = new HttpParams();
            if (id_token) {
                params = params.set('id_token_hint', id_token);
            }
            const postLogoutUrl = this.postLogoutRedirectUri || this.redirectUri;
            if (postLogoutUrl) {
                params = params.set('post_logout_redirect_uri', postLogoutUrl);
                if (state) {
                    params = params.set('state', state);
                }
            }
            for (let key in customParameters) {
                params = params.set(key, customParameters[key]);
            }
            logoutUrl =
                this.logoutUrl +
                    (this.logoutUrl.indexOf('?') > -1 ? '&' : '?') +
                    params.toString();
        }
        this.config.openUri(logoutUrl);
    }
    /**
     * @ignore
     */
    createAndSaveNonce() {
        const that = this;
        return this.createNonce().then(function (nonce) {
            // Use localStorage for nonce if possible
            // localStorage is the only storage who survives a
            // redirect in ALL browsers (also IE)
            // Otherwiese we'd force teams who have to support
            // IE into using localStorage for everything
            if (that.saveNoncesInLocalStorage &&
                typeof window['localStorage'] !== 'undefined') {
                localStorage.setItem('nonce', nonce);
            }
            else {
                that._storage.setItem('nonce', nonce);
            }
            return nonce;
        });
    }
    /**
     * @ignore
     */
    ngOnDestroy() {
        this.clearAccessTokenTimer();
        this.clearIdTokenTimer();
        this.removeSilentRefreshEventListener();
        const silentRefreshFrame = this.document.getElementById(this.silentRefreshIFrameName);
        if (silentRefreshFrame) {
            silentRefreshFrame.remove();
        }
        this.stopSessionCheckTimer();
        this.removeSessionCheckEventListener();
        const sessionCheckFrame = this.document.getElementById(this.sessionCheckIFrameName);
        if (sessionCheckFrame) {
            sessionCheckFrame.remove();
        }
    }
    createNonce() {
        return new Promise(resolve => {
            if (this.rngUrl) {
                throw new Error('createNonce with rng-web-api has not been implemented so far');
            }
            /*
             * This alphabet is from:
             * https://tools.ietf.org/html/rfc7636#section-4.1
             *
             * [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
             */
            const unreserved = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
            let size = 45;
            let id = '';
            const crypto = typeof self === 'undefined' ? null : self.crypto || self['msCrypto'];
            if (crypto) {
                let bytes = new Uint8Array(size);
                crypto.getRandomValues(bytes);
                // Needed for IE
                if (!bytes.map) {
                    bytes.map = Array.prototype.map;
                }
                bytes = bytes.map(x => unreserved.charCodeAt(x % unreserved.length));
                id = String.fromCharCode.apply(null, bytes);
            }
            else {
                while (0 < size--) {
                    id += unreserved[(Math.random() * unreserved.length) | 0];
                }
            }
            resolve(base64UrlEncode(id));
        });
    }
    checkAtHash(params) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!this.tokenValidationHandler) {
                this.logger.warn('No tokenValidationHandler configured. Cannot check at_hash.');
                return true;
            }
            return this.tokenValidationHandler.validateAtHash(params);
        });
    }
    checkSignature(params) {
        if (!this.tokenValidationHandler) {
            this.logger.warn('No tokenValidationHandler configured. Cannot check signature.');
            return Promise.resolve(null);
        }
        return this.tokenValidationHandler.validateSignature(params);
    }
    /**
     * Start the implicit flow or the code flow,
     * depending on your configuration.
     */
    initLoginFlow(additionalState = '', params = {}) {
        if (this.responseType === 'code') {
            return this.initCodeFlow(additionalState, params);
        }
        else {
            return this.initImplicitFlow(additionalState, params);
        }
    }
    /**
     * Starts the authorization code flow and redirects to user to
     * the auth servers login url.
     */
    initCodeFlow(additionalState = '', params = {}) {
        if (this.loginUrl !== '') {
            this.initCodeFlowInternal(additionalState, params);
        }
        else {
            this.events
                .pipe(filter(e => e.type === 'discovery_document_loaded'))
                .subscribe(_ => this.initCodeFlowInternal(additionalState, params));
        }
    }
    initCodeFlowInternal(additionalState = '', params = {}) {
        if (!this.validateUrlForHttps(this.loginUrl)) {
            throw new Error("loginUrl  must use HTTPS (with TLS), or config value for property 'requireHttps' must be set to 'false' and allow HTTP (without TLS).");
        }
        let addParams = {};
        let loginHint = null;
        if (typeof params === 'string') {
            loginHint = params;
        }
        else if (typeof params === 'object') {
            addParams = params;
        }
        this.createLoginUrl(additionalState, loginHint, null, false, addParams)
            .then(this.config.openUri)
            .catch(error => {
            console.error('Error in initAuthorizationCodeFlow');
            console.error(error);
        });
    }
    createChallangeVerifierPairForPKCE() {
        return __awaiter(this, void 0, void 0, function* () {
            if (!this.crypto) {
                throw new Error('PKCE support for code flow needs a CryptoHander. Did you import the OAuthModule using forRoot() ?');
            }
            const verifier = yield this.createNonce();
            const challengeRaw = yield this.crypto.calcHash(verifier, 'sha-256');
            const challenge = base64UrlEncode(challengeRaw);
            return [challenge, verifier];
        });
    }
    extractRecognizedCustomParameters(tokenResponse) {
        let foundParameters = new Map();
        if (!this.config.customTokenParameters) {
            return foundParameters;
        }
        this.config.customTokenParameters.forEach((recognizedParameter) => {
            if (tokenResponse[recognizedParameter]) {
                foundParameters.set(recognizedParameter, JSON.stringify(tokenResponse[recognizedParameter]));
            }
        });
        return foundParameters;
    }
    /**
     * Revokes the auth token to secure the vulnarability
     * of the token issued allowing the authorization server to clean
     * up any security credentials associated with the authorization
     */
    revokeTokenAndLogout(customParameters = {}, ignoreCorsIssues = false) {
        let revokeEndpoint = this.revocationEndpoint;
        let accessToken = this.getAccessToken();
        let refreshToken = this.getRefreshToken();
        if (!accessToken) {
            return;
        }
        let params = new HttpParams();
        let headers = new HttpHeaders().set('Content-Type', 'application/x-www-form-urlencoded');
        if (this.useHttpBasicAuth) {
            const header = btoa(`${this.clientId}:${this.dummyClientSecret}`);
            headers = headers.set('Authorization', 'Basic ' + header);
        }
        if (!this.useHttpBasicAuth) {
            params = params.set('client_id', this.clientId);
        }
        if (!this.useHttpBasicAuth && this.dummyClientSecret) {
            params = params.set('client_secret', this.dummyClientSecret);
        }
        if (this.customQueryParams) {
            for (const key of Object.getOwnPropertyNames(this.customQueryParams)) {
                params = params.set(key, this.customQueryParams[key]);
            }
        }
        return new Promise((resolve, reject) => {
            let revokeAccessToken;
            let revokeRefreshToken;
            if (accessToken) {
                let revokationParams = params
                    .set('token', accessToken)
                    .set('token_type_hint', 'access_token');
                revokeAccessToken = this.http.post(revokeEndpoint, revokationParams, { headers });
            }
            else {
                revokeAccessToken = of(null);
            }
            if (refreshToken) {
                let revokationParams = params
                    .set('token', refreshToken)
                    .set('token_type_hint', 'refresh_token');
                revokeRefreshToken = this.http.post(revokeEndpoint, revokationParams, { headers });
            }
            else {
                revokeRefreshToken = of(null);
            }
            if (ignoreCorsIssues) {
                revokeAccessToken = revokeAccessToken.pipe(catchError((err) => {
                    if (err.status === 0) {
                        return of(null);
                    }
                    return throwError(err);
                }));
                revokeRefreshToken = revokeRefreshToken.pipe(catchError((err) => {
                    if (err.status === 0) {
                        return of(null);
                    }
                    return throwError(err);
                }));
            }
            combineLatest([revokeAccessToken, revokeRefreshToken]).subscribe(res => {
                this.logOut(customParameters);
                resolve(res);
                this.logger.info('Token successfully revoked');
            }, err => {
                this.logger.error('Error revoking token', err);
                this.eventsSubject.next(new OAuthErrorEvent('token_revoke_error', err));
                reject(err);
            });
        });
    }
}
OAuthService.decorators = [
    { type: Injectable }
];
OAuthService.ctorParameters = () => [
    { type: NgZone },
    { type: HttpClient },
    { type: OAuthStorage, decorators: [{ type: Optional }] },
    { type: ValidationHandler, decorators: [{ type: Optional }] },
    { type: AuthConfig, decorators: [{ type: Optional }] },
    { type: UrlHelperService },
    { type: OAuthLogger },
    { type: HashHandler, decorators: [{ type: Optional }] },
    { type: undefined, decorators: [{ type: Inject, args: [DOCUMENT,] }] }
];
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoib2F1dGgtc2VydmljZS5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uLy4uL3Byb2plY3RzL2xpYi9zcmMvb2F1dGgtc2VydmljZS50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiO0FBQUEsT0FBTyxFQUFFLFVBQVUsRUFBRSxNQUFNLEVBQUUsUUFBUSxFQUFhLE1BQU0sRUFBRSxNQUFNLGVBQWUsQ0FBQztBQUNoRixPQUFPLEVBQ0wsVUFBVSxFQUNWLFdBQVcsRUFDWCxVQUFVLEVBRVgsTUFBTSxzQkFBc0IsQ0FBQztBQUM5QixPQUFPLEVBRUwsT0FBTyxFQUVQLEVBQUUsRUFDRixJQUFJLEVBQ0osSUFBSSxFQUNKLGFBQWEsRUFDYixVQUFVLEVBQ1gsTUFBTSxNQUFNLENBQUM7QUFDZCxPQUFPLEVBQ0wsTUFBTSxFQUNOLEtBQUssRUFDTCxLQUFLLEVBQ0wsR0FBRyxFQUNILEdBQUcsRUFDSCxTQUFTLEVBQ1QsWUFBWSxFQUNaLFVBQVUsRUFDWCxNQUFNLGdCQUFnQixDQUFDO0FBQ3hCLE9BQU8sRUFBRSxRQUFRLEVBQUUsTUFBTSxpQkFBaUIsQ0FBQztBQUUzQyxPQUFPLEVBQ0wsaUJBQWlCLEVBRWxCLE1BQU0sdUNBQXVDLENBQUM7QUFDL0MsT0FBTyxFQUFFLGdCQUFnQixFQUFFLE1BQU0sc0JBQXNCLENBQUM7QUFDeEQsT0FBTyxFQUVMLGNBQWMsRUFDZCxlQUFlLEVBQ2YsaUJBQWlCLEVBQ2xCLE1BQU0sVUFBVSxDQUFDO0FBQ2xCLE9BQU8sRUFDTCxXQUFXLEVBQ1gsWUFBWSxFQU1iLE1BQU0sU0FBUyxDQUFDO0FBQ2pCLE9BQU8sRUFBRSxnQkFBZ0IsRUFBRSxlQUFlLEVBQUUsTUFBTSxpQkFBaUIsQ0FBQztBQUNwRSxPQUFPLEVBQUUsVUFBVSxFQUFFLE1BQU0sZUFBZSxDQUFDO0FBQzNDLE9BQU8sRUFBRSx1QkFBdUIsRUFBRSxNQUFNLFdBQVcsQ0FBQztBQUNwRCxPQUFPLEVBQUUsV0FBVyxFQUFFLE1BQU0saUNBQWlDLENB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QUFDLENBQUMsaUJBQWlCLEVBQUUsa0JBQWtCLENBQUMsQ0FBQyxDQUFDLFNBQVMsQ0FDOUQsR0FBRyxDQUFDLEVBQUU7Z0JBQ0osSUFBSSxDQUFDLE1BQU0sQ0FBQyxnQkFBZ0IsQ0FBQyxDQUFDO2dCQUM5QixPQUFPLENBQUMsR0FBRyxDQUFDLENBQUM7Z0JBQ2IsSUFBSSxDQUFDLE1BQU0sQ0FBQyxJQUFJLENBQUMsNEJBQTRCLENBQUMsQ0FBQztZQUNqRCxDQUFDLEVBQ0QsR0FBRyxDQUFDLEVBQUU7Z0JBQ0osSUFBSSxDQUFDLE1BQU0sQ0FBQyxLQUFLLENBQUMsc0JBQXNCLEVBQUUsR0FBRyxDQUFDLENBQUM7Z0JBQy9DLElBQUksQ0FBQyxhQUFhLENBQUMsSUFBSSxDQUNyQixJQUFJLGVBQWUsQ0FBQyxvQkFBb0IsRUFBRSxHQUFHLENBQUMsQ0FDL0MsQ0FBQztnQkFDRixNQUFNLENBQUMsR0FBRyxDQUFDLENBQUM7WUFDZCxDQUFDLENBQ0YsQ0FBQztRQUNKLENBQUMsQ0FBQyxDQUFDO0lBQ0wsQ0FBQzs7O1lBcmxGRixVQUFVOzs7WUEzRFUsTUFBTTtZQUV6QixVQUFVO1lBd0NWLFlBQVksdUJBMEVULFFBQVE7WUF0RlgsaUJBQWlCLHVCQXVGZCxRQUFRO1lBbkVKLFVBQVUsdUJBb0VkLFFBQVE7WUFyRkosZ0JBQWdCO1lBUXZCLFdBQVc7WUFXSixXQUFXLHVCQXFFZixRQUFROzRDQUNSLE1BQU0sU0FBQyxRQUFRIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgSW5qZWN0YWJsZSwgTmdab25lLCBPcHRpb25hbCwgT25EZXN0cm95LCBJbmplY3QgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcbmltcG9ydCB7XG4gIEh0dHBDbGllbnQsXG4gIEh0dHBIZWFkZXJzLFxuICBIdHRwUGFyYW1zLFxuICBIdHRwRXJyb3JSZXNwb25zZVxufSBmcm9tICdAYW5ndWxhci9jb21tb24vaHR0cCc7XG5pbXBvcnQge1xuICBPYnNlcnZhYmxlLFxuICBTdWJqZWN0LFxuICBTdWJzY3JpcHRpb24sXG4gIG9mLFxuICByYWNlLFxuICBmcm9tLFxuICBjb21iaW5lTGF0ZXN0LFxuICB0aHJvd0Vycm9yXG59IGZyb20gJ3J4anMnO1xuaW1wb3J0IHtcbiAgZmlsdGVyLFxuICBkZWxheSxcbiAgZmlyc3QsXG4gIHRhcCxcbiAgbWFwLFxuICBzd2l0Y2hNYXAsXG4gIGRlYm91bmNlVGltZSxcbiAgY2F0Y2hFcnJvclxufSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XG5pbXBvcnQgeyBET0NVTUVOVCB9IGZyb20gJ0Bhbmd1bGFyL2NvbW1vbic7XG5cbmltcG9ydCB7XG4gIFZhbGlkYXRpb25IYW5kbGVyLFxuICBWYWxpZGF0aW9uUGFyYW1zXG59IGZyb20gJy4vdG9rZW4tdmFsaWRhdGlvbi92YWxpZGF0aW9uLWhhbmRsZXInO1xuaW1wb3J0IHsgVXJsSGVscGVyU2VydmljZSB9IGZyb20gJy4vdXJsLWhlbHBlci5zZXJ2aWNlJztcbmltcG9ydCB7XG4gIE9BdXRoRXZlbnQsXG4gIE9BdXRoSW5mb0V2ZW50LFxuICBPQXV0aEVycm9yRXZlbnQsXG4gIE9BdXRoU3VjY2Vzc0V2ZW50XG59IGZyb20gJy4vZXZlbnRzJztcbmltcG9ydCB7XG4gIE9BdXRoTG9nZ2VyLFxuICBPQXV0aFN0b3JhZ2UsXG4gIExvZ2luT3B0aW9ucyxcbiAgUGFyc2VkSWRUb2tlbixcbiAgT2lkY0Rpc2NvdmVyeURvYyxcbiAgVG9rZW5SZXNwb25zZSxcbiAgVXNlckluZm9cbn0gZnJvbSAnLi90eXBlcyc7XG5pbXBvcnQgeyBiNjREZWNvZGVVbmljb2RlLCBiYXNlNjRVcmxFbmNvZGUgfSBmcm9tICcuL2Jhc2U2NC1oZWxwZXInO1xuaW1wb3J0IHsgQXV0aENvbmZpZyB9IGZyb20gJy4vYXV0aC5jb25maWcnO1xuaW1wb3J0IHsgV2ViSHR0cFVybEVuY29kaW5nQ29kZWMgfSBmcm9tICcuL2VuY29kZXInO1xuaW1wb3J0IHsgSGFzaEhhbmRsZXIgfSBmcm9tICcuL3Rva2VuLXZhbGlkYXRpb24vaGFzaC1oYW5kbGVyJztcblxuLyoqXG4gKiBTZXJ2aWNlIGZvciBsb2dnaW5nIGluIGFuZCBsb2dnaW5nIG91dCB3aXRoXG4gKiBPSURDIGFuZCBPQXV0aDIuIFN1cHBvcnRzIGltcGxpY2l0IGZsb3cgYW5kXG4gKiBwYXNzd29yZCBmbG93LlxuICovXG5ASW5qZWN0YWJsZSgpXG5leHBvcnQgY2xhc3MgT0F1dGhTZXJ2aWNlIGV4dGVuZHMgQXV0aENvbmZpZyBpbXBsZW1lbnRzIE9uRGVzdHJveSB7XG4gIC8vIEV4dGVuZGluZyBBdXRoQ29uZmlnIGlzdCBqdXN0IGZvciBMRUdBQ1kgcmVhc29uc1xuICAvLyB0byBub3QgYnJlYWsgZXhpc3RpbmcgY29kZS5cblxuICAvKipcbiAgICogVGhlIFZhbGlkYXRpb25IYW5kbGVyIHVzZWQgdG8gdmFsaWRhdGUgcmVjZWl2ZWRcbiAgICogaWRfdG9rZW5zLlxuICAgKi9cbiAgcHVibGljIHRva2VuVmFsaWRhdGlvbkhhbmRsZXI6IFZhbGlkYXRpb25IYW5kbGVyO1xuXG4gIC8qKlxuICAgKiBAaW50ZXJuYWxcbiAgICogRGVwcmVjYXRlZDogIHVzZSBwcm9wZXJ0eSBldmVudHMgaW5zdGVhZFxuICAgKi9cbiAgcHVibGljIGRpc2NvdmVyeURvY3VtZW50TG9hZGVkID0gZmFsc2U7XG5cbiAgLyoqXG4gICAqIEBpbnRlcm5hbFxuICAgKiBEZXByZWNhdGVkOiAgdXNlIHByb3BlcnR5IGV2ZW50cyBpbnN0ZWFkXG4gICAqL1xuICBwdWJsaWMgZGlzY292ZXJ5RG9jdW1lbnRMb2FkZWQkOiBPYnNlcnZhYmxlPE9pZGNEaXNjb3ZlcnlEb2M+O1xuXG4gIC8qKlxuICAgKiBJbmZvcm1zIGFib3V0IGV2ZW50cywgbGlrZSB0b2tlbl9yZWNlaXZlZCBvciB0b2tlbl9leHBpcmVzLlxuICAgKiBTZWUgdGhlIHN0cmluZyBlbnVtIEV2ZW50VHlwZSBmb3IgYSBmdWxsIGxpc3Qgb2YgZXZlbnQgdHlwZXMuXG4gICAqL1xuICBwdWJsaWMgZXZlbnRzOiBPYnNlcnZhYmxlPE9BdXRoRXZlbnQ+O1xuXG4gIC8qKlxuICAgKiBUaGUgcmVjZWl2ZWQgKHBhc3NlZCBhcm91bmQpIHN0YXRlLCB3aGVuIGxvZ2dpbmdcbiAgICogaW4gd2l0aCBpbXBsaWNpdCBmbG93LlxuICAgKi9cbiAgcHVibGljIHN0YXRlPyA9ICcnO1xuXG4gIHByb3RlY3RlZCBldmVudHNTdWJqZWN0OiBTdWJqZWN0PE9BdXRoRXZlbnQ+ID0gbmV3IFN1YmplY3Q8T0F1dGhFdmVudD4oKTtcbiAgcHJvdGVjdGVkIGRpc2NvdmVyeURvY3VtZW50TG9hZGVkU3ViamVjdDogU3ViamVjdDxcbiAgICBPaWRjRGlzY292ZXJ5RG9jXG4gID4gPSBuZXcgU3ViamVjdDxPaWRjRGlzY292ZXJ5RG9jPigpO1xuICBwcm90ZWN0ZWQgc2lsZW50UmVmcmVzaFBvc3RNZXNzYWdlRXZlbnRMaXN0ZW5lcjogRXZlbnRMaXN0ZW5lcjtcbiAgcHJvdGVjdGVkIGdyYW50VHlwZXNTdXBwb3J0ZWQ6IEFycmF5PHN0cmluZz4gPSBbXTtcbiAgcHJvdGVjdGVkIF9zdG9yYWdlOiBPQXV0aFN0b3JhZ2U7XG4gIHByb3RlY3RlZCBhY2Nlc3NUb2tlblRpbWVvdXRTdWJzY3JpcHRpb246IFN1YnNjcmlwdGlvbjtcbiAgcHJvdGVjdGVkIGlkVG9rZW5UaW1lb3V0U3Vic2NyaXB0aW9uOiBTdWJzY3JpcHRpb247XG4gIHByb3RlY3RlZCB0b2tlblJlY2VpdmVkU3Vic2NyaXB0aW9uOiBTdWJzY3JpcHRpb247XG4gIHByb3RlY3RlZCBzZXNzaW9uQ2hlY2tFdmVudExpc3RlbmVyOiBFdmVudExpc3RlbmVyO1xuICBwcm90ZWN0ZWQgandrc1VyaTogc3RyaW5nO1xuICBwcm90ZWN0ZWQgc2Vzc2lvbkNoZWNrVGltZXI6IGFueTtcbiAgcHJvdGVjdGVkIHNpbGVudFJlZnJlc2hTdWJqZWN0OiBzdHJpbmc7XG4gIHByb3RlY3RlZCBpbkltcGxpY2l0RmxvdyA9IGZhbHNlO1xuXG4gIHByb3RlY3RlZCBzYXZlTm9uY2VzSW5Mb2NhbFN0b3JhZ2UgPSBmYWxzZTtcbiAgcHJpdmF0ZSBkb2N1bWVudDogRG9jdW1lbnQ7XG5cbiAgY29uc3RydWN0b3IoXG4gICAgcHJvdGVjdGVkIG5nWm9uZTogTmdab25lLFxuICAgIHByb3RlY3RlZCBodHRwOiBIdHRwQ2xpZW50LFxuICAgIEBPcHRpb25hbCgpIHN0b3JhZ2U6IE9BdXRoU3RvcmFnZSxcbiAgICBAT3B0aW9uYWwoKSB0b2tlblZhbGlkYXRpb25IYW5kbGVyOiBWYWxpZGF0aW9uSGFuZGxlcixcbiAgICBAT3B0aW9uYWwoKSBwcm90ZWN0ZWQgY29uZmlnOiBBdXRoQ29uZmlnLFxuICAgIHByb3RlY3RlZCB1cmxIZWxwZXI6IFVybEhlbHBlclNlcnZpY2UsXG4gICAgcHJvdGVjdGVkIGxvZ2dlcjogT0F1dGhMb2dnZXIsXG4gICAgQE9wdGlvbmFsKCkgcHJvdGVjdGVkIGNyeXB0bzogSGFzaEhhbmRsZXIsXG4gICAgQEluamVjdChET0NVTUVOVCkgZG9jdW1lbnQ6IGFueVxuICApIHtcbiAgICBzdXBlcigpO1xuXG4gICAgdGhpcy5kZWJ1ZygnYW5ndWxhci1vYXV0aDItb2lkYyB2OC1iZXRhJyk7XG5cbiAgICAvLyBTZWUgaHR0cHM6Ly9naXRodWIuY29tL21hbmZyZWRzdGV5ZXIvYW5ndWxhci1vYXV0aDItb2lkYy9pc3N1ZXMvNzczIGZvciB3aHkgdGhpcyBpcyBuZWVkZWRcbiAgICB0aGlzLmRvY3VtZW50ID0gZG9jdW1lbnQ7XG5cbiAgICB0aGlzLmRpc2NvdmVyeURvY3VtZW50TG9hZGVkJCA9IHRoaXMuZGlzY292ZXJ5RG9jdW1lbnRMb2FkZWRTdWJqZWN0LmFzT2JzZXJ2YWJsZSgpO1xuICAgIHRoaXMuZXZlbnRzID0gdGhpcy5ldmVudHNTdWJqZWN0LmFzT2JzZXJ2YWJsZSgpO1xuXG4gICAgaWYgKHRva2VuVmFsaWRhdGlvbkhhbmRsZXIpIHtcbiAgICAgIHRoaXMudG9rZW5WYWxpZGF0aW9uSGFuZGxlciA9IHRva2VuVmFsaWRhdGlvbkhhbmRsZXI7XG4gICAgfVxuXG4gICAgaWYgKGNvbmZpZykge1xuICAgICAgdGhpcy5jb25maWd1cmUoY29uZmlnKTtcbiAgICB9XG5cbiAgICB0cnkge1xuICAgICAgaWYgKHN0b3JhZ2UpIHtcbiAgICAgICAgdGhpcy5zZXRTdG9yYWdlKHN0b3JhZ2UpO1xuICAgICAgfSBlbHNlIGlmICh0eXBlb2Ygc2Vzc2lvblN0b3JhZ2UgIT09ICd1bmRlZmluZWQnKSB7XG4gICAgICAgIHRoaXMuc2V0U3RvcmFnZShzZXNzaW9uU3RvcmFnZSk7XG4gICAgICB9XG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgY29uc29sZS5lcnJvcihcbiAgICAgICAgJ05vIE9BdXRoU3RvcmFnZSBwcm92aWRlZCBhbmQgY2Fubm90IGFjY2VzcyBkZWZhdWx0IChzZXNzaW9uU3RvcmFnZSkuJyArXG4gICAgICAgICAgJ0NvbnNpZGVyIHByb3ZpZGluZyBhIGN1c3RvbSBPQXV0aFN0b3JhZ2UgaW1wbGVtZW50YXRpb24gaW4geW91ciBtb2R1bGUuJyxcbiAgICAgICAgZVxuICAgICAgKTtcbiAgICB9XG5cbiAgICAvLyBpbiBJRSwgc2Vzc2lvblN0b3JhZ2UgZG9lcyBub3QgYWx3YXlzIHN1cnZpdmUgYSByZWRpcmVjdFxuICAgIGlmIChcbiAgICAgIHR5cGVvZiB3aW5kb3cgIT09ICd1bmRlZmluZWQnICYmXG4gICAgICB0eXBlb2Ygd2luZG93Wydsb2NhbFN0b3JhZ2UnXSAhPT0gJ3VuZGVmaW5lZCdcbiAgICApIHtcbiAgICAgIGNvbnN0IHVhID0gd2luZG93Py5uYXZpZ2F0b3I/LnVzZXJBZ2VudDtcbiAgICAgIGNvbnN0IG1zaWUgPSB1YT8uaW5jbHVkZXMoJ01TSUUgJykgfHwgdWE/LmluY2x1ZGVzKCdUcmlkZW50Jyk7XG5cbiAgICAgIGlmIChtc2llKSB7XG4gICAgICAgIHRoaXMuc2F2ZU5vbmNlc0luTG9jYWxTdG9yYWdlID0gdHJ1ZTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICB0aGlzLnNldHVwUmVmcmVzaFRpbWVyKCk7XG4gIH1cblxuICAvKipcbiAgICogVXNlIHRoaXMgbWV0aG9kIHRvIGNvbmZpZ3VyZSB0aGUgc2VydmljZVxuICAgKiBAcGFyYW0gY29uZmlnIHRoZSBjb25maWd1cmF0aW9uXG4gICAqL1xuICBwdWJsaWMgY29uZmlndXJlKGNvbmZpZzogQXV0aENvbmZpZyk6IHZvaWQge1xuICAgIC8vIEZvciB0aGUgc2FrZSBvZiBkb3dud2FyZCBjb21wYXRpYmlsaXR5IHdpdGhcbiAgICAvLyBvcmlnaW5hbCBjb25maWd1cmF0aW9uIEFQSVxuICAgIE9iamVjdC5hc3NpZ24odGhpcywgbmV3IEF1dGhDb25maWcoKSwgY29uZmlnKTtcblxuICAgIHRoaXMuY29uZmlnID0gT2JqZWN0LmFzc2lnbih7fSBhcyBBdXRoQ29uZmlnLCBuZXcgQXV0aENvbmZpZygpLCBjb25maWcpO1xuXG4gICAgaWYgKHRoaXMuc2Vzc2lvbkNoZWNrc0VuYWJsZWQpIHtcbiAgICAgIHRoaXMuc2V0dXBTZXNzaW9uQ2hlY2soKTtcbiAgICB9XG5cbiAgICB0aGlzLmNvbmZpZ0NoYW5nZWQoKTtcbiAgfVxuXG4gIHByb3RlY3RlZCBjb25maWdDaGFuZ2VkKCk6IHZvaWQge1xuICAgIHRoaXMuc2V0dXBSZWZyZXNoVGltZXIoKTtcbiAgfVxuXG4gIHB1YmxpYyByZXN0YXJ0U2Vzc2lvbkNoZWNrc0lmU3RpbGxMb2dnZWRJbigpOiB2b2lkIHtcbiAgICBpZiAodGhpcy5oYXNWYWxpZElkVG9rZW4oKSkge1xuICAgICAgdGhpcy5pbml0U2Vzc2lvbkNoZWNrKCk7XG4gICAgfVxuICB9XG5cbiAgcHJvdGVjdGVkIHJlc3RhcnRSZWZyZXNoVGltZXJJZlN0aWxsTG9nZ2VkSW4oKTogdm9pZCB7XG4gICAgdGhpcy5zZXR1cEV4cGlyYXRpb25UaW1lcnMoKTtcbiAgfVxuXG4gIHByb3RlY3RlZCBzZXR1cFNlc3Npb25DaGVjaygpOiB2b2lkIHtcbiAgICB0aGlzLmV2ZW50cy5waXBlKGZpbHRlcihlID0+IGUudHlwZSA9PT0gJ3Rva2VuX3JlY2VpdmVkJykpLnN1YnNjcmliZShlID0+IHtcbiAgICAgIHRoaXMuaW5pdFNlc3Npb25DaGVjaygpO1xuICAgIH0pO1xuICB9XG5cbiAgLyoqXG4gICAqIFdpbGwgc2V0dXAgdXAgc2lsZW50IHJlZnJlc2hpbmcgZm9yIHdoZW4gdGhlIHRva2VuIGlzXG4gICAqIGFib3V0IHRvIGV4cGlyZS4gV2hlbiB0aGUgdXNlciBpcyBsb2dnZWQgb3V0IHZpYSB0aGlzLmxvZ091dCBtZXRob2QsIHRoZVxuICAgKiBzaWxlbnQgcmVmcmVzaGluZyB3aWxsIHBhdXNlIGFuZCBub3QgcmVmcmVzaCB0aGUgdG9rZW5zIHVudGlsIHRoZSB1c2VyIGlzXG4gICAqIGxvZ2dlZCBiYWNrIGluIHZpYSByZWNlaXZpbmcgYSBuZXcgdG9rZW4uXG4gICAqIEBwYXJhbSBwYXJhbXMgQWRkaXRpb25hbCBwYXJhbWV0ZXIgdG8gcGFzc1xuICAgKiBAcGFyYW0gbGlzdGVuVG8gU2V0dXAgYXV0b21hdGljIHJlZnJlc2ggb2YgYSBzcGVjaWZpYyB0b2tlbiB0eXBlXG4gICAqL1xuICBwdWJsaWMgc2V0dXBBdXRvbWF0aWNTaWxlbnRSZWZyZXNoKFxuICAgIHBhcmFtczogb2JqZWN0ID0ge30sXG4gICAgbGlzdGVuVG8/OiAnYWNjZXNzX3Rva2VuJyB8ICdpZF90b2tlbicgfCAnYW55JyxcbiAgICBub1Byb21wdCA9IHRydWVcbiAgKTogdm9pZCB7XG4gICAgbGV0IHNob3VsZFJ1blNpbGVudFJlZnJlc2ggPSB0cnVlO1xuICAgIHRoaXMuZXZlbnRzXG4gICAgICAucGlwZShcbiAgICAgICAgdGFwKGUgPT4ge1xuICAgICAgICAgIGlmIChlLnR5cGUgPT09ICd0b2tlbl9yZWNlaXZlZCcpIHtcbiAgICAgICAgICAgIHNob3VsZFJ1blNpbGVudFJlZnJlc2ggPSB0cnVlO1xuICAgICAgICAgIH0gZWxzZSBpZiAoZS50eXBlID09PSAnbG9nb3V0Jykge1xuICAgICAgICAgICAgc2hvdWxkUnVuU2lsZW50UmVmcmVzaCA9IGZhbHNlO1xuICAgICAgICAgIH1cbiAgICAgICAgfSksXG4gICAgICAgIGZpbHRlcihlID0+IGUudHlwZSA9PT0gJ3Rva2VuX2V4cGlyZXMnKSxcbiAgICAgICAgZGVib3VuY2VUaW1lKDEwMDApXG4gICAgICApXG4gICAgICAuc3Vic2NyaWJlKGUgPT4ge1xuICAgICAgICBjb25zdCBldmVudCA9IGUgYXMgT0F1dGhJbmZvRXZlbnQ7XG4gICAgICAgIGlmIChcbiAgICAgICAgICAobGlzdGVuVG8gPT0gbnVsbCB8fCBsaXN0ZW5UbyA9PT0gJ2FueScgfHwgZXZlbnQuaW5mbyA9PT0gbGlzdGVuVG8pICYmXG4gICAgICAgICAgc2hvdWxkUnVuU2lsZW50UmVmcmVzaFxuICAgICAgICApIHtcbiAgICAgICAgICAvLyB0aGlzLnNpbGVudFJlZnJlc2gocGFyYW1zLCBub1Byb21wdCkuY2F0Y2goXyA9PiB7XG4gICAgICAgICAgdGhpcy5yZWZyZXNoSW50ZXJuYWwocGFyYW1zLCBub1Byb21wdCkuY2F0Y2goXyA9PiB7XG4gICAgICAgICAgICB0aGlzLmRlYnVnKCdBdXRvbWF0aWMgc2lsZW50IHJlZnJlc2ggZGlkIG5vdCB3b3JrJyk7XG4gICAgICAgICAgfSk7XG4gICAgICAgIH1cbiAgICAgIH0pO1xuXG4gICAgdGhpcy5yZXN0YXJ0UmVmcmVzaFRpbWVySWZTdGlsbExvZ2dlZEluKCk7XG4gIH1cblxuICBwcm90ZWN0ZWQgcmVmcmVzaEludGVybmFsKFxuICAgIHBhcmFtcyxcbiAgICBub1Byb21wdFxuICApOiBQcm9taXNlPFRva2VuUmVzcG9uc2UgfCBPQXV0aEV2ZW50PiB7XG4gICAgaWYgKCF0aGlzLnVzZVNpbGVudFJlZnJlc2ggJiYgdGhpcy5yZXNwb25zZVR5cGUgPT09ICdjb2RlJykge1xuICAgICAgcmV0dXJuIHRoaXMucmVmcmVzaFRva2VuKCk7XG4gICAgfSBlbHNlIHtcbiAgICAgIHJldHVybiB0aGlzLnNpbGVudFJlZnJlc2gocGFyYW1zLCBub1Byb21wdCk7XG4gICAgfVxuICB9XG5cbiAgLyoqXG4gICAqIENvbnZlbmllbmNlIG1ldGhvZCB0aGF0IGZpcnN0IGNhbGxzIGBsb2FkRGlzY292ZXJ5RG9jdW1lbnQoLi4uKWAgYW5kXG4gICAqIGRpcmVjdGx5IGNoYWlucyB1c2luZyB0aGUgYHRoZW4oLi4uKWAgcGFydCBvZiB0aGUgcHJvbWlzZSB0byBjYWxsXG4gICAqIHRoZSBgdHJ5TG9naW4oLi4uKWAgbWV0aG9kLlxuICAgKlxuICAgKiBAcGFyYW0gb3B0aW9ucyBMb2dpbk9wdGlvbnMgdG8gcGFzcyB0aHJvdWdoIHRvIGB0cnlMb2dpbiguLi4pYFxuICAgKi9cbiAgcHVibGljIGxvYWREaXNjb3ZlcnlEb2N1bWVudEFuZFRyeUxvZ2luKFxuICAgIG9wdGlvbnM6IExvZ2luT3B0aW9ucyA9IG51bGxcbiAgKTogUHJvbWlzZTxib29sZWFuPiB7XG4gICAgcmV0dXJuIHRoaXMubG9hZERpc2NvdmVyeURvY3VtZW50KCkudGhlbihkb2MgPT4ge1xuICAgICAgcmV0dXJuIHRoaXMudHJ5TG9naW4ob3B0aW9ucyk7XG4gICAgfSk7XG4gIH1cblxuICAvKipcbiAgICogQ29udmVuaWVuY2UgbWV0aG9kIHRoYXQgZmlyc3QgY2FsbHMgYGxvYWREaXNjb3ZlcnlEb2N1bWVudEFuZFRyeUxvZ2luKC4uLilgXG4gICAqIGFuZCBpZiB0aGVuIGNoYWlucyB0byBgaW5pdExvZ2luRmxvdygpYCwgYnV0IG9ubHkgaWYgdGhlcmUgaXMgbm8gdmFsaWRcbiAgICogSWRUb2tlbiBvciBubyB2YWxpZCBBY2Nlc3NUb2tlbi5cbiAgICpcbiAgICogQHBhcmFtIG9wdGlvbnMgTG9naW5PcHRpb25zIHRvIHBhc3MgdGhyb3VnaCB0byBgdHJ5TG9naW4oLi4uKWBcbiAgICovXG4gIHB1YmxpYyBsb2FkRGlzY292ZXJ5RG9jdW1lbnRBbmRMb2dpbihcbiAgICBvcHRpb25zOiBMb2dpbk9wdGlvbnMgJiB7IHN0YXRlPzogc3RyaW5nIH0gPSBudWxsXG4gICk6IFByb21pc2U8Ym9vbGVhbj4ge1xuICAgIG9wdGlvbnMgPSBvcHRpb25zIHx8IHt9O1xuICAgIHJldHVybiB0aGlzLmxvYWREaXNjb3ZlcnlEb2N1bWVudEFuZFRyeUxvZ2luKG9wdGlvbnMpLnRoZW4oXyA9PiB7XG4gICAgICBpZiAoIXRoaXMuaGFzVmFsaWRJZFRva2VuKCkgfHwgIXRoaXMuaGFzVmFsaWRBY2Nlc3NUb2tlbigpKSB7XG4gICAgICAgIGNvbnN0IHN0YXRlID0gdHlwZW9mIG9wdGlvbnMuc3RhdGUgPT09ICdzdHJpbmcnID8gb3B0aW9ucy5zdGF0ZSA6ICcnO1xuICAgICAgICB0aGlzLmluaXRMb2dpbkZsb3coc3RhdGUpO1xuICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgIH1cbiAgICB9KTtcbiAgfVxuXG4gIHByb3RlY3RlZCBkZWJ1ZyguLi5hcmdzKTogdm9pZCB7XG4gICAgaWYgKHRoaXMuc2hvd0RlYnVnSW5mb3JtYXRpb24pIHtcbiAgICAgIHRoaXMubG9nZ2VyLmRlYnVnLmFwcGx5KHRoaXMubG9nZ2VyLCBhcmdzKTtcbiAgICB9XG4gIH1cblxuICBwcm90ZWN0ZWQgdmFsaWRhdGVVcmxGcm9tRGlzY292ZXJ5RG9jdW1lbnQodXJsOiBzdHJpbmcpOiBzdHJpbmdbXSB7XG4gICAgY29uc3QgZXJyb3JzOiBzdHJpbmdbXSA9IFtdO1xuICAgIGNvbnN0IGh0dHBzQ2hlY2sgPSB0aGlzLnZhbGlkYXRlVXJsRm9ySHR0cHModXJsKTtcbiAgICBjb25zdCBpc3N1ZXJDaGVjayA9IHRoaXMudmFsaWRhdGVVcmxBZ2FpbnN0SXNzdWVyKHVybCk7XG5cbiAgICBpZiAoIWh0dHBzQ2hlY2spIHtcbiAgICAgIGVycm9ycy5wdXNoKFxuICAgICAgICAnaHR0cHMgZm9yIGFsbCB1cmxzIHJlcXVpcmVkLiBBbHNvIGZvciB1cmxzIHJlY2VpdmVkIGJ5IGRpc2NvdmVyeS4nXG4gICAgICApO1xuICAgIH1cblxuICAgIGlmICghaXNzdWVyQ2hlY2spIHtcbiAgICAgIGVycm9ycy5wdXNoKFxuICAgICAgICAnRXZlcnkgdXJsIGluIGRpc2NvdmVyeSBkb2N1bWVudCBoYXMgdG8gc3RhcnQgd2l0aCB0aGUgaXNzdWVyIHVybC4nICtcbiAgICAgICAgICAnQWxzbyBzZWUgcHJvcGVydHkgc3RyaWN0RGlzY292ZXJ5RG9jdW1lbnRWYWxpZGF0aW9uLidcbiAgICAgICk7XG4gICAgfVxuXG4gICAgcmV0dXJuIGVycm9ycztcbiAgfVxuXG4gIHByb3RlY3RlZCB2YWxpZGF0ZVVybEZvckh0dHBzKHVybDogc3RyaW5nKTogYm9vbGVhbiB7XG4gICAgaWYgKCF1cmwpIHtcbiAgICAgIHJldHVybiB0cnVlO1xuICAgIH1cblxuICAgIGNvbnN0IGxjVXJsID0gdXJsLnRvTG93ZXJDYXNlKCk7XG5cbiAgICBpZiAodGhpcy5yZXF1aXJlSHR0cHMgPT09IGZhbHNlKSB7XG4gICAgICByZXR1cm4gdHJ1ZTtcbiAgICB9XG5cbiAgICBpZiAoXG4gICAgICAobGNVcmwubWF0Y2goL15odHRwOlxcL1xcL2xvY2FsaG9zdCgkfFs6XFwvXSkvKSB8fFxuICAgICAgICBsY1VybC5tYXRjaCgvXmh0dHA6XFwvXFwvbG9jYWxob3N0KCR8WzpcXC9dKS8pKSAmJlxuICAgICAgdGhpcy5yZXF1aXJlSHR0cHMgPT09ICdyZW1vdGVPbmx5J1xuICAgICkge1xuICAgICAgcmV0dXJuIHRydWU7XG4gICAgfVxuXG4gICAgcmV0dXJuIGxjVXJsLnN0YXJ0c1dpdGgoJ2h0dHBzOi8vJyk7XG4gIH1cblxuICBwcm90ZWN0ZWQgYXNzZXJ0VXJsTm90TnVsbEFuZENvcnJlY3RQcm90b2NvbChcbiAgICB1cmw6IHN0cmluZyB8IHVuZGVmaW5lZCxcbiAgICBkZXNjcmlwdGlvbjogc3RyaW5nXG4gICkge1xuICAgIGlmICghdXJsKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoYCcke2Rlc2NyaXB0aW9ufScgc2hvdWxkIG5vdCBiZSBudWxsYCk7XG4gICAgfVxuICAgIGlmICghdGhpcy52YWxpZGF0ZVVybEZvckh0dHBzKHVybCkpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcihcbiAgICAgICAgYCcke2Rlc2NyaXB0aW9ufScgbXVzdCB1c2UgSFRUUFMgKHdpdGggVExTKSwgb3IgY29uZmlnIHZhbHVlIGZvciBwcm9wZXJ0eSAncmVxdWlyZUh0dHBzJyBtdXN0IGJlIHNldCB0byAnZmFsc2UnIGFuZCBhbGxvdyBIVFRQICh3aXRob3V0IFRMUykuYFxuICAgICAgKTtcbiAgICB9XG4gIH1cblxuICBwcm90ZWN0ZWQgdmFsaWRhdGVVcmxBZ2FpbnN0SXNzdWVyKHVybDogc3RyaW5nKSB7XG4gICAgaWYgKCF0aGlzLnN0cmljdERpc2NvdmVyeURvY3VtZW50VmFsaWRhdGlvbikge1xuICAgICAgcmV0dXJuIHRydWU7XG4gICAgfVxuICAgIGlmICghdXJsKSB7XG4gICAgICByZXR1cm4gdHJ1ZTtcbiAgICB9XG4gICAgcmV0dXJuIHVybC50b0xvd2VyQ2FzZSgpLnN0YXJ0c1dpdGgodGhpcy5pc3N1ZXIudG9Mb3dlckNhc2UoKSk7XG4gIH1cblxuICBwcm90ZWN0ZWQgc2V0dXBSZWZyZXNoVGltZXIoKTogdm9pZCB7XG4gICAgaWYgKHR5cGVvZiB3aW5kb3cgPT09ICd1bmRlZmluZWQnKSB7XG4gICAgICB0aGlzLmRlYnVnKCd0aW1lciBub3Qgc3VwcG9ydGVkIG9uIHRoaXMgcGxhdHRmb3JtJyk7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgaWYgKHRoaXMuaGFzVmFsaWRJZFRva2VuKCkgfHwgdGhpcy5oYXNWYWxpZEFjY2Vzc1Rva2VuKCkpIHtcbiAgICAgIHRoaXMuY2xlYXJBY2Nlc3NUb2tlblRpbWVyKCk7XG4gICAgICB0aGlzLmNsZWFySWRUb2tlblRpbWVyKCk7XG4gICAgICB0aGlzLnNldHVwRXhwaXJhdGlvblRpbWVycygpO1xuICAgIH1cblxuICAgIGlmICh0aGlzLnRva2VuUmVjZWl2ZWRTdWJzY3JpcHRpb24pXG4gICAgICB0aGlzLnRva2VuUmVjZWl2ZWRTdWJzY3JpcHRpb24udW5zdWJzY3JpYmUoKTtcblxuICAgIHRoaXMudG9rZW5SZWNlaXZlZFN1YnNjcmlwdGlvbiA9IHRoaXMuZXZlbnRzXG4gICAgICAucGlwZShmaWx0ZXIoZSA9PiBlLnR5cGUgPT09ICd0b2tlbl9yZWNlaXZlZCcpKVxuICAgICAgLnN1YnNjcmliZShfID0+IHtcbiAgICAgICAgdGhpcy5jbGVhckFjY2Vzc1Rva2VuVGltZXIoKTtcbiAgICAgICAgdGhpcy5jbGVhcklkVG9rZW5UaW1lcigpO1xuICAgICAgICB0aGlzLnNldHVwRXhwaXJhdGlvblRpbWVycygpO1xuICAgICAgfSk7XG4gIH1cblxuICBwcm90ZWN0ZWQgc2V0dXBFeHBpcmF0aW9uVGltZXJzKCk6IHZvaWQge1xuICAgIGlmICh0aGlzLmhhc1ZhbGlkQWNjZXNzVG9rZW4oKSkge1xuICAgICAgdGhpcy5zZXR1cEFjY2Vzc1Rva2VuVGltZXIoKTtcbiAgICB9XG5cbiAgICBpZiAodGhpcy5oYXNWYWxpZElkVG9rZW4oKSkge1xuICAgICAgdGhpcy5zZXR1cElkVG9rZW5UaW1lcigpO1xuICAgIH1cbiAgfVxuXG4gIHByb3RlY3RlZCBzZXR1cEFjY2Vzc1Rva2VuVGltZXIoKTogdm9pZCB7XG4gICAgY29uc3QgZXhwaXJhdGlvbiA9IHRoaXMuZ2V0QWNjZXNzVG9rZW5FeHBpcmF0aW9uKCk7XG4gICAgY29uc3Qgc3RvcmVkQXQgPSB0aGlzLmdldEFjY2Vzc1Rva2VuU3RvcmVkQXQoKTtcbiAgICBjb25zdCB0aW1lb3V0ID0gdGhpcy5jYWxjVGltZW91dChzdG9yZWRBdCwgZXhwaXJhdGlvbik7XG5cbiAgICB0aGlzLm5nWm9uZS5ydW5PdXRzaWRlQW5ndWxhcigoKSA9PiB7XG4gICAgICB0aGlzLmFjY2Vzc1Rva2VuVGltZW91dFN1YnNjcmlwdGlvbiA9IG9mKFxuICAgICAgICBuZXcgT0F1dGhJbmZvRXZlbnQoJ3Rva2VuX2V4cGlyZXMnLCAnYWNjZXNzX3Rva2VuJylcbiAgICAgIClcbiAgICAgICAgLnBpcGUoZGVsYXkodGltZW91dCkpXG4gICAgICAgIC5zdWJzY3JpYmUoZSA9PiB7XG4gICAgICAgICAgdGhpcy5uZ1pvbmUucnVuKCgpID0+IHtcbiAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KGUpO1xuICAgICAgICAgIH0pO1xuICAgICAgICB9KTtcbiAgICB9KTtcbiAgfVxuXG4gIHByb3RlY3RlZCBzZXR1cElkVG9rZW5UaW1lcigpOiB2b2lkIHtcbiAgICBjb25zdCBleHBpcmF0aW9uID0gdGhpcy5nZXRJZFRva2VuRXhwaXJhdGlvbigpO1xuICAgIGNvbnN0IHN0b3JlZEF0ID0gdGhpcy5nZXRJZFRva2VuU3RvcmVkQXQoKTtcbiAgICBjb25zdCB0aW1lb3V0ID0gdGhpcy5jYWxjVGltZW91dChzdG9yZWRBdCwgZXhwaXJhdGlvbik7XG5cbiAgICB0aGlzLm5nWm9uZS5ydW5PdXRzaWRlQW5ndWxhcigoKSA9PiB7XG4gICAgICB0aGlzLmlkVG9rZW5UaW1lb3V0U3Vic2NyaXB0aW9uID0gb2YoXG4gICAgICAgIG5ldyBPQXV0aEluZm9FdmVudCgndG9rZW5fZXhwaXJlcycsICdpZF90b2tlbicpXG4gICAgICApXG4gICAgICAgIC5waXBlKGRlbGF5KHRpbWVvdXQpKVxuICAgICAgICAuc3Vic2NyaWJlKGUgPT4ge1xuICAgICAgICAgIHRoaXMubmdab25lLnJ1bigoKSA9PiB7XG4gICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChlKTtcbiAgICAgICAgICB9KTtcbiAgICAgICAgfSk7XG4gICAgfSk7XG4gIH1cblxuICAvKipcbiAgICogU3RvcHMgdGltZXJzIGZvciBhdXRvbWF0aWMgcmVmcmVzaC5cbiAgICogVG8gcmVzdGFydCBpdCwgY2FsbCBzZXR1cEF1dG9tYXRpY1NpbGVudFJlZnJlc2ggYWdhaW4uXG4gICAqL1xuICBwdWJsaWMgc3RvcEF1dG9tYXRpY1JlZnJlc2goKSB7XG4gICAgdGhpcy5jbGVhckFjY2Vzc1Rva2VuVGltZXIoKTtcbiAgICB0aGlzLmNsZWFySWRUb2tlblRpbWVyKCk7XG4gIH1cblxuICBwcm90ZWN0ZWQgY2xlYXJBY2Nlc3NUb2tlblRpbWVyKCk6IHZvaWQge1xuICAgIGlmICh0aGlzLmFjY2Vzc1Rva2VuVGltZW91dFN1YnNjcmlwdGlvbikge1xuICAgICAgdGhpcy5hY2Nlc3NUb2tlblRpbWVvdXRTdWJzY3JpcHRpb24udW5zdWJzY3JpYmUoKTtcbiAgICB9XG4gIH1cblxuICBwcm90ZWN0ZWQgY2xlYXJJZFRva2VuVGltZXIoKTogdm9pZCB7XG4gICAgaWYgKHRoaXMuaWRUb2tlblRpbWVvdXRTdWJzY3JpcHRpb24pIHtcbiAgICAgIHRoaXMuaWRUb2tlblRpbWVvdXRTdWJzY3JpcHRpb24udW5zdWJzY3JpYmUoKTtcbiAgICB9XG4gIH1cblxuICBwcm90ZWN0ZWQgY2FsY1RpbWVvdXQoc3RvcmVkQXQ6IG51bWJlciwgZXhwaXJhdGlvbjogbnVtYmVyKTogbnVtYmVyIHtcbiAgICBjb25zdCBub3cgPSBEYXRlLm5vdygpO1xuICAgIGNvbnN0IGRlbHRhID1cbiAgICAgIChleHBpcmF0aW9uIC0gc3RvcmVkQXQpICogdGhpcy50aW1lb3V0RmFjdG9yIC0gKG5vdyAtIHN0b3JlZEF0KTtcbiAgICByZXR1cm4gTWF0aC5tYXgoMCwgZGVsdGEpO1xuICB9XG5cbiAgLyoqXG4gICAqIERFUFJFQ0FURUQuIFVzZSBhIHByb3ZpZGVyIGZvciBPQXV0aFN0b3JhZ2UgaW5zdGVhZDpcbiAgICpcbiAgICogeyBwcm92aWRlOiBPQXV0aFN0b3JhZ2UsIHVzZUZhY3Rvcnk6IG9BdXRoU3RvcmFnZUZhY3RvcnkgfVxuICAgKiBleHBvcnQgZnVuY3Rpb24gb0F1dGhTdG9yYWdlRmFjdG9yeSgpOiBPQXV0aFN0b3JhZ2UgeyByZXR1cm4gbG9jYWxTdG9yYWdlOyB9XG4gICAqIFNldHMgYSBjdXN0b20gc3RvcmFnZSB1c2VkIHRvIHN0b3JlIHRoZSByZWNlaXZlZFxuICAgKiB0b2tlbnMgb24gY2xpZW50IHNpZGUuIEJ5IGRlZmF1bHQsIHRoZSBicm93c2VyJ3NcbiAgICogc2Vzc2lvblN0b3JhZ2UgaXMgdXNlZC5cbiAgICogQGlnbm9yZVxuICAgKlxuICAgKiBAcGFyYW0gc3RvcmFnZVxuICAgKi9cbiAgcHVibGljIHNldFN0b3JhZ2Uoc3RvcmFnZTogT0F1dGhTdG9yYWdlKTogdm9pZCB7XG4gICAgdGhpcy5fc3RvcmFnZSA9IHN0b3JhZ2U7XG4gICAgdGhpcy5jb25maWdDaGFuZ2VkKCk7XG4gIH1cblxuICAvKipcbiAgICogTG9hZHMgdGhlIGRpc2NvdmVyeSBkb2N1bWVudCB0byBjb25maWd1cmUgbW9zdFxuICAgKiBwcm9wZXJ0aWVzIG9mIHRoaXMgc2VydmljZS4gVGhlIHVybCBvZiB0aGUgZGlzY292ZXJ5XG4gICAqIGRvY3VtZW50IGlzIGluZmVyZWQgZnJvbSB0aGUgaXNzdWVyJ3MgdXJsIGFjY29yZGluZ1xuICAgKiB0byB0aGUgT3BlbklkIENvbm5lY3Qgc3BlYy4gVG8gdXNlIGFub3RoZXIgdXJsIHlvdVxuICAgKiBjYW4gcGFzcyBpdCB0byB0byBvcHRpb25hbCBwYXJhbWV0ZXIgZnVsbFVybC5cbiAgICpcbiAgICogQHBhcmFtIGZ1bGxVcmxcbiAgICovXG4gIHB1YmxpYyBsb2FkRGlzY292ZXJ5RG9jdW1lbnQoXG4gICAgZnVsbFVybDogc3RyaW5nID0gbnVsbFxuICApOiBQcm9taXNlPE9BdXRoU3VjY2Vzc0V2ZW50PiB7XG4gICAgcmV0dXJuIG5ldyBQcm9taXNlKChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIGlmICghZnVsbFVybCkge1xuICAgICAgICBmdWxsVXJsID0gdGhpcy5pc3N1ZXIgfHwgJyc7XG4gICAgICAgIGlmICghZnVsbFVybC5lbmRzV2l0aCgnLycpKSB7XG4gICAgICAgICAgZnVsbFVybCArPSAnLyc7XG4gICAgICAgIH1cbiAgICAgICAgZnVsbFVybCArPSAnLndlbGwta25vd24vb3BlbmlkLWNvbmZpZ3VyYXRpb24nO1xuICAgICAgfVxuXG4gICAgICBpZiAoIXRoaXMudmFsaWRhdGVVcmxGb3JIdHRwcyhmdWxsVXJsKSkge1xuICAgICAgICByZWplY3QoXG4gICAgICAgICAgXCJpc3N1ZXIgIG11c3QgdXNlIEhUVFBTICh3aXRoIFRMUyksIG9yIGNvbmZpZyB2YWx1ZSBmb3IgcHJvcGVydHkgJ3JlcXVpcmVIdHRwcycgbXVzdCBiZSBzZXQgdG8gJ2ZhbHNlJyBhbmQgYWxsb3cgSFRUUCAod2l0aG91dCBUTFMpLlwiXG4gICAgICAgICk7XG4gICAgICAgIHJldHVybjtcbiAgICAgIH1cblxuICAgICAgdGhpcy5odHRwLmdldDxPaWRjRGlzY292ZXJ5RG9jPihmdWxsVXJsKS5zdWJzY3JpYmUoXG4gICAgICAgIGRvYyA9PiB7XG4gICAgICAgICAgaWYgKCF0aGlzLnZhbGlkYXRlRGlzY292ZXJ5RG9jdW1lbnQoZG9jKSkge1xuICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoXG4gICAgICAgICAgICAgIG5ldyBPQXV0aEVycm9yRXZlbnQoJ2Rpc2NvdmVyeV9kb2N1bWVudF92YWxpZGF0aW9uX2Vycm9yJywgbnVsbClcbiAgICAgICAgICAgICk7XG4gICAgICAgICAgICByZWplY3QoJ2Rpc2NvdmVyeV9kb2N1bWVudF92YWxpZGF0aW9uX2Vycm9yJyk7XG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgdGhpcy5sb2dpblVybCA9IGRvYy5hdXRob3JpemF0aW9uX2VuZHBvaW50O1xuICAgICAgICAgIHRoaXMubG9nb3V0VXJsID0gZG9jLmVuZF9zZXNzaW9uX2VuZHBvaW50IHx8IHRoaXMubG9nb3V0VXJsO1xuICAgICAgICAgIHRoaXMuZ3JhbnRUeXBlc1N1cHBvcnRlZCA9IGRvYy5ncmFudF90eXBlc19zdXBwb3J0ZWQ7XG4gICAgICAgICAgdGhpcy5pc3N1ZXIgPSBkb2MuaXNzdWVyO1xuICAgICAgICAgIHRoaXMudG9rZW5FbmRwb2ludCA9IGRvYy50b2tlbl9lbmRwb2ludDtcbiAgICAgICAgICB0aGlzLnVzZXJpbmZvRW5kcG9pbnQgPVxuICAgICAgICAgICAgZG9jLnVzZXJpbmZvX2VuZHBvaW50IHx8IHRoaXMudXNlcmluZm9FbmRwb2ludDtcbiAgICAgICAgICB0aGlzLmp3a3NVcmkgPSBkb2Muandrc191cmk7XG4gICAgICAgICAgdGhpcy5zZXNzaW9uQ2hlY2tJRnJhbWVVcmwgPVxuICAgICAgICAgICAgZG9jLmNoZWNrX3Nlc3Npb25faWZyYW1lIHx8IHRoaXMuc2Vzc2lvbkNoZWNrSUZyYW1lVXJsO1xuXG4gICAgICAgICAgdGhpcy5kaXNjb3ZlcnlEb2N1bWVudExvYWRlZCA9IHRydWU7XG4gICAgICAgICAgdGhpcy5kaXNjb3ZlcnlEb2N1bWVudExvYWRlZFN1YmplY3QubmV4dChkb2MpO1xuICAgICAgICAgIHRoaXMucmV2b2NhdGlvbkVuZHBvaW50ID0gZG9jLnJldm9jYXRpb25fZW5kcG9pbnQ7XG5cbiAgICAgICAgICBpZiAodGhpcy5zZXNzaW9uQ2hlY2tzRW5hYmxlZCkge1xuICAgICAgICAgICAgdGhpcy5yZXN0YXJ0U2Vzc2lvbkNoZWNrc0lmU3RpbGxMb2dnZWRJbigpO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIHRoaXMubG9hZEp3a3MoKVxuICAgICAgICAgICAgLnRoZW4oandrcyA9PiB7XG4gICAgICAgICAgICAgIGNvbnN0IHJlc3VsdDogb2JqZWN0ID0ge1xuICAgICAgICAgICAgICAgIGRpc2NvdmVyeURvY3VtZW50OiBkb2MsXG4gICAgICAgICAgICAgICAgandrczogandrc1xuICAgICAgICAgICAgICB9O1xuXG4gICAgICAgICAgICAgIGNvbnN0IGV2ZW50ID0gbmV3IE9BdXRoU3VjY2Vzc0V2ZW50KFxuICAgICAgICAgICAgICAgICdkaXNjb3ZlcnlfZG9jdW1lbnRfbG9hZGVkJyxcbiAgICAgICAgICAgICAgICByZXN1bHRcbiAgICAgICAgICAgICAgKTtcbiAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoZXZlbnQpO1xuICAgICAgICAgICAgICByZXNvbHZlKGV2ZW50KTtcbiAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgfSlcbiAgICAgICAgICAgIC5jYXRjaChlcnIgPT4ge1xuICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChcbiAgICAgICAgICAgICAgICBuZXcgT0F1dGhFcnJvckV2ZW50KCdkaXNjb3ZlcnlfZG9jdW1lbnRfbG9hZF9lcnJvcicsIGVycilcbiAgICAgICAgICAgICAgKTtcbiAgICAgICAgICAgICAgcmVqZWN0KGVycik7XG4gICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9LFxuICAgICAgICBlcnIgPT4ge1xuICAgICAgICAgIHRoaXMubG9nZ2VyLmVycm9yKCdlcnJvciBsb2FkaW5nIGRpc2NvdmVyeSBkb2N1bWVudCcsIGVycik7XG4gICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoXG4gICAgICAgICAgICBuZXcgT0F1dGhFcnJvckV2ZW50KCdkaXNjb3ZlcnlfZG9jdW1lbnRfbG9hZF9lcnJvcicsIGVycilcbiAgICAgICAgICApO1xuICAgICAgICAgIHJlamVjdChlcnIpO1xuICAgICAgICB9XG4gICAgICApO1xuICAgIH0pO1xuICB9XG5cbiAgcHJvdGVjdGVkIGxvYWRKd2tzKCk6IFByb21pc2U8b2JqZWN0PiB7XG4gICAgcmV0dXJuIG5ldyBQcm9taXNlPG9iamVjdD4oKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgaWYgKHRoaXMuandrc1VyaSkge1xuICAgICAgICB0aGlzLmh0dHAuZ2V0KHRoaXMuandrc1VyaSkuc3Vic2NyaWJlKFxuICAgICAgICAgIGp3a3MgPT4ge1xuICAgICAgICAgICAgdGhpcy5qd2tzID0gandrcztcbiAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KFxuICAgICAgICAgICAgICBuZXcgT0F1dGhTdWNjZXNzRXZlbnQoJ2Rpc2NvdmVyeV9kb2N1bWVudF9sb2FkZWQnKVxuICAgICAgICAgICAgKTtcbiAgICAgICAgICAgIHJlc29sdmUoandrcyk7XG4gICAgICAgICAgfSxcbiAgICAgICAgICBlcnIgPT4ge1xuICAgICAgICAgICAgdGhpcy5sb2dnZXIuZXJyb3IoJ2Vycm9yIGxvYWRpbmcgandrcycsIGVycik7XG4gICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChcbiAgICAgICAgICAgICAgbmV3IE9BdXRoRXJyb3JFdmVudCgnandrc19sb2FkX2Vycm9yJywgZXJyKVxuICAgICAgICAgICAgKTtcbiAgICAgICAgICAgIHJlamVjdChlcnIpO1xuICAgICAgICAgIH1cbiAgICAgICAgKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHJlc29sdmUobnVsbCk7XG4gICAgICB9XG4gICAgfSk7XG4gIH1cblxuICBwcm90ZWN0ZWQgdmFsaWRhdGVEaXNjb3ZlcnlEb2N1bWVudChkb2M6IE9pZGNEaXNjb3ZlcnlEb2MpOiBib29sZWFuIHtcbiAgICBsZXQgZXJyb3JzOiBzdHJpbmdbXTtcblxuICAgIGlmICghdGhpcy5za2lwSXNzdWVyQ2hlY2sgJiYgZG9jLmlzc3VlciAhPT0gdGhpcy5pc3N1ZXIpIHtcbiAgICAgIHRoaXMubG9nZ2VyLmVycm9yKFxuICAgICAgICAnaW52YWxpZCBpc3N1ZXIgaW4gZGlzY292ZXJ5IGRvY3VtZW50JyxcbiAgICAgICAgJ2V4cGVjdGVkOiAnICsgdGhpcy5pc3N1ZXIsXG4gICAgICAgICdjdXJyZW50OiAnICsgZG9jLmlzc3VlclxuICAgICAgKTtcbiAgICAgIHJldHVybiBmYWxzZTtcbiAgICB9XG5cbiAgICBlcnJvcnMgPSB0aGlzLnZhbGlkYXRlVXJsRnJvbURpc2NvdmVyeURvY3VtZW50KGRvYy5hdXRob3JpemF0aW9uX2VuZHBvaW50KTtcbiAgICBpZiAoZXJyb3JzLmxlbmd0aCA+IDApIHtcbiAgICAgIHRoaXMubG9nZ2VyLmVycm9yKFxuICAgICAgICAnZXJyb3IgdmFsaWRhdGluZyBhdXRob3JpemF0aW9uX2VuZHBvaW50IGluIGRpc2NvdmVyeSBkb2N1bWVudCcsXG4gICAgICAgIGVycm9yc1xuICAgICAgKTtcbiAgICAgIHJldHVybiBmYWxzZTtcbiAgICB9XG5cbiAgICBlcnJvcnMgPSB0aGlzLnZhbGlkYXRlVXJsRnJvbURpc2NvdmVyeURvY3VtZW50KGRvYy5lbmRfc2Vzc2lvbl9lbmRwb2ludCk7XG4gICAgaWYgKGVycm9ycy5sZW5ndGggPiAwKSB7XG4gICAgICB0aGlzLmxvZ2dlci5lcnJvcihcbiAgICAgICAgJ2Vycm9yIHZhbGlkYXRpbmcgZW5kX3Nlc3Npb25fZW5kcG9pbnQgaW4gZGlzY292ZXJ5IGRvY3VtZW50JyxcbiAgICAgICAgZXJyb3JzXG4gICAgICApO1xuICAgICAgcmV0dXJuIGZhbHNlO1xuICAgIH1cblxuICAgIGVycm9ycyA9IHRoaXMudmFsaWRhdGVVcmxGcm9tRGlzY292ZXJ5RG9jdW1lbnQoZG9jLnRva2VuX2VuZHBvaW50KTtcbiAgICBpZiAoZXJyb3JzLmxlbmd0aCA+IDApIHtcbiAgICAgIHRoaXMubG9nZ2VyLmVycm9yKFxuICAgICAgICAnZXJyb3IgdmFsaWRhdGluZyB0b2tlbl9lbmRwb2ludCBpbiBkaXNjb3ZlcnkgZG9jdW1lbnQnLFxuICAgICAgICBlcnJvcnNcbiAgICAgICk7XG4gICAgfVxuXG4gICAgZXJyb3JzID0gdGhpcy52YWxpZGF0ZVVybEZyb21EaXNjb3ZlcnlEb2N1bWVudChkb2MucmV2b2NhdGlvbl9lbmRwb2ludCk7XG4gICAgaWYgKGVycm9ycy5sZW5ndGggPiAwKSB7XG4gICAgICB0aGlzLmxvZ2dlci5lcnJvcihcbiAgICAgICAgJ2Vycm9yIHZhbGlkYXRpbmcgcmV2b2NhdGlvbl9lbmRwb2ludCBpbiBkaXNjb3ZlcnkgZG9jdW1lbnQnLFxuICAgICAgICBlcnJvcnNcbiAgICAgICk7XG4gICAgfVxuXG4gICAgZXJyb3JzID0gdGhpcy52YWxpZGF0ZVVybEZyb21EaXNjb3ZlcnlEb2N1bWVudChkb2MudXNlcmluZm9fZW5kcG9pbnQpO1xuICAgIGlmIChlcnJvcnMubGVuZ3RoID4gMCkge1xuICAgICAgdGhpcy5sb2dnZXIuZXJyb3IoXG4gICAgICAgICdlcnJvciB2YWxpZGF0aW5nIHVzZXJpbmZvX2VuZHBvaW50IGluIGRpc2NvdmVyeSBkb2N1bWVudCcsXG4gICAgICAgIGVycm9yc1xuICAgICAgKTtcbiAgICAgIHJldHVybiBmYWxzZTtcbiAgICB9XG5cbiAgICBlcnJvcnMgPSB0aGlzLnZhbGlkYXRlVXJsRnJvbURpc2NvdmVyeURvY3VtZW50KGRvYy5qd2tzX3VyaSk7XG4gICAgaWYgKGVycm9ycy5sZW5ndGggPiAwKSB7XG4gICAgICB0aGlzLmxvZ2dlci5lcnJvcihcbiAgICAgICAgJ2Vycm9yIHZhbGlkYXRpbmcgandrc191cmkgaW4gZGlzY292ZXJ5IGRvY3VtZW50JyxcbiAgICAgICAgZXJyb3JzXG4gICAgICApO1xuICAgICAgcmV0dXJuIGZhbHNlO1xuICAgIH1cblxuICAgIGlmICh0aGlzLnNlc3Npb25DaGVja3NFbmFibGVkICYmICFkb2MuY2hlY2tfc2Vzc2lvbl9pZnJhbWUpIHtcbiAgICAgIHRoaXMubG9nZ2VyLndhcm4oXG4gICAgICAgICdzZXNzaW9uQ2hlY2tzRW5hYmxlZCBpcyBhY3RpdmF0ZWQgYnV0IGRpc2NvdmVyeSBkb2N1bWVudCcgK1xuICAgICAgICAgICcgZG9lcyBub3QgY29udGFpbiBhIGNoZWNrX3Nlc3Npb25faWZyYW1lIGZpZWxkJ1xuICAgICAgKTtcbiAgICB9XG5cbiAgICByZXR1cm4gdHJ1ZTtcbiAgfVxuXG4gIC8qKlxuICAgKiBVc2VzIHBhc3N3b3JkIGZsb3cgdG8gZXhjaGFuZ2UgdXNlck5hbWUgYW5kIHBhc3N3b3JkIGZvciBhblxuICAgKiBhY2Nlc3NfdG9rZW4uIEFmdGVyIHJlY2VpdmluZyB0aGUgYWNjZXNzX3Rva2VuLCB0aGlzIG1ldGhvZFxuICAgKiB1c2VzIGl0IHRvIHF1ZXJ5IHRoZSB1c2VyaW5mbyBlbmRwb2ludCBpbiBvcmRlciB0byBnZXQgaW5mb3JtYXRpb25cbiAgICogYWJvdXQgdGhlIHVzZXIgaW4gcXVlc3Rpb24uXG4gICAqXG4gICAqIFdoZW4gdXNpbmcgdGhpcywgbWFrZSBzdXJlIHRoYXQgdGhlIHByb3BlcnR5IG9pZGMgaXMgc2V0IHRvIGZhbHNlLlxuICAgKiBPdGhlcndpc2Ugc3RyaWN0ZXIgdmFsaWRhdGlvbnMgdGFrZSBwbGFjZSB0aGF0IG1ha2UgdGhpcyBvcGVyYXRpb25cbiAgICogZmFpbC5cbiAgICpcbiAgICogQHBhcmFtIHVzZXJOYW1lXG4gICAqIEBwYXJhbSBwYXNzd29yZFxuICAgKiBAcGFyYW0gaGVhZGVycyBPcHRpb25hbCBhZGRpdGlvbmFsIGh0dHAtaGVhZGVycy5cbiAgICovXG4gIHB1YmxpYyBmZXRjaFRva2VuVXNpbmdQYXNzd29yZEZsb3dBbmRMb2FkVXNlclByb2ZpbGUoXG4gICAgdXNlck5hbWU6IHN0cmluZyxcbiAgICBwYXNzd29yZDogc3RyaW5nLFxuICAgIGhlYWRlcnM6IEh0dHBIZWFkZXJzID0gbmV3IEh0dHBIZWFkZXJzKClcbiAgKTogUHJvbWlzZTxVc2VySW5mbz4ge1xuICAgIHJldHVybiB0aGlzLmZldGNoVG9rZW5Vc2luZ1Bhc3N3b3JkRmxvdyhcbiAgICAgIHVzZXJOYW1lLFxuICAgICAgcGFzc3dvcmQsXG4gICAgICBoZWFkZXJzXG4gICAgKS50aGVuKCgpID0+IHRoaXMubG9hZFVzZXJQcm9maWxlKCkpO1xuICB9XG5cbiAgLyoqXG4gICAqIExvYWRzIHRoZSB1c2VyIHByb2ZpbGUgYnkgYWNjZXNzaW5nIHRoZSB1c2VyIGluZm8gZW5kcG9pbnQgZGVmaW5lZCBieSBPcGVuSWQgQ29ubmVjdC5cbiAgICpcbiAgICogV2hlbiB1c2luZyB0aGlzIHdpdGggT0F1dGgyIHBhc3N3b3JkIGZsb3csIG1ha2Ugc3VyZSB0aGF0IHRoZSBwcm9wZXJ0eSBvaWRjIGlzIHNldCB0byBmYWxzZS5cbiAgICogT3RoZXJ3aXNlIHN0cmljdGVyIHZhbGlkYXRpb25zIHRha2UgcGxhY2UgdGhhdCBtYWtlIHRoaXMgb3BlcmF0aW9uIGZhaWwuXG4gICAqL1xuICBwdWJsaWMgbG9hZFVzZXJQcm9maWxlKCk6IFByb21pc2U8VXNlckluZm8+IHtcbiAgICBpZiAoIXRoaXMuaGFzVmFsaWRBY2Nlc3NUb2tlbigpKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoJ0NhbiBub3QgbG9hZCBVc2VyIFByb2ZpbGUgd2l0aG91dCBhY2Nlc3NfdG9rZW4nKTtcbiAgICB9XG4gICAgaWYgKCF0aGlzLnZhbGlkYXRlVXJsRm9ySHR0cHModGhpcy51c2VyaW5mb0VuZHBvaW50KSkge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKFxuICAgICAgICBcInVzZXJpbmZvRW5kcG9pbnQgbXVzdCB1c2UgSFRUUFMgKHdpdGggVExTKSwgb3IgY29uZmlnIHZhbHVlIGZvciBwcm9wZXJ0eSAncmVxdWlyZUh0dHBzJyBtdXN0IGJlIHNldCB0byAnZmFsc2UnIGFuZCBhbGxvdyBIVFRQICh3aXRob3V0IFRMUykuXCJcbiAgICAgICk7XG4gICAgfVxuXG4gICAgcmV0dXJuIG5ldyBQcm9taXNlKChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIGNvbnN0IGhlYWRlcnMgPSBuZXcgSHR0cEhlYWRlcnMoKS5zZXQoXG4gICAgICAgICdBdXRob3JpemF0aW9uJyxcbiAgICAgICAgJ0JlYXJlciAnICsgdGhpcy5nZXRBY2Nlc3NUb2tlbigpXG4gICAgICApO1xuXG4gICAgICB0aGlzLmh0dHBcbiAgICAgICAgLmdldDxVc2VySW5mbz4odGhpcy51c2VyaW5mb0VuZHBvaW50LCB7IGhlYWRlcnMgfSlcbiAgICAgICAgLnN1YnNjcmliZShcbiAgICAgICAgICBpbmZvID0+IHtcbiAgICAgICAgICAgIHRoaXMuZGVidWcoJ3VzZXJpbmZvIHJlY2VpdmVkJywgaW5mbyk7XG5cbiAgICAgICAgICAgIGNvbnN0IGV4aXN0aW5nQ2xhaW1zID0gdGhpcy5nZXRJZGVudGl0eUNsYWltcygpIHx8IHt9O1xuXG4gICAgICAgICAgICBpZiAoIXRoaXMuc2tpcFN1YmplY3RDaGVjaykge1xuICAgICAgICAgICAgICBpZiAoXG4gICAgICAgICAgICAgICAgdGhpcy5vaWRjICYmXG4gICAgICAgICAgICAgICAgKCFleGlzdGluZ0NsYWltc1snc3ViJ10gfHwgaW5mby5zdWIgIT09IGV4aXN0aW5nQ2xhaW1zWydzdWInXSlcbiAgICAgICAgICAgICAgKSB7XG4gICAgICAgICAgICAgICAgY29uc3QgZXJyID1cbiAgICAgICAgICAgICAgICAgICdpZiBwcm9wZXJ0eSBvaWRjIGlzIHRydWUsIHRoZSByZWNlaXZlZCB1c2VyLWlkIChzdWIpIGhhcyB0byBiZSB0aGUgdXNlci1pZCAnICtcbiAgICAgICAgICAgICAgICAgICdvZiB0aGUgdXNlciB0aGF0IGhhcyBsb2dnZWQgaW4gd2l0aCBvaWRjLlxcbicgK1xuICAgICAgICAgICAgICAgICAgJ2lmIHlvdSBhcmUgbm90IHVzaW5nIG9pZGMgYnV0IGp1c3Qgb2F1dGgyIHBhc3N3b3JkIGZsb3cgc2V0IG9pZGMgdG8gZmFsc2UnO1xuXG4gICAgICAgICAgICAgICAgcmVqZWN0KGVycik7XG4gICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIGluZm8gPSBPYmplY3QuYXNzaWduKHt9LCBleGlzdGluZ0NsYWltcywgaW5mbyk7XG5cbiAgICAgICAgICAgIHRoaXMuX3N0b3JhZ2Uuc2V0SXRlbSgnaWRfdG9rZW5fY2xhaW1zX29iaicsIEpTT04uc3RyaW5naWZ5KGluZm8pKTtcbiAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KFxuICAgICAgICAgICAgICBuZXcgT0F1dGhTdWNjZXNzRXZlbnQoJ3VzZXJfcHJvZmlsZV9sb2FkZWQnKVxuICAgICAgICAgICAgKTtcbiAgICAgICAgICAgIHJlc29sdmUoaW5mbyk7XG4gICAgICAgICAgfSxcbiAgICAgICAgICBlcnIgPT4ge1xuICAgICAgICAgICAgdGhpcy5sb2dnZXIuZXJyb3IoJ2Vycm9yIGxvYWRpbmcgdXNlciBpbmZvJywgZXJyKTtcbiAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KFxuICAgICAgICAgICAgICBuZXcgT0F1dGhFcnJvckV2ZW50KCd1c2VyX3Byb2ZpbGVfbG9hZF9lcnJvcicsIGVycilcbiAgICAgICAgICAgICk7XG4gICAgICAgICAgICByZWplY3QoZXJyKTtcbiAgICAgICAgICB9XG4gICAgICAgICk7XG4gICAgfSk7XG4gIH1cblxuICAvKipcbiAgICogVXNlcyBwYXNzd29yZCBmbG93IHRvIGV4Y2hhbmdlIHVzZXJOYW1lIGFuZCBwYXNzd29yZCBmb3IgYW4gYWNjZXNzX3Rva2VuLlxuICAgKiBAcGFyYW0gdXNlck5hbWVcbiAgICogQHBhcmFtIHBhc3N3b3JkXG4gICAqIEBwYXJhbSBoZWFkZXJzIE9wdGlvbmFsIGFkZGl0aW9uYWwgaHR0cC1oZWFkZXJzLlxuICAgKi9cbiAgcHVibGljIGZldGNoVG9rZW5Vc2luZ1Bhc3N3b3JkRmxvdyhcbiAgICB1c2VyTmFtZTogc3RyaW5nLFxuICAgIHBhc3N3b3JkOiBzdHJpbmcsXG4gICAgaGVhZGVyczogSHR0cEhlYWRlcnMgPSBuZXcgSHR0cEhlYWRlcnMoKVxuICApOiBQcm9taXNlPFRva2VuUmVzcG9uc2U+IHtcbiAgICB0aGlzLmFzc2VydFVybE5vdE51bGxBbmRDb3JyZWN0UHJvdG9jb2woXG4gICAgICB0aGlzLnRva2VuRW5kcG9pbnQsXG4gICAgICAndG9rZW5FbmRwb2ludCdcbiAgICApO1xuXG4gICAgcmV0dXJuIG5ldyBQcm9taXNlKChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIC8qKlxuICAgICAgICogQSBgSHR0cFBhcmFtZXRlckNvZGVjYCB0aGF0IHVzZXMgYGVuY29kZVVSSUNvbXBvbmVudGAgYW5kIGBkZWNvZGVVUklDb21wb25lbnRgIHRvXG4gICAgICAgKiBzZXJpYWxpemUgYW5kIHBhcnNlIFVSTCBwYXJhbWV0ZXIga2V5cyBhbmQgdmFsdWVzLlxuICAgICAgICpcbiAgICAgICAqIEBzdGFibGVcbiAgICAgICAqL1xuICAgICAgbGV0IHBhcmFtcyA9IG5ldyBIdHRwUGFyYW1zKHsgZW5jb2RlcjogbmV3IFdlYkh0dHBVcmxFbmNvZGluZ0NvZGVjKCkgfSlcbiAgICAgICAgLnNldCgnZ3JhbnRfdHlwZScsICdwYXNzd29yZCcpXG4gICAgICAgIC5zZXQoJ3Njb3BlJywgdGhpcy5zY29wZSlcbiAgICAgICAgLnNldCgndXNlcm5hbWUnLCB1c2VyTmFtZSlcbiAgICAgICAgLnNldCgncGFzc3dvcmQnLCBwYXNzd29yZCk7XG5cbiAgICAgIGlmICh0aGlzLnVzZUh0dHBCYXNpY0F1dGgpIHtcbiAgICAgICAgY29uc3QgaGVhZGVyID0gYnRvYShgJHt0aGlzLmNsaWVudElkfToke3RoaXMuZHVtbXlDbGllbnRTZWNyZXR9YCk7XG4gICAgICAgIGhlYWRlcnMgPSBoZWFkZXJzLnNldCgnQXV0aG9yaXphdGlvbicsICdCYXNpYyAnICsgaGVhZGVyKTtcbiAgICAgIH1cblxuICAgICAgaWYgKCF0aGlzLnVzZUh0dHBCYXNpY0F1dGgpIHtcbiAgICAgICAgcGFyYW1zID0gcGFyYW1zLnNldCgnY2xpZW50X2lkJywgdGhpcy5jbGllbnRJZCk7XG4gICAgICB9XG5cbiAgICAgIGlmICghdGhpcy51c2VIdHRwQmFzaWNBdXRoICYmIHRoaXMuZHVtbXlDbGllbnRTZWNyZXQpIHtcbiAgICAgICAgcGFyYW1zID0gcGFyYW1zLnNldCgnY2xpZW50X3NlY3JldCcsIHRoaXMuZHVtbXlDbGllbnRTZWNyZXQpO1xuICAgICAgfVxuXG4gICAgICBpZiAodGhpcy5jdXN0b21RdWVyeVBhcmFtcykge1xuICAgICAgICBmb3IgKGNvbnN0IGtleSBvZiBPYmplY3QuZ2V0T3duUHJvcGVydHlOYW1lcyh0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zKSkge1xuICAgICAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoa2V5LCB0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zW2tleV0pO1xuICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIGhlYWRlcnMgPSBoZWFkZXJzLnNldChcbiAgICAgICAgJ0NvbnRlbnQtVHlwZScsXG4gICAgICAgICdhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWQnXG4gICAgICApO1xuXG4gICAgICB0aGlzLmh0dHBcbiAgICAgICAgLnBvc3Q8VG9rZW5SZXNwb25zZT4odGhpcy50b2tlbkVuZHBvaW50LCBwYXJhbXMsIHsgaGVhZGVycyB9KVxuICAgICAgICAuc3Vic2NyaWJlKFxuICAgICAgICAgIHRva2VuUmVzcG9uc2UgPT4ge1xuICAgICAgICAgICAgdGhpcy5kZWJ1ZygndG9rZW5SZXNwb25zZScsIHRva2VuUmVzcG9uc2UpO1xuICAgICAgICAgICAgdGhpcy5zdG9yZUFjY2Vzc1Rva2VuUmVzcG9uc2UoXG4gICAgICAgICAgICAgIHRva2VuUmVzcG9uc2UuYWNjZXNzX3Rva2VuLFxuICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLnJlZnJlc2hfdG9rZW4sXG4gICAgICAgICAgICAgIHRva2VuUmVzcG9uc2UuZXhwaXJlc19pbiB8fFxuICAgICAgICAgICAgICAgIHRoaXMuZmFsbGJhY2tBY2Nlc3NUb2tlbkV4cGlyYXRpb25UaW1lSW5TZWMsXG4gICAgICAgICAgICAgIHRva2VuUmVzcG9uc2Uuc2NvcGUsXG4gICAgICAgICAgICAgIHRoaXMuZXh0cmFjdFJlY29nbml6ZWRDdXN0b21QYXJhbWV0ZXJzKHRva2VuUmVzcG9uc2UpXG4gICAgICAgICAgICApO1xuXG4gICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhTdWNjZXNzRXZlbnQoJ3Rva2VuX3JlY2VpdmVkJykpO1xuICAgICAgICAgICAgcmVzb2x2ZSh0b2tlblJlc3BvbnNlKTtcbiAgICAgICAgICB9LFxuICAgICAgICAgIGVyciA9PiB7XG4gICAgICAgICAgICB0aGlzLmxvZ2dlci5lcnJvcignRXJyb3IgcGVyZm9ybWluZyBwYXNzd29yZCBmbG93JywgZXJyKTtcbiAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aEVycm9yRXZlbnQoJ3Rva2VuX2Vycm9yJywgZXJyKSk7XG4gICAgICAgICAgICByZWplY3QoZXJyKTtcbiAgICAgICAgICB9XG4gICAgICAgICk7XG4gICAgfSk7XG4gIH1cblxuICAvKipcbiAgICogUmVmcmVzaGVzIHRoZSB0b2tlbiB1c2luZyBhIHJlZnJlc2hfdG9rZW4uXG4gICAqIFRoaXMgZG9lcyBub3Qgd29yayBmb3IgaW1wbGljaXQgZmxvdywgYi9jXG4gICAqIHRoZXJlIGlzIG5vIHJlZnJlc2hfdG9rZW4gaW4gdGhpcyBmbG93LlxuICAgKiBBIHNvbHV0aW9uIGZvciB0aGlzIGlzIHByb3ZpZGVkIGJ5IHRoZVxuICAgKiBtZXRob2Qgc2lsZW50UmVmcmVzaC5cbiAgICovXG4gIHB1YmxpYyByZWZyZXNoVG9rZW4oKTogUHJvbWlzZTxUb2tlblJlc3BvbnNlPiB7XG4gICAgdGhpcy5hc3NlcnRVcmxOb3ROdWxsQW5kQ29ycmVjdFByb3RvY29sKFxuICAgICAgdGhpcy50b2tlbkVuZHBvaW50LFxuICAgICAgJ3Rva2VuRW5kcG9pbnQnXG4gICAgKTtcblxuICAgIHJldHVybiBuZXcgUHJvbWlzZSgocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICBsZXQgcGFyYW1zID0gbmV3IEh0dHBQYXJhbXMoKVxuICAgICAgICAuc2V0KCdncmFudF90eXBlJywgJ3JlZnJlc2hfdG9rZW4nKVxuICAgICAgICAuc2V0KCdzY29wZScsIHRoaXMuc2NvcGUpXG4gICAgICAgIC5zZXQoJ3JlZnJlc2hfdG9rZW4nLCB0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ3JlZnJlc2hfdG9rZW4nKSk7XG5cbiAgICAgIGxldCBoZWFkZXJzID0gbmV3IEh0dHBIZWFkZXJzKCkuc2V0KFxuICAgICAgICAnQ29udGVudC1UeXBlJyxcbiAgICAgICAgJ2FwcGxpY2F0aW9uL3gtd3d3LWZvcm0tdXJsZW5jb2RlZCdcbiAgICAgICk7XG5cbiAgICAgIGlmICh0aGlzLnVzZUh0dHBCYXNpY0F1dGgpIHtcbiAgICAgICAgY29uc3QgaGVhZGVyID0gYnRvYShgJHt0aGlzLmNsaWVudElkfToke3RoaXMuZHVtbXlDbGllbnRTZWNyZXR9YCk7XG4gICAgICAgIGhlYWRlcnMgPSBoZWFkZXJzLnNldCgnQXV0aG9yaXphdGlvbicsICdCYXNpYyAnICsgaGVhZGVyKTtcbiAgICAgIH1cblxuICAgICAgaWYgKCF0aGlzLnVzZUh0dHBCYXNpY0F1dGgpIHtcbiAgICAgICAgcGFyYW1zID0gcGFyYW1zLnNldCgnY2xpZW50X2lkJywgdGhpcy5jbGllbnRJZCk7XG4gICAgICB9XG5cbiAgICAgIGlmICghdGhpcy51c2VIdHRwQmFzaWNBdXRoICYmIHRoaXMuZHVtbXlDbGllbnRTZWNyZXQpIHtcbiAgICAgICAgcGFyYW1zID0gcGFyYW1zLnNldCgnY2xpZW50X3NlY3JldCcsIHRoaXMuZHVtbXlDbGllbnRTZWNyZXQpO1xuICAgICAgfVxuXG4gICAgICBpZiAodGhpcy5jdXN0b21RdWVyeVBhcmFtcykge1xuICAgICAgICBmb3IgKGNvbnN0IGtleSBvZiBPYmplY3QuZ2V0T3duUHJvcGVydHlOYW1lcyh0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zKSkge1xuICAgICAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoa2V5LCB0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zW2tleV0pO1xuICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIHRoaXMuaHR0cFxuICAgICAgICAucG9zdDxUb2tlblJlc3BvbnNlPih0aGlzLnRva2VuRW5kcG9pbnQsIHBhcmFtcywgeyBoZWFkZXJzIH0pXG4gICAgICAgIC5waXBlKFxuICAgICAgICAgIHN3aXRjaE1hcCh0b2tlblJlc3BvbnNlID0+IHtcbiAgICAgICAgICAgIGlmICh0b2tlblJlc3BvbnNlLmlkX3Rva2VuKSB7XG4gICAgICAgICAgICAgIHJldHVybiBmcm9tKFxuICAgICAgICAgICAgICAgIHRoaXMucHJvY2Vzc0lkVG9rZW4oXG4gICAgICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLmlkX3Rva2VuLFxuICAgICAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5hY2Nlc3NfdG9rZW4sXG4gICAgICAgICAgICAgICAgICB0cnVlXG4gICAgICAgICAgICAgICAgKVxuICAgICAgICAgICAgICApLnBpcGUoXG4gICAgICAgICAgICAgICAgdGFwKHJlc3VsdCA9PiB0aGlzLnN0b3JlSWRUb2tlbihyZXN1bHQpKSxcbiAgICAgICAgICAgICAgICBtYXAoXyA9PiB0b2tlblJlc3BvbnNlKVxuICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgcmV0dXJuIG9mKHRva2VuUmVzcG9uc2UpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgIH0pXG4gICAgICAgIClcbiAgICAgICAgLnN1YnNjcmliZShcbiAgICAgICAgICB0b2tlblJlc3BvbnNlID0+IHtcbiAgICAgICAgICAgIHRoaXMuZGVidWcoJ3JlZnJlc2ggdG9rZW5SZXNwb25zZScsIHRva2VuUmVzcG9uc2UpO1xuICAgICAgICAgICAgdGhpcy5zdG9yZUFjY2Vzc1Rva2VuUmVzcG9uc2UoXG4gICAgICAgICAgICAgIHRva2VuUmVzcG9uc2UuYWNjZXNzX3Rva2VuLFxuICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLnJlZnJlc2hfdG9rZW4sXG4gICAgICAgICAgICAgIHRva2VuUmVzcG9uc2UuZXhwaXJlc19pbiB8fFxuICAgICAgICAgICAgICAgIHRoaXMuZmFsbGJhY2tBY2Nlc3NUb2tlbkV4cGlyYXRpb25UaW1lSW5TZWMsXG4gICAgICAgICAgICAgIHRva2VuUmVzcG9uc2Uuc2NvcGUsXG4gICAgICAgICAgICAgIHRoaXMuZXh0cmFjdFJlY29nbml6ZWRDdXN0b21QYXJhbWV0ZXJzKHRva2VuUmVzcG9uc2UpXG4gICAgICAgICAgICApO1xuXG4gICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhTdWNjZXNzRXZlbnQoJ3Rva2VuX3JlY2VpdmVkJykpO1xuICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoU3VjY2Vzc0V2ZW50KCd0b2tlbl9yZWZyZXNoZWQnKSk7XG4gICAgICAgICAgICByZXNvbHZlKHRva2VuUmVzcG9uc2UpO1xuICAgICAgICAgIH0sXG4gICAgICAgICAgZXJyID0+IHtcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyLmVycm9yKCdFcnJvciByZWZyZXNoaW5nIHRva2VuJywgZXJyKTtcbiAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KFxuICAgICAgICAgICAgICBuZXcgT0F1dGhFcnJvckV2ZW50KCd0b2tlbl9yZWZyZXNoX2Vycm9yJywgZXJyKVxuICAgICAgICAgICAgKTtcbiAgICAgICAgICAgIHJlamVjdChlcnIpO1xuICAgICAgICAgIH1cbiAgICAgICAgKTtcbiAgICB9KTtcbiAgfVxuXG4gIHByb3RlY3RlZCByZW1vdmVTaWxlbnRSZWZyZXNoRXZlbnRMaXN0ZW5lcigpOiB2b2lkIHtcbiAgICBpZiAodGhpcy5zaWxlbnRSZWZyZXNoUG9zdE1lc3NhZ2VFdmVudExpc3RlbmVyKSB7XG4gICAgICB3aW5kb3cucmVtb3ZlRXZlbnRMaXN0ZW5lcihcbiAgICAgICAgJ21lc3NhZ2UnLFxuICAgICAgICB0aGlzLnNpbGVudFJlZnJlc2hQb3N0TWVzc2FnZUV2ZW50TGlzdGVuZXJcbiAgICAgICk7XG4gICAgICB0aGlzLnNpbGVudFJlZnJlc2hQb3N0TWVzc2FnZUV2ZW50TGlzdGVuZXIgPSBudWxsO1xuICAgIH1cbiAgfVxuXG4gIHByb3RlY3RlZCBzZXR1cFNpbGVudFJlZnJlc2hFdmVudExpc3RlbmVyKCk6IHZvaWQge1xuICAgIHRoaXMucmVtb3ZlU2lsZW50UmVmcmVzaEV2ZW50TGlzdGVuZXIoKTtcblxuICAgIHRoaXMuc2lsZW50UmVmcmVzaFBvc3RNZXNzYWdlRXZlbnRMaXN0ZW5lciA9IChlOiBNZXNzYWdlRXZlbnQpID0+IHtcbiAgICAgIGNvbnN0IG1lc3NhZ2UgPSB0aGlzLnByb2Nlc3NNZXNzYWdlRXZlbnRNZXNzYWdlKGUpO1xuXG4gICAgICB0aGlzLnRyeUxvZ2luKHtcbiAgICAgICAgY3VzdG9tSGFzaEZyYWdtZW50OiBtZXNzYWdlLFxuICAgICAgICBwcmV2ZW50Q2xlYXJIYXNoQWZ0ZXJMb2dpbjogdHJ1ZSxcbiAgICAgICAgY3VzdG9tUmVkaXJlY3RVcmk6IHRoaXMuc2lsZW50UmVmcmVzaFJlZGlyZWN0VXJpIHx8IHRoaXMucmVkaXJlY3RVcmlcbiAgICAgIH0pLmNhdGNoKGVyciA9PiB0aGlzLmRlYnVnKCd0cnlMb2dpbiBkdXJpbmcgc2lsZW50IHJlZnJlc2ggZmFpbGVkJywgZXJyKSk7XG4gICAgfTtcblxuICAgIHdpbmRvdy5hZGRFdmVudExpc3RlbmVyKFxuICAgICAgJ21lc3NhZ2UnLFxuICAgICAgdGhpcy5zaWxlbnRSZWZyZXNoUG9zdE1lc3NhZ2VFdmVudExpc3RlbmVyXG4gICAgKTtcbiAgfVxuXG4gIC8qKlxuICAgKiBQZXJmb3JtcyBhIHNpbGVudCByZWZyZXNoIGZvciBpbXBsaWNpdCBmbG93LlxuICAgKiBVc2UgdGhpcyBtZXRob2QgdG8gZ2V0IG5ldyB0b2tlbnMgd2hlbi9iZWZvcmVcbiAgICogdGhlIGV4aXN0aW5nIHRva2VucyBleHBpcmUuXG4gICAqL1xuICBwdWJsaWMgc2lsZW50UmVmcmVzaChcbiAgICBwYXJhbXM6IG9iamVjdCA9IHt9LFxuICAgIG5vUHJvbXB0ID0gdHJ1ZVxuICApOiBQcm9taXNlPE9BdXRoRXZlbnQ+IHtcbiAgICBjb25zdCBjbGFpbXM6IG9iamVjdCA9IHRoaXMuZ2V0SWRlbnRpdHlDbGFpbXMoKSB8fCB7fTtcblxuICAgIGlmICh0aGlzLnVzZUlkVG9rZW5IaW50Rm9yU2lsZW50UmVmcmVzaCAmJiB0aGlzLmhhc1ZhbGlkSWRUb2tlbigpKSB7XG4gICAgICBwYXJhbXNbJ2lkX3Rva2VuX2hpbnQnXSA9IHRoaXMuZ2V0SWRUb2tlbigpO1xuICAgIH1cblxuICAgIGlmICghdGhpcy52YWxpZGF0ZVVybEZvckh0dHBzKHRoaXMubG9naW5VcmwpKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoXG4gICAgICAgIFwibG9naW5VcmwgIG11c3QgdXNlIEhUVFBTICh3aXRoIFRMUyksIG9yIGNvbmZpZyB2YWx1ZSBmb3IgcHJvcGVydHkgJ3JlcXVpcmVIdHRwcycgbXVzdCBiZSBzZXQgdG8gJ2ZhbHNlJyBhbmQgYWxsb3cgSFRUUCAod2l0aG91dCBUTFMpLlwiXG4gICAgICApO1xuICAgIH1cblxuICAgIGlmICh0eXBlb2YgdGhpcy5kb2N1bWVudCA9PT0gJ3VuZGVmaW5lZCcpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcignc2lsZW50IHJlZnJlc2ggaXMgbm90IHN1cHBvcnRlZCBvbiB0aGlzIHBsYXRmb3JtJyk7XG4gICAgfVxuXG4gICAgY29uc3QgZXhpc3RpbmdJZnJhbWUgPSB0aGlzLmRvY3VtZW50LmdldEVsZW1lbnRCeUlkKFxuICAgICAgdGhpcy5zaWxlbnRSZWZyZXNoSUZyYW1lTmFtZVxuICAgICk7XG5cbiAgICBpZiAoZXhpc3RpbmdJZnJhbWUpIHtcbiAgICAgIHRoaXMuZG9jdW1lbnQuYm9keS5yZW1vdmVDaGlsZChleGlzdGluZ0lmcmFtZSk7XG4gICAgfVxuXG4gICAgdGhpcy5zaWxlbnRSZWZyZXNoU3ViamVjdCA9IGNsYWltc1snc3ViJ107XG5cbiAgICBjb25zdCBpZnJhbWUgPSB0aGlzLmRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2lmcmFtZScpO1xuICAgIGlmcmFtZS5pZCA9IHRoaXMuc2lsZW50UmVmcmVzaElGcmFtZU5hbWU7XG5cbiAgICB0aGlzLnNldHVwU2lsZW50UmVmcmVzaEV2ZW50TGlzdGVuZXIoKTtcblxuICAgIGNvbnN0IHJlZGlyZWN0VXJpID0gdGhpcy5zaWxlbnRSZWZyZXNoUmVkaXJlY3RVcmkgfHwgdGhpcy5yZWRpcmVjdFVyaTtcbiAgICB0aGlzLmNyZWF0ZUxvZ2luVXJsKG51bGwsIG51bGwsIHJlZGlyZWN0VXJpLCBub1Byb21wdCwgcGFyYW1zKS50aGVuKHVybCA9PiB7XG4gICAgICBpZnJhbWUuc2V0QXR0cmlidXRlKCdzcmMnLCB1cmwpO1xuXG4gICAgICBpZiAoIXRoaXMuc2lsZW50UmVmcmVzaFNob3dJRnJhbWUpIHtcbiAgICAgICAgaWZyYW1lLnN0eWxlWydkaXNwbGF5J10gPSAnbm9uZSc7XG4gICAgICB9XG4gICAgICB0aGlzLmRvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoaWZyYW1lKTtcbiAgICB9KTtcblxuICAgIGNvbnN0IGVycm9ycyA9IHRoaXMuZXZlbnRzLnBpcGUoXG4gICAgICBmaWx0ZXIoZSA9PiBlIGluc3RhbmNlb2YgT0F1dGhFcnJvckV2ZW50KSxcbiAgICAgIGZpcnN0KClcbiAgICApO1xuICAgIGNvbnN0IHN1Y2Nlc3MgPSB0aGlzLmV2ZW50cy5waXBlKFxuICAgICAgZmlsdGVyKGUgPT4gZS50eXBlID09PSAndG9rZW5fcmVjZWl2ZWQnKSxcbiAgICAgIGZpcnN0KClcbiAgICApO1xuICAgIGNvbnN0IHRpbWVvdXQgPSBvZihcbiAgICAgIG5ldyBPQXV0aEVycm9yRXZlbnQoJ3NpbGVudF9yZWZyZXNoX3RpbWVvdXQnLCBudWxsKVxuICAgICkucGlwZShkZWxheSh0aGlzLnNpbGVudFJlZnJlc2hUaW1lb3V0KSk7XG5cbiAgICByZXR1cm4gcmFjZShbZXJyb3JzLCBzdWNjZXNzLCB0aW1lb3V0XSlcbiAgICAgIC5waXBlKFxuICAgICAgICBtYXAoZSA9PiB7XG4gICAgICAgICAgaWYgKGUgaW5zdGFuY2VvZiBPQXV0aEVycm9yRXZlbnQpIHtcbiAgICAgICAgICAgIGlmIChlLnR5cGUgPT09ICdzaWxlbnRfcmVmcmVzaF90aW1lb3V0Jykge1xuICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChlKTtcbiAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgIGUgPSBuZXcgT0F1dGhFcnJvckV2ZW50KCdzaWxlbnRfcmVmcmVzaF9lcnJvcicsIGUpO1xuICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChlKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHRocm93IGU7XG4gICAgICAgICAgfSBlbHNlIGlmIChlLnR5cGUgPT09ICd0b2tlbl9yZWNlaXZlZCcpIHtcbiAgICAgICAgICAgIGUgPSBuZXcgT0F1dGhTdWNjZXNzRXZlbnQoJ3NpbGVudGx5X3JlZnJlc2hlZCcpO1xuICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoZSk7XG4gICAgICAgICAgfVxuICAgICAgICAgIHJldHVybiBlO1xuICAgICAgICB9KVxuICAgICAgKVxuICAgICAgLnRvUHJvbWlzZSgpO1xuICB9XG5cbiAgLyoqXG4gICAqIFRoaXMgbWV0aG9kIGV4aXN0cyBmb3IgYmFja3dhcmRzIGNvbXBhdGliaWxpdHkuXG4gICAqIHtAbGluayBPQXV0aFNlcnZpY2UjaW5pdExvZ2luRmxvd0luUG9wdXB9IGhhbmRsZXMgYm90aCBjb2RlXG4gICAqIGFuZCBpbXBsaWNpdCBmbG93cy5cbiAgICovXG4gIHB1YmxpYyBpbml0SW1wbGljaXRGbG93SW5Qb3B1cChvcHRpb25zPzoge1xuICAgIGhlaWdodD86IG51bWJlcjtcbiAgICB3aWR0aD86IG51bWJlcjtcbiAgfSkge1xuICAgIHJldHVybiB0aGlzLmluaXRMb2dpbkZsb3dJblBvcHVwKG9wdGlvbnMpO1xuICB9XG5cbiAgcHVibGljIGluaXRMb2dpbkZsb3dJblBvcHVwKG9wdGlvbnM/OiB7IGhlaWdodD86IG51bWJlcjsgd2lkdGg/OiBudW1iZXIgfSkge1xuICAgIG9wdGlvbnMgPSBvcHRpb25zIHx8IHt9O1xuICAgIHJldHVybiB0aGlzLmNyZWF0ZUxvZ2luVXJsKFxuICAgICAgbnVsbCxcbiAgICAgIG51bGwsXG4gICAgICB0aGlzLnNpbGVudFJlZnJlc2hSZWRpcmVjdFVyaSxcbiAgICAgIGZhbHNlLFxuICAgICAge1xuICAgICAgICBkaXNwbGF5OiAncG9wdXAnXG4gICAgICB9XG4gICAgKS50aGVuKHVybCA9PiB7XG4gICAgICByZXR1cm4gbmV3IFByb21pc2UoKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgICAvKipcbiAgICAgICAgICogRXJyb3IgaGFuZGxpbmcgc2VjdGlvblxuICAgICAgICAgKi9cbiAgICAgICAgY29uc3QgY2hlY2tGb3JQb3B1cENsb3NlZEludGVydmFsID0gNTAwO1xuICAgICAgICBsZXQgd2luZG93UmVmID0gd2luZG93Lm9wZW4oXG4gICAgICAgICAgdXJsLFxuICAgICAgICAgICdfYmxhbmsnLFxuICAgICAgICAgIHRoaXMuY2FsY3VsYXRlUG9wdXBGZWF0dXJlcyhvcHRpb25zKVxuICAgICAgICApO1xuICAgICAgICBsZXQgY2hlY2tGb3JQb3B1cENsb3NlZFRpbWVyOiBhbnk7XG4gICAgICAgIGNvbnN0IGNoZWNrRm9yUG9wdXBDbG9zZWQgPSAoKSA9PiB7XG4gICAgICAgICAgaWYgKCF3aW5kb3dSZWYgfHwgd2luZG93UmVmLmNsb3NlZCkge1xuICAgICAgICAgICAgY2xlYW51cCgpO1xuICAgICAgICAgICAgcmVqZWN0KG5ldyBPQXV0aEVycm9yRXZlbnQoJ3BvcHVwX2Nsb3NlZCcsIHt9KSk7XG4gICAgICAgICAgfVxuICAgICAgICB9O1xuICAgICAgICBpZiAoIXdpbmRvd1JlZikge1xuICAgICAgICAgIHJlamVjdChuZXcgT0F1dGhFcnJvckV2ZW50KCdwb3B1cF9ibG9ja2VkJywge30pKTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICBjaGVja0ZvclBvcHVwQ2xvc2VkVGltZXIgPSB3aW5kb3cuc2V0SW50ZXJ2YWwoXG4gICAgICAgICAgICBjaGVja0ZvclBvcHVwQ2xvc2VkLFxuICAgICAgICAgICAgY2hlY2tGb3JQb3B1cENsb3NlZEludGVydmFsXG4gICAgICAgICAgKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGNvbnN0IGNsZWFudXAgPSAoKSA9PiB7XG4gICAgICAgICAgd2luZG93LmNsZWFySW50ZXJ2YWwoY2hlY2tGb3JQb3B1cENsb3NlZFRpbWVyKTtcbiAgICAgICAgICB3aW5kb3cucmVtb3ZlRXZlbnRMaXN0ZW5lcignbWVzc2FnZScsIGxpc3RlbmVyKTtcbiAgICAgICAgICBpZiAod2luZG93UmVmICE9PSBudWxsKSB7XG4gICAgICAgICAgICB3aW5kb3dSZWYuY2xvc2UoKTtcbiAgICAgICAgICB9XG4gICAgICAgICAgd2luZG93UmVmID0gbnVsbDtcbiAgICAgICAgfTtcblxuICAgICAgICBjb25zdCBsaXN0ZW5lciA9IChlOiBNZXNzYWdlRXZlbnQpID0+IHtcbiAgICAgICAgICBjb25zdCBtZXNzYWdlID0gdGhpcy5wcm9jZXNzTWVzc2FnZUV2ZW50TWVzc2FnZShlKTtcblxuICAgICAgICAgIGlmIChtZXNzYWdlICYmIG1lc3NhZ2UgIT09IG51bGwpIHtcbiAgICAgICAgICAgIHRoaXMudHJ5TG9naW4oe1xuICAgICAgICAgICAgICBjdXN0b21IYXNoRnJhZ21lbnQ6IG1lc3NhZ2UsXG4gICAgICAgICAgICAgIHByZXZlbnRDbGVhckhhc2hBZnRlckxvZ2luOiB0cnVlLFxuICAgICAgICAgICAgICBjdXN0b21SZWRpcmVjdFVyaTogdGhpcy5zaWxlbnRSZWZyZXNoUmVkaXJlY3RVcmlcbiAgICAgICAgICAgIH0pLnRoZW4oXG4gICAgICAgICAgICAgICgpID0+IHtcbiAgICAgICAgICAgICAgICBjbGVhbnVwKCk7XG4gICAgICAgICAgICAgICAgcmVzb2x2ZSgpO1xuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICBlcnIgPT4ge1xuICAgICAgICAgICAgICAgIGNsZWFudXAoKTtcbiAgICAgICAgICAgICAgICByZWplY3QoZXJyKTtcbiAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgKTtcbiAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgY29uc29sZS5sb2coJ2ZhbHNlIGV2ZW50IGZpcmluZycpO1xuICAgICAgICAgIH1cbiAgICAgICAgfTtcblxuICAgICAgICB3aW5kb3cuYWRkRXZlbnRMaXN0ZW5lcignbWVzc2FnZScsIGxpc3RlbmVyKTtcbiAgICAgIH0pO1xuICAgIH0pO1xuICB9XG5cbiAgcHJvdGVjdGVkIGNhbGN1bGF0ZVBvcHVwRmVhdHVyZXMob3B0aW9uczoge1xuICAgIGhlaWdodD86IG51bWJlcjtcbiAgICB3aWR0aD86IG51bWJlcjtcbiAgfSk6IHN0cmluZyB7XG4gICAgLy8gU3BlY2lmeSBhbiBzdGF0aWMgaGVpZ2h0IGFuZCB3aWR0aCBhbmQgY2FsY3VsYXRlIGNlbnRlcmVkIHBvc2l0aW9uXG5cbiAgICBjb25zdCBoZWlnaHQgPSBvcHRpb25zLmhlaWdodCB8fCA0NzA7XG4gICAgY29uc3Qgd2lkdGggPSBvcHRpb25zLndpZHRoIHx8IDUwMDtcbiAgICBjb25zdCBsZWZ0ID0gd2luZG93LnNjcmVlbkxlZnQgKyAod2luZG93Lm91dGVyV2lkdGggLSB3aWR0aCkgLyAyO1xuICAgIGNvbnN0IHRvcCA9IHdpbmRvdy5zY3JlZW5Ub3AgKyAod2luZG93Lm91dGVySGVpZ2h0IC0gaGVpZ2h0KSAvIDI7XG4gICAgcmV0dXJuIGBsb2NhdGlvbj1ubyx0b29sYmFyPW5vLHdpZHRoPSR7d2lkdGh9LGhlaWdodD0ke2hlaWdodH0sdG9wPSR7dG9wfSxsZWZ0PSR7bGVmdH1gO1xuICB9XG5cbiAgcHJvdGVjdGVkIHByb2Nlc3NNZXNzYWdlRXZlbnRNZXNzYWdlKGU6IE1lc3NhZ2VFdmVudCk6IHN0cmluZyB7XG4gICAgbGV0IGV4cGVjdGVkUHJlZml4ID0gJyMnO1xuXG4gICAgaWYgKHRoaXMuc2lsZW50UmVmcmVzaE1lc3NhZ2VQcmVmaXgpIHtcbiAgICAgIGV4cGVjdGVkUHJlZml4ICs9IHRoaXMuc2lsZW50UmVmcmVzaE1lc3NhZ2VQcmVmaXg7XG4gICAgfVxuXG4gICAgaWYgKCFlIHx8ICFlLmRhdGEgfHwgdHlwZW9mIGUuZGF0YSAhPT0gJ3N0cmluZycpIHtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICBjb25zdCBwcmVmaXhlZE1lc3NhZ2U6IHN0cmluZyA9IGUuZGF0YTtcblxuICAgIGlmICghcHJlZml4ZWRNZXNzYWdlLnN0YXJ0c1dpdGgoZXhwZWN0ZWRQcmVmaXgpKSB7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgcmV0dXJuICcjJyArIHByZWZpeGVkTWVzc2FnZS5zdWJzdHIoZXhwZWN0ZWRQcmVmaXgubGVuZ3RoKTtcbiAgfVxuXG4gIHByb3RlY3RlZCBjYW5QZXJmb3JtU2Vzc2lvbkNoZWNrKCk6IGJvb2xlYW4ge1xuICAgIGlmICghdGhpcy5zZXNzaW9uQ2hlY2tzRW5hYmxlZCkge1xuICAgICAgcmV0dXJuIGZhbHNlO1xuICAgIH1cbiAgICBpZiAoIXRoaXMuc2Vzc2lvbkNoZWNrSUZyYW1lVXJsKSB7XG4gICAgICBjb25zb2xlLndhcm4oXG4gICAgICAgICdzZXNzaW9uQ2hlY2tzRW5hYmxlZCBpcyBhY3RpdmF0ZWQgYnV0IHRoZXJlIGlzIG5vIHNlc3Npb25DaGVja0lGcmFtZVVybCdcbiAgICAgICk7XG4gICAgICByZXR1cm4gZmFsc2U7XG4gICAgfVxuICAgIGNvbnN0IHNlc3Npb25TdGF0ZSA9IHRoaXMuZ2V0U2Vzc2lvblN0YXRlKCk7XG4gICAgaWYgKCFzZXNzaW9uU3RhdGUpIHtcbiAgICAgIGNvbnNvbGUud2FybihcbiAgICAgICAgJ3Nlc3Npb25DaGVja3NFbmFibGVkIGlzIGFjdGl2YXRlZCBidXQgdGhlcmUgaXMgbm8gc2Vzc2lvbl9zdGF0ZSdcbiAgICAgICk7XG4gICAgICByZXR1cm4gZmFsc2U7XG4gICAgfVxuICAgIGlmICh0eXBlb2YgdGhpcy5kb2N1bWVudCA9PT0gJ3VuZGVmaW5lZCcpIHtcbiAgICAgIHJldHVybiBmYWxzZTtcbiAgICB9XG5cbiAgICByZXR1cm4gdHJ1ZTtcbiAgfVxuXG4gIHByb3RlY3RlZCBzZXR1cFNlc3Npb25DaGVja0V2ZW50TGlzdGVuZXIoKTogdm9pZCB7XG4gICAgdGhpcy5yZW1vdmVTZXNzaW9uQ2hlY2tFdmVudExpc3RlbmVyKCk7XG5cbiAgICB0aGlzLnNlc3Npb25DaGVja0V2ZW50TGlzdGVuZXIgPSAoZTogTWVzc2FnZUV2ZW50KSA9PiB7XG4gICAgICBjb25zdCBvcmlnaW4gPSBlLm9yaWdpbi50b0xvd2VyQ2FzZSgpO1xuICAgICAgY29uc3QgaXNzdWVyID0gdGhpcy5pc3N1ZXIudG9Mb3dlckNhc2UoKTtcblxuICAgICAgdGhpcy5kZWJ1Zygnc2Vzc2lvbkNoZWNrRXZlbnRMaXN0ZW5lcicpO1xuXG4gICAgICBpZiAoIWlzc3Vlci5zdGFydHNXaXRoKG9yaWdpbikpIHtcbiAgICAgICAgdGhpcy5kZWJ1ZyhcbiAgICAgICAgICAnc2Vzc2lvbkNoZWNrRXZlbnRMaXN0ZW5lcicsXG4gICAgICAgICAgJ3dyb25nIG9yaWdpbicsXG4gICAgICAgICAgb3JpZ2luLFxuICAgICAgICAgICdleHBlY3RlZCcsXG4gICAgICAgICAgaXNzdWVyLFxuICAgICAgICAgICdldmVudCcsXG4gICAgICAgICAgZVxuICAgICAgICApO1xuXG4gICAgICAgIHJldHVybjtcbiAgICAgIH1cblxuICAgICAgLy8gb25seSBydW4gaW4gQW5ndWxhciB6b25lIGlmIGl0IGlzICdjaGFuZ2VkJyBvciAnZXJyb3InXG4gICAgICBzd2l0Y2ggKGUuZGF0YSkge1xuICAgICAgICBjYXNlICd1bmNoYW5nZWQnOlxuICAgICAgICAgIHRoaXMuaGFuZGxlU2Vzc2lvblVuY2hhbmdlZCgpO1xuICAgICAgICAgIGJyZWFrO1xuICAgICAgICBjYXNlICdjaGFuZ2VkJzpcbiAgICAgICAgICB0aGlzLm5nWm9uZS5ydW4oKCkgPT4ge1xuICAgICAgICAgICAgdGhpcy5oYW5kbGVTZXNzaW9uQ2hhbmdlKCk7XG4gICAgICAgICAgfSk7XG4gICAgICAgICAgYnJlYWs7XG4gICAgICAgIGNhc2UgJ2Vycm9yJzpcbiAgICAgICAgICB0aGlzLm5nWm9uZS5ydW4oKCkgPT4ge1xuICAgICAgICAgICAgdGhpcy5oYW5kbGVTZXNzaW9uRXJyb3IoKTtcbiAgICAgICAgICB9KTtcbiAgICAgICAgICBicmVhaztcbiAgICAgIH1cblxuICAgICAgdGhpcy5kZWJ1ZygnZ290IGluZm8gZnJvbSBzZXNzaW9uIGNoZWNrIGluZnJhbWUnLCBlKTtcbiAgICB9O1xuXG4gICAgLy8gcHJldmVudCBBbmd1bGFyIGZyb20gcmVmcmVzaGluZyB0aGUgdmlldyBvbiBldmVyeSBtZXNzYWdlIChydW5zIGluIGludGVydmFscylcbiAgICB0aGlzLm5nWm9uZS5ydW5PdXRzaWRlQW5ndWxhcigoKSA9PiB7XG4gICAgICB3aW5kb3cuYWRkRXZlbnRMaXN0ZW5lcignbWVzc2FnZScsIHRoaXMuc2Vzc2lvbkNoZWNrRXZlbnRMaXN0ZW5lcik7XG4gICAgfSk7XG4gIH1cblxuICBwcm90ZWN0ZWQgaGFuZGxlU2Vzc2lvblVuY2hhbmdlZCgpOiB2b2lkIHtcbiAgICB0aGlzLmRlYnVnKCdzZXNzaW9uIGNoZWNrJywgJ3Nlc3Npb24gdW5jaGFuZ2VkJyk7XG4gIH1cblxuICBwcm90ZWN0ZWQgaGFuZGxlU2Vzc2lvbkNoYW5nZSgpOiB2b2lkIHtcbiAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhJbmZvRXZlbnQoJ3Nlc3Npb25fY2hhbmdlZCcpKTtcbiAgICB0aGlzLnN0b3BTZXNzaW9uQ2hlY2tUaW1lcigpO1xuXG4gICAgaWYgKCF0aGlzLnVzZVNpbGVudFJlZnJlc2ggJiYgdGhpcy5yZXNwb25zZVR5cGUgPT09ICdjb2RlJykge1xuICAgICAgdGhpcy5yZWZyZXNoVG9rZW4oKVxuICAgICAgICAudGhlbihfID0+IHtcbiAgICAgICAgICB0aGlzLmRlYnVnKCd0b2tlbiByZWZyZXNoIGFmdGVyIHNlc3Npb24gY2hhbmdlIHdvcmtlZCcpO1xuICAgICAgICB9KVxuICAgICAgICAuY2F0Y2goXyA9PiB7XG4gICAgICAgICAgdGhpcy5kZWJ1ZygndG9rZW4gcmVmcmVzaCBkaWQgbm90IHdvcmsgYWZ0ZXIgc2Vzc2lvbiBjaGFuZ2VkJyk7XG4gICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoSW5mb0V2ZW50KCdzZXNzaW9uX3Rlcm1pbmF0ZWQnKSk7XG4gICAgICAgICAgdGhpcy5sb2dPdXQodHJ1ZSk7XG4gICAgICAgIH0pO1xuICAgIH0gZWxzZSBpZiAodGhpcy5zaWxlbnRSZWZyZXNoUmVkaXJlY3RVcmkpIHtcbiAgICAgIHRoaXMuc2lsZW50UmVmcmVzaCgpLmNhdGNoKF8gPT5cbiAgICAgICAgdGhpcy5kZWJ1Zygnc2lsZW50IHJlZnJlc2ggZmFpbGVkIGFmdGVyIHNlc3Npb24gY2hhbmdlZCcpXG4gICAgICApO1xuICAgICAgdGhpcy53YWl0Rm9yU2lsZW50UmVmcmVzaEFmdGVyU2Vzc2lvbkNoYW5nZSgpO1xuICAgIH0gZWxzZSB7XG4gICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhJbmZvRXZlbnQoJ3Nlc3Npb25fdGVybWluYXRlZCcpKTtcbiAgICAgIHRoaXMubG9nT3V0KHRydWUpO1xuICAgIH1cbiAgfVxuXG4gIHByb3RlY3RlZCB3YWl0Rm9yU2lsZW50UmVmcmVzaEFmdGVyU2Vzc2lvbkNoYW5nZSgpOiB2b2lkIHtcbiAgICB0aGlzLmV2ZW50c1xuICAgICAgLnBpcGUoXG4gICAgICAgIGZpbHRlcihcbiAgICAgICAgICAoZTogT0F1dGhFdmVudCkgPT5cbiAgICAgICAgICAgIGUudHlwZSA9PT0gJ3NpbGVudGx5X3JlZnJlc2hlZCcgfHxcbiAgICAgICAgICAgIGUudHlwZSA9PT0gJ3NpbGVudF9yZWZyZXNoX3RpbWVvdXQnIHx8XG4gICAgICAgICAgICBlLnR5cGUgPT09ICdzaWxlbnRfcmVmcmVzaF9lcnJvcidcbiAgICAgICAgKSxcbiAgICAgICAgZmlyc3QoKVxuICAgICAgKVxuICAgICAgLnN1YnNjcmliZShlID0+IHtcbiAgICAgICAgaWYgKGUudHlwZSAhPT0gJ3NpbGVudGx5X3JlZnJlc2hlZCcpIHtcbiAgICAgICAgICB0aGlzLmRlYnVnKCdzaWxlbnQgcmVmcmVzaCBkaWQgbm90IHdvcmsgYWZ0ZXIgc2Vzc2lvbiBjaGFuZ2VkJyk7XG4gICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoSW5mb0V2ZW50KCdzZXNzaW9uX3Rlcm1pbmF0ZWQnKSk7XG4gICAgICAgICAgdGhpcy5sb2dPdXQodHJ1ZSk7XG4gICAgICAgIH1cbiAgICAgIH0pO1xuICB9XG5cbiAgcHJvdGVjdGVkIGhhbmRsZVNlc3Npb25FcnJvcigpOiB2b2lkIHtcbiAgICB0aGlzLnN0b3BTZXNzaW9uQ2hlY2tUaW1lcigpO1xuICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aEluZm9FdmVudCgnc2Vzc2lvbl9lcnJvcicpKTtcbiAgfVxuXG4gIHByb3RlY3RlZCByZW1vdmVTZXNzaW9uQ2hlY2tFdmVudExpc3RlbmVyKCk6IHZvaWQge1xuICAgIGlmICh0aGlzLnNlc3Npb25DaGVja0V2ZW50TGlzdGVuZXIpIHtcbiAgICAgIHdpbmRvdy5yZW1vdmVFdmVudExpc3RlbmVyKCdtZXNzYWdlJywgdGhpcy5zZXNzaW9uQ2hlY2tFdmVudExpc3RlbmVyKTtcbiAgICAgIHRoaXMuc2Vzc2lvbkNoZWNrRXZlbnRMaXN0ZW5lciA9IG51bGw7XG4gICAgfVxuICB9XG5cbiAgcHJvdGVjdGVkIGluaXRTZXNzaW9uQ2hlY2soKTogdm9pZCB7XG4gICAgaWYgKCF0aGlzLmNhblBlcmZvcm1TZXNzaW9uQ2hlY2soKSkge1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIGNvbnN0IGV4aXN0aW5nSWZyYW1lID0gdGhpcy5kb2N1bWVudC5nZXRFbGVtZW50QnlJZChcbiAgICAgIHRoaXMuc2Vzc2lvbkNoZWNrSUZyYW1lTmFtZVxuICAgICk7XG4gICAgaWYgKGV4aXN0aW5nSWZyYW1lKSB7XG4gICAgICB0aGlzLmRvY3VtZW50LmJvZHkucmVtb3ZlQ2hpbGQoZXhpc3RpbmdJZnJhbWUpO1xuICAgIH1cblxuICAgIGNvbnN0IGlmcmFtZSA9IHRoaXMuZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnaWZyYW1lJyk7XG4gICAgaWZyYW1lLmlkID0gdGhpcy5zZXNzaW9uQ2hlY2tJRnJhbWVOYW1lO1xuXG4gICAgdGhpcy5zZXR1cFNlc3Npb25DaGVja0V2ZW50TGlzdGVuZXIoKTtcblxuICAgIGNvbnN0IHVybCA9IHRoaXMuc2Vzc2lvbkNoZWNrSUZyYW1lVXJsO1xuICAgIGlmcmFtZS5zZXRBdHRyaWJ1dGUoJ3NyYycsIHVybCk7XG4gICAgaWZyYW1lLnN0eWxlLmRpc3BsYXkgPSAnbm9uZSc7XG4gICAgdGhpcy5kb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKGlmcmFtZSk7XG5cbiAgICB0aGlzLnN0YXJ0U2Vzc2lvbkNoZWNrVGltZXIoKTtcbiAgfVxuXG4gIHByb3RlY3RlZCBzdGFydFNlc3Npb25DaGVja1RpbWVyKCk6IHZvaWQge1xuICAgIHRoaXMuc3RvcFNlc3Npb25DaGVja1RpbWVyKCk7XG4gICAgdGhpcy5uZ1pvbmUucnVuT3V0c2lkZUFuZ3VsYXIoKCkgPT4ge1xuICAgICAgdGhpcy5zZXNzaW9uQ2hlY2tUaW1lciA9IHNldEludGVydmFsKFxuICAgICAgICB0aGlzLmNoZWNrU2Vzc2lvbi5iaW5kKHRoaXMpLFxuICAgICAgICB0aGlzLnNlc3Npb25DaGVja0ludGVydmFsbFxuICAgICAgKTtcbiAgICB9KTtcbiAgfVxuXG4gIHByb3RlY3RlZCBzdG9wU2Vzc2lvbkNoZWNrVGltZXIoKTogdm9pZCB7XG4gICAgaWYgKHRoaXMuc2Vzc2lvbkNoZWNrVGltZXIpIHtcbiAgICAgIGNsZWFySW50ZXJ2YWwodGhpcy5zZXNzaW9uQ2hlY2tUaW1lcik7XG4gICAgICB0aGlzLnNlc3Npb25DaGVja1RpbWVyID0gbnVsbDtcbiAgICB9XG4gIH1cblxuICBwdWJsaWMgY2hlY2tTZXNzaW9uKCk6IHZvaWQge1xuICAgIGNvbnN0IGlmcmFtZTogYW55ID0gdGhpcy5kb2N1bWVudC5nZXRFbGVtZW50QnlJZChcbiAgICAgIHRoaXMuc2Vzc2lvbkNoZWNrSUZyYW1lTmFtZVxuICAgICk7XG5cbiAgICBpZiAoIWlmcmFtZSkge1xuICAgICAgdGhpcy5sb2dnZXIud2FybihcbiAgICAgICAgJ2NoZWNrU2Vzc2lvbiBkaWQgbm90IGZpbmQgaWZyYW1lJyxcbiAgICAgICAgdGhpcy5zZXNzaW9uQ2hlY2tJRnJhbWVOYW1lXG4gICAgICApO1xuICAgIH1cblxuICAgIGNvbnN0IHNlc3Npb25TdGF0ZSA9IHRoaXMuZ2V0U2Vzc2lvblN0YXRlKCk7XG5cbiAgICBpZiAoIXNlc3Npb25TdGF0ZSkge1xuICAgICAgdGhpcy5zdG9wU2Vzc2lvbkNoZWNrVGltZXIoKTtcbiAgICB9XG5cbiAgICBjb25zdCBtZXNzYWdlID0gdGhpcy5jbGllbnRJZCArICcgJyArIHNlc3Npb25TdGF0ZTtcbiAgICBpZnJhbWUuY29udGVudFdpbmRvdy5wb3N0TWVzc2FnZShtZXNzYWdlLCB0aGlzLmlzc3Vlcik7XG4gIH1cblxuICBwcm90ZWN0ZWQgYXN5bmMgY3JlYXRlTG9naW5VcmwoXG4gICAgc3RhdGUgPSAnJyxcbiAgICBsb2dpbkhpbnQgPSAnJyxcbiAgICBjdXN0b21SZWRpcmVjdFVyaSA9ICcnLFxuICAgIG5vUHJvbXB0ID0gZmFsc2UsXG4gICAgcGFyYW1zOiBvYmplY3QgPSB7fVxuICApOiBQcm9taXNlPHN0cmluZz4ge1xuICAgIGNvbnN0IHRoYXQgPSB0aGlzO1xuXG4gICAgbGV0IHJlZGlyZWN0VXJpOiBzdHJpbmc7XG5cbiAgICBpZiAoY3VzdG9tUmVkaXJlY3RVcmkpIHtcbiAgICAgIHJlZGlyZWN0VXJpID0gY3VzdG9tUmVkaXJlY3RVcmk7XG4gICAgfSBlbHNlIHtcbiAgICAgIHJlZGlyZWN0VXJpID0gdGhpcy5yZWRpcmVjdFVyaTtcbiAgICB9XG5cbiAgICBjb25zdCBub25jZSA9IGF3YWl0IHRoaXMuY3JlYXRlQW5kU2F2ZU5vbmNlKCk7XG5cbiAgICBpZiAoc3RhdGUpIHtcbiAgICAgIHN0YXRlID1cbiAgICAgICAgbm9uY2UgKyB0aGlzLmNvbmZpZy5ub25jZVN0YXRlU2VwYXJhdG9yICsgZW5jb2RlVVJJQ29tcG9uZW50KHN0YXRlKTtcbiAgICB9IGVsc2Uge1xuICAgICAgc3RhdGUgPSBub25jZTtcbiAgICB9XG5cbiAgICBpZiAoIXRoaXMucmVxdWVzdEFjY2Vzc1Rva2VuICYmICF0aGlzLm9pZGMpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcignRWl0aGVyIHJlcXVlc3RBY2Nlc3NUb2tlbiBvciBvaWRjIG9yIGJvdGggbXVzdCBiZSB0cnVlJyk7XG4gICAgfVxuXG4gICAgaWYgKHRoaXMuY29uZmlnLnJlc3BvbnNlVHlwZSkge1xuICAgICAgdGhpcy5yZXNwb25zZVR5cGUgPSB0aGlzLmNvbmZpZy5yZXNwb25zZVR5cGU7XG4gICAgfSBlbHNlIHtcbiAgICAgIGlmICh0aGlzLm9pZGMgJiYgdGhpcy5yZXF1ZXN0QWNjZXNzVG9rZW4pIHtcbiAgICAgICAgdGhpcy5yZXNwb25zZVR5cGUgPSAnaWRfdG9rZW4gdG9rZW4nO1xuICAgICAgfSBlbHNlIGlmICh0aGlzLm9pZGMgJiYgIXRoaXMucmVxdWVzdEFjY2Vzc1Rva2VuKSB7XG4gICAgICAgIHRoaXMucmVzcG9uc2VUeXBlID0gJ2lkX3Rva2VuJztcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHRoaXMucmVzcG9uc2VUeXBlID0gJ3Rva2VuJztcbiAgICAgIH1cbiAgICB9XG5cbiAgICBjb25zdCBzZXBlcmF0aW9uQ2hhciA9IHRoYXQubG9naW5VcmwuaW5kZXhPZignPycpID4gLTEgPyAnJicgOiAnPyc7XG5cbiAgICBsZXQgc2NvcGUgPSB0aGF0LnNjb3BlO1xuXG4gICAgaWYgKHRoaXMub2lkYyAmJiAhc2NvcGUubWF0Y2goLyhefFxccylvcGVuaWQoJHxcXHMpLykpIHtcbiAgICAgIHNjb3BlID0gJ29wZW5pZCAnICsgc2NvcGU7XG4gICAgfVxuXG4gICAgbGV0IHVybCA9XG4gICAgICB0aGF0LmxvZ2luVXJsICtcbiAgICAgIHNlcGVyYXRpb25DaGFyICtcbiAgICAgICdyZXNwb25zZV90eXBlPScgK1xuICAgICAgZW5jb2RlVVJJQ29tcG9uZW50KHRoYXQucmVzcG9uc2VUeXBlKSArXG4gICAgICAnJmNsaWVudF9pZD0nICtcbiAgICAgIGVuY29kZVVSSUNvbXBvbmVudCh0aGF0LmNsaWVudElkKSArXG4gICAgICAnJnN0YXRlPScgK1xuICAgICAgZW5jb2RlVVJJQ29tcG9uZW50KHN0YXRlKSArXG4gICAgICAnJnJlZGlyZWN0X3VyaT0nICtcbiAgICAgIGVuY29kZVVSSUNvbXBvbmVudChyZWRpcmVjdFVyaSkgK1xuICAgICAgJyZzY29wZT0nICtcbiAgICAgIGVuY29kZVVSSUNvbXBvbmVudChzY29wZSk7XG5cbiAgICBpZiAodGhpcy5yZXNwb25zZVR5cGUuaW5jbHVkZXMoJ2NvZGUnKSAmJiAhdGhpcy5kaXNhYmxlUEtDRSkge1xuICAgICAgY29uc3QgW1xuICAgICAgICBjaGFsbGVuZ2UsXG4gICAgICAgIHZlcmlmaWVyXG4gICAgICBdID0gYXdhaXQgdGhpcy5jcmVhdGVDaGFsbGFuZ2VWZXJpZmllclBhaXJGb3JQS0NFKCk7XG5cbiAgICAgIGlmIChcbiAgICAgICAgdGhpcy5zYXZlTm9uY2VzSW5Mb2NhbFN0b3JhZ2UgJiZcbiAgICAgICAgdHlwZW9mIHdpbmRvd1snbG9jYWxTdG9yYWdlJ10gIT09ICd1bmRlZmluZWQnXG4gICAgICApIHtcbiAgICAgICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oJ1BLQ0VfdmVyaWZpZXInLCB2ZXJpZmllcik7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oJ1BLQ0VfdmVyaWZpZXInLCB2ZXJpZmllcik7XG4gICAgICB9XG5cbiAgICAgIHVybCArPSAnJmNvZGVfY2hhbGxlbmdlPScgKyBjaGFsbGVuZ2U7XG4gICAgICB1cmwgKz0gJyZjb2RlX2NoYWxsZW5nZV9tZXRob2Q9UzI1Nic7XG4gICAgfVxuXG4gICAgaWYgKGxvZ2luSGludCkge1xuICAgICAgdXJsICs9ICcmbG9naW5faGludD0nICsgZW5jb2RlVVJJQ29tcG9uZW50KGxvZ2luSGludCk7XG4gICAgfVxuXG4gICAgaWYgKHRoYXQucmVzb3VyY2UpIHtcbiAgICAgIHVybCArPSAnJnJlc291cmNlPScgKyBlbmNvZGVVUklDb21wb25lbnQodGhhdC5yZXNvdXJjZSk7XG4gICAgfVxuXG4gICAgaWYgKHRoYXQub2lkYykge1xuICAgICAgdXJsICs9ICcmbm9uY2U9JyArIGVuY29kZVVSSUNvbXBvbmVudChub25jZSk7XG4gICAgfVxuXG4gICAgaWYgKG5vUHJvbXB0KSB7XG4gICAgICB1cmwgKz0gJyZwcm9tcHQ9bm9uZSc7XG4gICAgfVxuXG4gICAgZm9yIChjb25zdCBrZXkgb2YgT2JqZWN0LmtleXMocGFyYW1zKSkge1xuICAgICAgdXJsICs9XG4gICAgICAgICcmJyArIGVuY29kZVVSSUNvbXBvbmVudChrZXkpICsgJz0nICsgZW5jb2RlVVJJQ29tcG9uZW50KHBhcmFtc1trZXldKTtcbiAgICB9XG5cbiAgICBpZiAodGhpcy5jdXN0b21RdWVyeVBhcmFtcykge1xuICAgICAgZm9yIChjb25zdCBrZXkgb2YgT2JqZWN0LmdldE93blByb3BlcnR5TmFtZXModGhpcy5jdXN0b21RdWVyeVBhcmFtcykpIHtcbiAgICAgICAgdXJsICs9XG4gICAgICAgICAgJyYnICsga2V5ICsgJz0nICsgZW5jb2RlVVJJQ29tcG9uZW50KHRoaXMuY3VzdG9tUXVlcnlQYXJhbXNba2V5XSk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgcmV0dXJuIHVybDtcbiAgfVxuXG4gIGluaXRJbXBsaWNpdEZsb3dJbnRlcm5hbChcbiAgICBhZGRpdGlvbmFsU3RhdGUgPSAnJyxcbiAgICBwYXJhbXM6IHN0cmluZyB8IG9iamVjdCA9ICcnXG4gICk6IHZvaWQge1xuICAgIGlmICh0aGlzLmluSW1wbGljaXRGbG93KSB7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgdGhpcy5pbkltcGxpY2l0RmxvdyA9IHRydWU7XG5cbiAgICBpZiAoIXRoaXMudmFsaWRhdGVVcmxGb3JIdHRwcyh0aGlzLmxvZ2luVXJsKSkge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKFxuICAgICAgICBcImxvZ2luVXJsICBtdXN0IHVzZSBIVFRQUyAod2l0aCBUTFMpLCBvciBjb25maWcgdmFsdWUgZm9yIHByb3BlcnR5ICdyZXF1aXJlSHR0cHMnIG11c3QgYmUgc2V0IHRvICdmYWxzZScgYW5kIGFsbG93IEhUVFAgKHdpdGhvdXQgVExTKS5cIlxuICAgICAgKTtcbiAgICB9XG5cbiAgICBsZXQgYWRkUGFyYW1zOiBvYmplY3QgPSB7fTtcbiAgICBsZXQgbG9naW5IaW50OiBzdHJpbmcgPSBudWxsO1xuXG4gICAgaWYgKHR5cGVvZiBwYXJhbXMgPT09ICdzdHJpbmcnKSB7XG4gICAgICBsb2dpbkhpbnQgPSBwYXJhbXM7XG4gICAgfSBlbHNlIGlmICh0eXBlb2YgcGFyYW1zID09PSAnb2JqZWN0Jykge1xuICAgICAgYWRkUGFyYW1zID0gcGFyYW1zO1xuICAgIH1cblxuICAgIHRoaXMuY3JlYXRlTG9naW5VcmwoYWRkaXRpb25hbFN0YXRlLCBsb2dpbkhpbnQsIG51bGwsIGZhbHNlLCBhZGRQYXJhbXMpXG4gICAgICAudGhlbih0aGlzLmNvbmZpZy5vcGVuVXJpKVxuICAgICAgLmNhdGNoKGVycm9yID0+IHtcbiAgICAgICAgY29uc29sZS5lcnJvcignRXJyb3IgaW4gaW5pdEltcGxpY2l0RmxvdycsIGVycm9yKTtcbiAgICAgICAgdGhpcy5pbkltcGxpY2l0RmxvdyA9IGZhbHNlO1xuICAgICAgfSk7XG4gIH1cblxuICAvKipcbiAgICogU3RhcnRzIHRoZSBpbXBsaWNpdCBmbG93IGFuZCByZWRpcmVjdHMgdG8gdXNlciB0b1xuICAgKiB0aGUgYXV0aCBzZXJ2ZXJzJyBsb2dpbiB1cmwuXG4gICAqXG4gICAqIEBwYXJhbSBhZGRpdGlvbmFsU3RhdGUgT3B0aW9uYWwgc3RhdGUgdGhhdCBpcyBwYXNzZWQgYXJvdW5kLlxuICAgKiAgWW91J2xsIGZpbmQgdGhpcyBzdGF0ZSBpbiB0aGUgcHJvcGVydHkgYHN0YXRlYCBhZnRlciBgdHJ5TG9naW5gIGxvZ2dlZCBpbiB0aGUgdXNlci5cbiAgICogQHBhcmFtIHBhcmFtcyBIYXNoIHdpdGggYWRkaXRpb25hbCBwYXJhbWV0ZXIuIElmIGl0IGlzIGEgc3RyaW5nLCBpdCBpcyB1c2VkIGZvciB0aGVcbiAgICogICAgICAgICAgICAgICBwYXJhbWV0ZXIgbG9naW5IaW50IChmb3IgdGhlIHNha2Ugb2YgY29tcGF0aWJpbGl0eSB3aXRoIGZvcm1lciB2ZXJzaW9ucylcbiAgICovXG4gIHB1YmxpYyBpbml0SW1wbGljaXRGbG93KFxuICAgIGFkZGl0aW9uYWxTdGF0ZSA9ICcnLFxuICAgIHBhcmFtczogc3RyaW5nIHwgb2JqZWN0ID0gJydcbiAgKTogdm9pZCB7XG4gICAgaWYgKHRoaXMubG9naW5VcmwgIT09ICcnKSB7XG4gICAgICB0aGlzLmluaXRJbXBsaWNpdEZsb3dJbnRlcm5hbChhZGRpdGlvbmFsU3RhdGUsIHBhcmFtcyk7XG4gICAgfSBlbHNlIHtcbiAgICAgIHRoaXMuZXZlbnRzXG4gICAgICAgIC5waXBlKGZpbHRlcihlID0+IGUudHlwZSA9PT0gJ2Rpc2NvdmVyeV9kb2N1bWVudF9sb2FkZWQnKSlcbiAgICAgICAgLnN1YnNjcmliZShfID0+IHRoaXMuaW5pdEltcGxpY2l0Rmxvd0ludGVybmFsKGFkZGl0aW9uYWxTdGF0ZSwgcGFyYW1zKSk7XG4gICAgfVxuICB9XG5cbiAgLyoqXG4gICAqIFJlc2V0IGN1cnJlbnQgaW1wbGljaXQgZmxvd1xuICAgKlxuICAgKiBAZGVzY3JpcHRpb24gVGhpcyBtZXRob2QgYWxsb3dzIHJlc2V0dGluZyB0aGUgY3VycmVudCBpbXBsaWN0IGZsb3cgaW4gb3JkZXIgdG8gYmUgaW5pdGlhbGl6ZWQgYWdhaW4uXG4gICAqL1xuICBwdWJsaWMgcmVzZXRJbXBsaWNpdEZsb3coKTogdm9pZCB7XG4gICAgdGhpcy5pbkltcGxpY2l0RmxvdyA9IGZhbHNlO1xuICB9XG5cbiAgcHJvdGVjdGVkIGNhbGxPblRva2VuUmVjZWl2ZWRJZkV4aXN0cyhvcHRpb25zOiBMb2dpbk9wdGlvbnMpOiB2b2lkIHtcbiAgICBjb25zdCB0aGF0ID0gdGhpcztcbiAgICBpZiAob3B0aW9ucy5vblRva2VuUmVjZWl2ZWQpIHtcbiAgICAgIGNvbnN0IHRva2VuUGFyYW1zID0ge1xuICAgICAgICBpZENsYWltczogdGhhdC5nZXRJZGVudGl0eUNsYWltcygpLFxuICAgICAgICBpZFRva2VuOiB0aGF0LmdldElkVG9rZW4oKSxcbiAgICAgICAgYWNjZXNzVG9rZW46IHRoYXQuZ2V0QWNjZXNzVG9rZW4oKSxcbiAgICAgICAgc3RhdGU6IHRoYXQuc3RhdGVcbiAgICAgIH07XG4gICAgICBvcHRpb25zLm9uVG9rZW5SZWNlaXZlZCh0b2tlblBhcmFtcyk7XG4gICAgfVxuICB9XG5cbiAgcHJvdGVjdGVkIHN0b3JlQWNjZXNzVG9rZW5SZXNwb25zZShcbiAgICBhY2Nlc3NUb2tlbjogc3RyaW5nLFxuICAgIHJlZnJlc2hUb2tlbjogc3RyaW5nLFxuICAgIGV4cGlyZXNJbjogbnVtYmVyLFxuICAgIGdyYW50ZWRTY29wZXM6IFN0cmluZyxcbiAgICBjdXN0b21QYXJhbWV0ZXJzPzogTWFwPHN0cmluZywgc3RyaW5nPlxuICApOiB2b2lkIHtcbiAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oJ2FjY2Vzc190b2tlbicsIGFjY2Vzc1Rva2VuKTtcbiAgICBpZiAoZ3JhbnRlZFNjb3BlcyAmJiAhQXJyYXkuaXNBcnJheShncmFudGVkU2NvcGVzKSkge1xuICAgICAgdGhpcy5fc3RvcmFnZS5zZXRJdGVtKFxuICAgICAgICAnZ3JhbnRlZF9zY29wZXMnLFxuICAgICAgICBKU09OLnN0cmluZ2lmeShncmFudGVkU2NvcGVzLnNwbGl0KCcrJykpXG4gICAgICApO1xuICAgIH0gZWxzZSBpZiAoZ3JhbnRlZFNjb3BlcyAmJiBBcnJheS5pc0FycmF5KGdyYW50ZWRTY29wZXMpKSB7XG4gICAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oJ2dyYW50ZWRfc2NvcGVzJywgSlNPTi5zdHJpbmdpZnkoZ3JhbnRlZFNjb3BlcykpO1xuICAgIH1cblxuICAgIHRoaXMuX3N0b3JhZ2Uuc2V0SXRlbSgnYWNjZXNzX3Rva2VuX3N0b3JlZF9hdCcsICcnICsgRGF0ZS5ub3coKSk7XG4gICAgaWYgKGV4cGlyZXNJbikge1xuICAgICAgY29uc3QgZXhwaXJlc0luTWlsbGlTZWNvbmRzID0gZXhwaXJlc0luICogMTAwMDtcbiAgICAgIGNvbnN0IG5vdyA9IG5ldyBEYXRlKCk7XG4gICAgICBjb25zdCBleHBpcmVzQXQgPSBub3cuZ2V0VGltZSgpICsgZXhwaXJlc0luTWlsbGlTZWNvbmRzO1xuICAgICAgdGhpcy5fc3RvcmFnZS5zZXRJdGVtKCdleHBpcmVzX2F0JywgJycgKyBleHBpcmVzQXQpO1xuICAgIH1cblxuICAgIGlmIChyZWZyZXNoVG9rZW4pIHtcbiAgICAgIHRoaXMuX3N0b3JhZ2Uuc2V0SXRlbSgncmVmcmVzaF90b2tlbicsIHJlZnJlc2hUb2tlbik7XG4gICAgfVxuICAgIGlmIChjdXN0b21QYXJhbWV0ZXJzKSB7XG4gICAgICBjdXN0b21QYXJhbWV0ZXJzLmZvckVhY2goKHZhbHVlOiBzdHJpbmcsIGtleTogc3RyaW5nKSA9PiB7XG4gICAgICAgIHRoaXMuX3N0b3JhZ2Uuc2V0SXRlbShrZXksIHZhbHVlKTtcbiAgICAgIH0pO1xuICAgIH1cbiAgfVxuXG4gIC8qKlxuICAgKiBEZWxlZ2F0ZXMgdG8gdHJ5TG9naW5JbXBsaWNpdEZsb3cgZm9yIHRoZSBzYWtlIG9mIGNvbXBldGFiaWxpdHlcbiAgICogQHBhcmFtIG9wdGlvbnMgT3B0aW9uYWwgb3B0aW9ucy5cbiAgICovXG4gIHB1YmxpYyB0cnlMb2dpbihvcHRpb25zOiBMb2dpbk9wdGlvbnMgPSBudWxsKTogUHJvbWlzZTxib29sZWFuPiB7XG4gICAgaWYgKHRoaXMuY29uZmlnLnJlc3BvbnNlVHlwZSA9PT0gJ2NvZGUnKSB7XG4gICAgICByZXR1cm4gdGhpcy50cnlMb2dpbkNvZGVGbG93KG9wdGlvbnMpLnRoZW4oXyA9PiB0cnVlKTtcbiAgICB9IGVsc2Uge1xuICAgICAgcmV0dXJuIHRoaXMudHJ5TG9naW5JbXBsaWNpdEZsb3cob3B0aW9ucyk7XG4gICAgfVxuICB9XG5cbiAgcHJpdmF0ZSBwYXJzZVF1ZXJ5U3RyaW5nKHF1ZXJ5U3RyaW5nOiBzdHJpbmcpOiBvYmplY3Qge1xuICAgIGlmICghcXVlcnlTdHJpbmcgfHwgcXVlcnlTdHJpbmcubGVuZ3RoID09PSAwKSB7XG4gICAgICByZXR1cm4ge307XG4gICAgfVxuXG4gICAgaWYgKHF1ZXJ5U3RyaW5nLmNoYXJBdCgwKSA9PT0gJz8nKSB7XG4gICAgICBxdWVyeVN0cmluZyA9IHF1ZXJ5U3RyaW5nLnN1YnN0cigxKTtcbiAgICB9XG5cbiAgICByZXR1cm4gdGhpcy51cmxIZWxwZXIucGFyc2VRdWVyeVN0cmluZyhxdWVyeVN0cmluZyk7XG4gIH1cblxuICBwdWJsaWMgdHJ5TG9naW5Db2RlRmxvdyhvcHRpb25zOiBMb2dpbk9wdGlvbnMgPSBudWxsKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgb3B0aW9ucyA9IG9wdGlvbnMgfHwge307XG5cbiAgICBjb25zdCBxdWVyeVNvdXJjZSA9IG9wdGlvbnMuY3VzdG9tSGFzaEZyYWdtZW50XG4gICAgICA/IG9wdGlvbnMuY3VzdG9tSGFzaEZyYWdtZW50LnN1YnN0cmluZygxKVxuICAgICAgOiB3aW5kb3cubG9jYXRpb24uc2VhcmNoO1xuXG4gICAgY29uc3QgcGFydHMgPSB0aGlzLmdldENvZGVQYXJ0c0Zyb21VcmwocXVlcnlTb3VyY2UpO1xuXG4gICAgY29uc3QgY29kZSA9IHBhcnRzWydjb2RlJ107XG4gICAgY29uc3Qgc3RhdGUgPSBwYXJ0c1snc3RhdGUnXTtcblxuICAgIGNvbnN0IHNlc3Npb25TdGF0ZSA9IHBhcnRzWydzZXNzaW9uX3N0YXRlJ107XG5cbiAgICBpZiAoIW9wdGlvbnMucHJldmVudENsZWFySGFzaEFmdGVyTG9naW4pIHtcbiAgICAgIGNvbnN0IGhyZWYgPSBsb2NhdGlvbi5ocmVmXG4gICAgICAgIC5yZXBsYWNlKC9bJlxcP11jb2RlPVteJlxcJF0qLywgJycpXG4gICAgICAgIC5yZXBsYWNlKC9bJlxcP11zY29wZT1bXiZcXCRdKi8sICcnKVxuICAgICAgICAucmVwbGFjZSgvWyZcXD9dc3RhdGU9W14mXFwkXSovLCAnJylcbiAgICAgICAgLnJlcGxhY2UoL1smXFw/XXNlc3Npb25fc3RhdGU9W14mXFwkXSovLCAnJyk7XG5cbiAgICAgIGhpc3RvcnkucmVwbGFjZVN0YXRlKG51bGwsIHdpbmRvdy5uYW1lLCBocmVmKTtcbiAgICB9XG5cbiAgICBsZXQgW25vbmNlSW5TdGF0ZSwgdXNlclN0YXRlXSA9IHRoaXMucGFyc2VTdGF0ZShzdGF0ZSk7XG4gICAgdGhpcy5zdGF0ZSA9IHVzZXJTdGF0ZTtcblxuICAgIGlmIChwYXJ0c1snZXJyb3InXSkge1xuICAgICAgdGhpcy5kZWJ1ZygnZXJyb3IgdHJ5aW5nIHRvIGxvZ2luJyk7XG4gICAgICB0aGlzLmhhbmRsZUxvZ2luRXJyb3Ioe30sIHBhcnRzKTtcbiAgICAgIGNvbnN0IGVyciA9IG5ldyBPQXV0aEVycm9yRXZlbnQoJ2NvZGVfZXJyb3InLCB7fSwgcGFydHMpO1xuICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoZXJyKTtcbiAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpO1xuICAgIH1cblxuICAgIGlmICghbm9uY2VJblN0YXRlKSB7XG4gICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKCk7XG4gICAgfVxuXG4gICAgY29uc3Qgc3VjY2VzcyA9IHRoaXMudmFsaWRhdGVOb25jZShub25jZUluU3RhdGUpO1xuICAgIGlmICghc3VjY2Vzcykge1xuICAgICAgY29uc3QgZXZlbnQgPSBuZXcgT0F1dGhFcnJvckV2ZW50KCdpbnZhbGlkX25vbmNlX2luX3N0YXRlJywgbnVsbCk7XG4gICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChldmVudCk7XG4gICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXZlbnQpO1xuICAgIH1cblxuICAgIHRoaXMuc3RvcmVTZXNzaW9uU3RhdGUoc2Vzc2lvblN0YXRlKTtcblxuICAgIGlmIChjb2RlKSB7XG4gICAgICByZXR1cm4gdGhpcy5nZXRUb2tlbkZyb21Db2RlKGNvZGUsIG9wdGlvbnMpLnRoZW4oXyA9PiBudWxsKTtcbiAgICB9IGVsc2Uge1xuICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSgpO1xuICAgIH1cbiAgfVxuXG4gIC8qKlxuICAgKiBSZXRyaWV2ZSB0aGUgcmV0dXJuZWQgYXV0aCBjb2RlIGZyb20gdGhlIHJlZGlyZWN0IHVyaSB0aGF0IGhhcyBiZWVuIGNhbGxlZC5cbiAgICogSWYgcmVxdWlyZWQgYWxzbyBjaGVjayBoYXNoLCBhcyB3ZSBjb3VsZCB1c2UgaGFzaCBsb2NhdGlvbiBzdHJhdGVneS5cbiAgICovXG4gIHByaXZhdGUgZ2V0Q29kZVBhcnRzRnJvbVVybChxdWVyeVN0cmluZzogc3RyaW5nKTogb2JqZWN0IHtcbiAgICBpZiAoIXF1ZXJ5U3RyaW5nIHx8IHF1ZXJ5U3RyaW5nLmxlbmd0aCA9PT0gMCkge1xuICAgICAgcmV0dXJuIHRoaXMudXJsSGVscGVyLmdldEhhc2hGcmFnbWVudFBhcmFtcygpO1xuICAgIH1cblxuICAgIC8vIG5vcm1hbGl6ZSBxdWVyeSBzdHJpbmdcbiAgICBpZiAocXVlcnlTdHJpbmcuY2hhckF0KDApID09PSAnPycpIHtcbiAgICAgIHF1ZXJ5U3RyaW5nID0gcXVlcnlTdHJpbmcuc3Vic3RyKDEpO1xuICAgIH1cblxuICAgIHJldHVybiB0aGlzLnVybEhlbHBlci5wYXJzZVF1ZXJ5U3RyaW5nKHF1ZXJ5U3RyaW5nKTtcbiAgfVxuXG4gIC8qKlxuICAgKiBHZXQgdG9rZW4gdXNpbmcgYW4gaW50ZXJtZWRpYXRlIGNvZGUuIFdvcmtzIGZvciB0aGUgQXV0aG9yaXphdGlvbiBDb2RlIGZsb3cuXG4gICAqL1xuICBwcml2YXRlIGdldFRva2VuRnJvbUNvZGUoXG4gICAgY29kZTogc3RyaW5nLFxuICAgIG9wdGlvbnM6IExvZ2luT3B0aW9uc1xuICApOiBQcm9taXNlPG9iamVjdD4ge1xuICAgIGxldCBwYXJhbXMgPSBuZXcgSHR0cFBhcmFtcygpXG4gICAgICAuc2V0KCdncmFudF90eXBlJywgJ2F1dGhvcml6YXRpb25fY29kZScpXG4gICAgICAuc2V0KCdjb2RlJywgY29kZSlcbiAgICAgIC5zZXQoJ3JlZGlyZWN0X3VyaScsIG9wdGlvbnMuY3VzdG9tUmVkaXJlY3RVcmkgfHwgdGhpcy5yZWRpcmVjdFVyaSk7XG5cbiAgICBpZiAoIXRoaXMuZGlzYWJsZVBLQ0UpIHtcbiAgICAgIGxldCBQS0NFVmVyaWZpZXI7XG5cbiAgICAgIGlmIChcbiAgICAgICAgdGhpcy5zYXZlTm9uY2VzSW5Mb2NhbFN0b3JhZ2UgJiZcbiAgICAgICAgdHlwZW9mIHdpbmRvd1snbG9jYWxTdG9yYWdlJ10gIT09ICd1bmRlZmluZWQnXG4gICAgICApIHtcbiAgICAgICAgUEtDRVZlcmlmaWVyID0gbG9jYWxTdG9yYWdlLmdldEl0ZW0oJ1BLQ0VfdmVyaWZpZXInKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIFBLQ0VWZXJpZmllciA9IHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnUEtDRV92ZXJpZmllcicpO1xuICAgICAgfVxuXG4gICAgICBpZiAoIVBLQ0VWZXJpZmllcikge1xuICAgICAgICBjb25zb2xlLndhcm4oJ05vIFBLQ0UgdmVyaWZpZXIgZm91bmQgaW4gb2F1dGggc3RvcmFnZSEnKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoJ2NvZGVfdmVyaWZpZXInLCBQS0NFVmVyaWZpZXIpO1xuICAgICAgfVxuICAgIH1cblxuICAgIHJldHVybiB0aGlzLmZldGNoQW5kUHJvY2Vzc1Rva2VuKHBhcmFtcyk7XG4gIH1cblxuICBwcml2YXRlIGZldGNoQW5kUHJvY2Vzc1Rva2VuKHBhcmFtczogSHR0cFBhcmFtcyk6IFByb21pc2U8VG9rZW5SZXNwb25zZT4ge1xuICAgIHRoaXMuYXNzZXJ0VXJsTm90TnVsbEFuZENvcnJlY3RQcm90b2NvbChcbiAgICAgIHRoaXMudG9rZW5FbmRwb2ludCxcbiAgICAgICd0b2tlbkVuZHBvaW50J1xuICAgICk7XG4gICAgbGV0IGhlYWRlcnMgPSBuZXcgSHR0cEhlYWRlcnMoKS5zZXQoXG4gICAgICAnQ29udGVudC1UeXBlJyxcbiAgICAgICdhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWQnXG4gICAgKTtcblxuICAgIGlmICh0aGlzLnVzZUh0dHBCYXNpY0F1dGgpIHtcbiAgICAgIGNvbnN0IGhlYWRlciA9IGJ0b2EoYCR7dGhpcy5jbGllbnRJZH06JHt0aGlzLmR1bW15Q2xpZW50U2VjcmV0fWApO1xuICAgICAgaGVhZGVycyA9IGhlYWRlcnMuc2V0KCdBdXRob3JpemF0aW9uJywgJ0Jhc2ljICcgKyBoZWFkZXIpO1xuICAgIH1cblxuICAgIGlmICghdGhpcy51c2VIdHRwQmFzaWNBdXRoKSB7XG4gICAgICBwYXJhbXMgPSBwYXJhbXMuc2V0KCdjbGllbnRfaWQnLCB0aGlzLmNsaWVudElkKTtcbiAgICB9XG5cbiAgICBpZiAoIXRoaXMudXNlSHR0cEJhc2ljQXV0aCAmJiB0aGlzLmR1bW15Q2xpZW50U2VjcmV0KSB7XG4gICAgICBwYXJhbXMgPSBwYXJhbXMuc2V0KCdjbGllbnRfc2VjcmV0JywgdGhpcy5kdW1teUNsaWVudFNlY3JldCk7XG4gICAgfVxuXG4gICAgcmV0dXJuIG5ldyBQcm9taXNlKChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIGlmICh0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zKSB7XG4gICAgICAgIGZvciAobGV0IGtleSBvZiBPYmplY3QuZ2V0T3duUHJvcGVydHlOYW1lcyh0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zKSkge1xuICAgICAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoa2V5LCB0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zW2tleV0pO1xuICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIHRoaXMuaHR0cFxuICAgICAgICAucG9zdDxUb2tlblJlc3BvbnNlPih0aGlzLnRva2VuRW5kcG9pbnQsIHBhcmFtcywgeyBoZWFkZXJzIH0pXG4gICAgICAgIC5zdWJzY3JpYmUoXG4gICAgICAgICAgdG9rZW5SZXNwb25zZSA9PiB7XG4gICAgICAgICAgICB0aGlzLmRlYnVnKCdyZWZyZXNoIHRva2VuUmVzcG9uc2UnLCB0b2tlblJlc3BvbnNlKTtcbiAgICAgICAgICAgIHRoaXMuc3RvcmVBY2Nlc3NUb2tlblJlc3BvbnNlKFxuICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLmFjY2Vzc190b2tlbixcbiAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5yZWZyZXNoX3Rva2VuLFxuICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLmV4cGlyZXNfaW4gfHxcbiAgICAgICAgICAgICAgICB0aGlzLmZhbGxiYWNrQWNjZXNzVG9rZW5FeHBpcmF0aW9uVGltZUluU2VjLFxuICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLnNjb3BlLFxuICAgICAgICAgICAgICB0aGlzLmV4dHJhY3RSZWNvZ25pemVkQ3VzdG9tUGFyYW1ldGVycyh0b2tlblJlc3BvbnNlKVxuICAgICAgICAgICAgKTtcblxuICAgICAgICAgICAgaWYgKHRoaXMub2lkYyAmJiB0b2tlblJlc3BvbnNlLmlkX3Rva2VuKSB7XG4gICAgICAgICAgICAgIHRoaXMucHJvY2Vzc0lkVG9rZW4oXG4gICAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5pZF90b2tlbixcbiAgICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLmFjY2Vzc190b2tlblxuICAgICAgICAgICAgICApXG4gICAgICAgICAgICAgICAgLnRoZW4ocmVzdWx0ID0+IHtcbiAgICAgICAgICAgICAgICAgIHRoaXMuc3RvcmVJZFRva2VuKHJlc3VsdCk7XG5cbiAgICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KFxuICAgICAgICAgICAgICAgICAgICBuZXcgT0F1dGhTdWNjZXNzRXZlbnQoJ3Rva2VuX3JlY2VpdmVkJylcbiAgICAgICAgICAgICAgICAgICk7XG4gICAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChcbiAgICAgICAgICAgICAgICAgICAgbmV3IE9BdXRoU3VjY2Vzc0V2ZW50KCd0b2tlbl9yZWZyZXNoZWQnKVxuICAgICAgICAgICAgICAgICAgKTtcblxuICAgICAgICAgICAgICAgICAgcmVzb2x2ZSh0b2tlblJlc3BvbnNlKTtcbiAgICAgICAgICAgICAgICB9KVxuICAgICAgICAgICAgICAgIC5jYXRjaChyZWFzb24gPT4ge1xuICAgICAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoXG4gICAgICAgICAgICAgICAgICAgIG5ldyBPQXV0aEVycm9yRXZlbnQoJ3Rva2VuX3ZhbGlkYXRpb25fZXJyb3InLCByZWFzb24pXG4gICAgICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgICAgICAgY29uc29sZS5lcnJvcignRXJyb3IgdmFsaWRhdGluZyB0b2tlbnMnKTtcbiAgICAgICAgICAgICAgICAgIGNvbnNvbGUuZXJyb3IocmVhc29uKTtcblxuICAgICAgICAgICAgICAgICAgcmVqZWN0KHJlYXNvbik7XG4gICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhTdWNjZXNzRXZlbnQoJ3Rva2VuX3JlY2VpdmVkJykpO1xuICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhTdWNjZXNzRXZlbnQoJ3Rva2VuX3JlZnJlc2hlZCcpKTtcblxuICAgICAgICAgICAgICByZXNvbHZlKHRva2VuUmVzcG9uc2UpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgIH0sXG4gICAgICAgICAgZXJyID0+IHtcbiAgICAgICAgICAgIGNvbnNvbGUuZXJyb3IoJ0Vycm9yIGdldHRpbmcgdG9rZW4nLCBlcnIpO1xuICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoXG4gICAgICAgICAgICAgIG5ldyBPQXV0aEVycm9yRXZlbnQoJ3Rva2VuX3JlZnJlc2hfZXJyb3InLCBlcnIpXG4gICAgICAgICAgICApO1xuICAgICAgICAgICAgcmVqZWN0KGVycik7XG4gICAgICAgICAgfVxuICAgICAgICApO1xuICAgIH0pO1xuICB9XG5cbiAgLyoqXG4gICAqIENoZWNrcyB3aGV0aGVyIHRoZXJlIGFyZSB0b2tlbnMgaW4gdGhlIGhhc2ggZnJhZ21lbnRcbiAgICogYXMgYSByZXN1bHQgb2YgdGhlIGltcGxpY2l0IGZsb3cuIFRoZXNlIHRva2VucyBhcmVcbiAgICogcGFyc2VkLCB2YWxpZGF0ZWQgYW5kIHVzZWQgdG8gc2lnbiB0aGUgdXNlciBpbiB0byB0aGVcbiAgICogY3VycmVudCBjbGllbnQuXG4gICAqXG4gICAqIEBwYXJhbSBvcHRpb25zIE9wdGlvbmFsIG9wdGlvbnMuXG4gICAqL1xuICBwdWJsaWMgdHJ5TG9naW5JbXBsaWNpdEZsb3cob3B0aW9uczogTG9naW5PcHRpb25zID0gbnVsbCk6IFByb21pc2U8Ym9vbGVhbj4ge1xuICAgIG9wdGlvbnMgPSBvcHRpb25zIHx8IHt9O1xuXG4gICAgbGV0IHBhcnRzOiBvYmplY3Q7XG5cbiAgICBpZiAob3B0aW9ucy5jdXN0b21IYXNoRnJhZ21lbnQpIHtcbiAgICAgIHBhcnRzID0gdGhpcy51cmxIZWxwZXIuZ2V0SGFzaEZyYWdtZW50UGFyYW1zKG9wdGlvbnMuY3VzdG9tSGFzaEZyYWdtZW50KTtcbiAgICB9IGVsc2Uge1xuICAgICAgcGFydHMgPSB0aGlzLnVybEhlbHBlci5nZXRIYXNoRnJhZ21lbnRQYXJhbXMoKTtcbiAgICB9XG5cbiAgICB0aGlzLmRlYnVnKCdwYXJzZWQgdXJsJywgcGFydHMpO1xuXG4gICAgY29uc3Qgc3RhdGUgPSBwYXJ0c1snc3RhdGUnXTtcblxuICAgIGxldCBbbm9uY2VJblN0YXRlLCB1c2VyU3RhdGVdID0gdGhpcy5wYXJzZVN0YXRlKHN0YXRlKTtcbiAgICB0aGlzLnN0YXRlID0gdXNlclN0YXRlO1xuXG4gICAgaWYgKHBhcnRzWydlcnJvciddKSB7XG4gICAgICB0aGlzLmRlYnVnKCdlcnJvciB0cnlpbmcgdG8gbG9naW4nKTtcbiAgICAgIHRoaXMuaGFuZGxlTG9naW5FcnJvcihvcHRpb25zLCBwYXJ0cyk7XG4gICAgICBjb25zdCBlcnIgPSBuZXcgT0F1dGhFcnJvckV2ZW50KCd0b2tlbl9lcnJvcicsIHt9LCBwYXJ0cyk7XG4gICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChlcnIpO1xuICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XG4gICAgfVxuXG4gICAgY29uc3QgYWNjZXNzVG9rZW4gPSBwYXJ0c1snYWNjZXNzX3Rva2VuJ107XG4gICAgY29uc3QgaWRUb2tlbiA9IHBhcnRzWydpZF90b2tlbiddO1xuICAgIGNvbnN0IHNlc3Npb25TdGF0ZSA9IHBhcnRzWydzZXNzaW9uX3N0YXRlJ107XG4gICAgY29uc3QgZ3JhbnRlZFNjb3BlcyA9IHBhcnRzWydzY29wZSddO1xuXG4gICAgaWYgKCF0aGlzLnJlcXVlc3RBY2Nlc3NUb2tlbiAmJiAhdGhpcy5vaWRjKSB7XG4gICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoXG4gICAgICAgICdFaXRoZXIgcmVxdWVzdEFjY2Vzc1Rva2VuIG9yIG9pZGMgKG9yIGJvdGgpIG11c3QgYmUgdHJ1ZS4nXG4gICAgICApO1xuICAgIH1cblxuICAgIGlmICh0aGlzLnJlcXVlc3RBY2Nlc3NUb2tlbiAmJiAhYWNjZXNzVG9rZW4pIHtcbiAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoZmFsc2UpO1xuICAgIH1cbiAgICBpZiAodGhpcy5yZXF1ZXN0QWNjZXNzVG9rZW4gJiYgIW9wdGlvbnMuZGlzYWJsZU9BdXRoMlN0YXRlQ2hlY2sgJiYgIXN0YXRlKSB7XG4gICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKGZhbHNlKTtcbiAgICB9XG4gICAgaWYgKHRoaXMub2lkYyAmJiAhaWRUb2tlbikge1xuICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZShmYWxzZSk7XG4gICAgfVxuXG4gICAgaWYgKHRoaXMuc2Vzc2lvbkNoZWNrc0VuYWJsZWQgJiYgIXNlc3Npb25TdGF0ZSkge1xuICAgICAgdGhpcy5sb2dnZXIud2FybihcbiAgICAgICAgJ3Nlc3Npb24gY2hlY2tzIChTZXNzaW9uIFN0YXR1cyBDaGFuZ2UgTm90aWZpY2F0aW9uKSAnICtcbiAgICAgICAgICAnd2VyZSBhY3RpdmF0ZWQgaW4gdGhlIGNvbmZpZ3VyYXRpb24gYnV0IHRoZSBpZF90b2tlbiAnICtcbiAgICAgICAgICAnZG9lcyBub3QgY29udGFpbiBhIHNlc3Npb25fc3RhdGUgY2xhaW0nXG4gICAgICApO1xuICAgIH1cblxuICAgIGlmICh0aGlzLnJlcXVlc3RBY2Nlc3NUb2tlbiAmJiAhb3B0aW9ucy5kaXNhYmxlT0F1dGgyU3RhdGVDaGVjaykge1xuICAgICAgY29uc3Qgc3VjY2VzcyA9IHRoaXMudmFsaWRhdGVOb25jZShub25jZUluU3RhdGUpO1xuXG4gICAgICBpZiAoIXN1Y2Nlc3MpIHtcbiAgICAgICAgY29uc3QgZXZlbnQgPSBuZXcgT0F1dGhFcnJvckV2ZW50KCdpbnZhbGlkX25vbmNlX2luX3N0YXRlJywgbnVsbCk7XG4gICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KGV2ZW50KTtcbiAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGV2ZW50KTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICBpZiAodGhpcy5yZXF1ZXN0QWNjZXNzVG9rZW4pIHtcbiAgICAgIHRoaXMuc3RvcmVBY2Nlc3NUb2tlblJlc3BvbnNlKFxuICAgICAgICBhY2Nlc3NUb2tlbixcbiAgICAgICAgbnVsbCxcbiAgICAgICAgcGFydHNbJ2V4cGlyZXNfaW4nXSB8fCB0aGlzLmZhbGxiYWNrQWNjZXNzVG9rZW5FeHBpcmF0aW9uVGltZUluU2VjLFxuICAgICAgICBncmFudGVkU2NvcGVzXG4gICAgICApO1xuICAgIH1cblxuICAgIGlmICghdGhpcy5vaWRjKSB7XG4gICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhTdWNjZXNzRXZlbnQoJ3Rva2VuX3JlY2VpdmVkJykpO1xuICAgICAgaWYgKHRoaXMuY2xlYXJIYXNoQWZ0ZXJMb2dpbiAmJiAhb3B0aW9ucy5wcmV2ZW50Q2xlYXJIYXNoQWZ0ZXJMb2dpbikge1xuICAgICAgICBsb2NhdGlvbi5oYXNoID0gJyc7XG4gICAgICB9XG5cbiAgICAgIHRoaXMuY2FsbE9uVG9rZW5SZWNlaXZlZElmRXhpc3RzKG9wdGlvbnMpO1xuICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSh0cnVlKTtcbiAgICB9XG5cbiAgICByZXR1cm4gdGhpcy5wcm9jZXNzSWRUb2tlbihpZFRva2VuLCBhY2Nlc3NUb2tlbilcbiAgICAgIC50aGVuKHJlc3VsdCA9PiB7XG4gICAgICAgIGlmIChvcHRpb25zLnZhbGlkYXRpb25IYW5kbGVyKSB7XG4gICAgICAgICAgcmV0dXJuIG9wdGlvbnNcbiAgICAgICAgICAgIC52YWxpZGF0aW9uSGFuZGxlcih7XG4gICAgICAgICAgICAgIGFjY2Vzc1Rva2VuOiBhY2Nlc3NUb2tlbixcbiAgICAgICAgICAgICAgaWRDbGFpbXM6IHJlc3VsdC5pZFRva2VuQ2xhaW1zLFxuICAgICAgICAgICAgICBpZFRva2VuOiByZXN1bHQuaWRUb2tlbixcbiAgICAgICAgICAgICAgc3RhdGU6IHN0YXRlXG4gICAgICAgICAgICB9KVxuICAgICAgICAgICAgLnRoZW4oXyA9PiByZXN1bHQpO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiByZXN1bHQ7XG4gICAgICB9KVxuICAgICAgLnRoZW4ocmVzdWx0ID0+IHtcbiAgICAgICAgdGhpcy5zdG9yZUlkVG9rZW4ocmVzdWx0KTtcbiAgICAgICAgdGhpcy5zdG9yZVNlc3Npb25TdGF0ZShzZXNzaW9uU3RhdGUpO1xuICAgICAgICBpZiAodGhpcy5jbGVhckhhc2hBZnRlckxvZ2luICYmICFvcHRpb25zLnByZXZlbnRDbGVhckhhc2hBZnRlckxvZ2luKSB7XG4gICAgICAgICAgbG9jYXRpb24uaGFzaCA9ICcnO1xuICAgICAgICB9XG4gICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aFN1Y2Nlc3NFdmVudCgndG9rZW5fcmVjZWl2ZWQnKSk7XG4gICAgICAgIHRoaXMuY2FsbE9uVG9rZW5SZWNlaXZlZElmRXhpc3RzKG9wdGlvbnMpO1xuICAgICAgICB0aGlzLmluSW1wbGljaXRGbG93ID0gZmFsc2U7XG4gICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgfSlcbiAgICAgIC5jYXRjaChyZWFzb24gPT4ge1xuICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChcbiAgICAgICAgICBuZXcgT0F1dGhFcnJvckV2ZW50KCd0b2tlbl92YWxpZGF0aW9uX2Vycm9yJywgcmVhc29uKVxuICAgICAgICApO1xuICAgICAgICB0aGlzLmxvZ2dlci5lcnJvcignRXJyb3IgdmFsaWRhdGluZyB0b2tlbnMnKTtcbiAgICAgICAgdGhpcy5sb2dnZXIuZXJyb3IocmVhc29uKTtcbiAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KHJlYXNvbik7XG4gICAgICB9KTtcbiAgfVxuXG4gIHByaXZhdGUgcGFyc2VTdGF0ZShzdGF0ZTogc3RyaW5nKTogW3N0cmluZywgc3RyaW5nXSB7XG4gICAgbGV0IG5vbmNlID0gc3RhdGU7XG4gICAgbGV0IHVzZXJTdGF0ZSA9ICcnO1xuXG4gICAgaWYgKHN0YXRlKSB7XG4gICAgICBjb25zdCBpZHggPSBzdGF0ZS5pbmRleE9mKHRoaXMuY29uZmlnLm5vbmNlU3RhdGVTZXBhcmF0b3IpO1xuICAgICAgaWYgKGlkeCA+IC0xKSB7XG4gICAgICAgIG5vbmNlID0gc3RhdGUuc3Vic3RyKDAsIGlkeCk7XG4gICAgICAgIHVzZXJTdGF0ZSA9IHN0YXRlLnN1YnN0cihpZHggKyB0aGlzLmNvbmZpZy5ub25jZVN0YXRlU2VwYXJhdG9yLmxlbmd0aCk7XG4gICAgICB9XG4gICAgfVxuICAgIHJldHVybiBbbm9uY2UsIHVzZXJTdGF0ZV07XG4gIH1cblxuICBwcm90ZWN0ZWQgdmFsaWRhdGVOb25jZShub25jZUluU3RhdGU6IHN0cmluZyk6IGJvb2xlYW4ge1xuICAgIGxldCBzYXZlZE5vbmNlO1xuXG4gICAgaWYgKFxuICAgICAgdGhpcy5zYXZlTm9uY2VzSW5Mb2NhbFN0b3JhZ2UgJiZcbiAgICAgIHR5cGVvZiB3aW5kb3dbJ2xvY2FsU3RvcmFnZSddICE9PSAndW5kZWZpbmVkJ1xuICAgICkge1xuICAgICAgc2F2ZWROb25jZSA9IGxvY2FsU3RvcmFnZS5nZXRJdGVtKCdub25jZScpO1xuICAgIH0gZWxzZSB7XG4gICAgICBzYXZlZE5vbmNlID0gdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdub25jZScpO1xuICAgIH1cblxuICAgIGlmIChzYXZlZE5vbmNlICE9PSBub25jZUluU3RhdGUpIHtcbiAgICAgIGNvbnN0IGVyciA9ICdWYWxpZGF0aW5nIGFjY2Vzc190b2tlbiBmYWlsZWQsIHdyb25nIHN0YXRlL25vbmNlLic7XG4gICAgICBjb25zb2xlLmVycm9yKGVyciwgc2F2ZWROb25jZSwgbm9uY2VJblN0YXRlKTtcbiAgICAgIHJldHVybiBmYWxzZTtcbiAgICB9XG4gICAgcmV0dXJuIHRydWU7XG4gIH1cblxuICBwcm90ZWN0ZWQgc3RvcmVJZFRva2VuKGlkVG9rZW46IFBhcnNlZElkVG9rZW4pOiB2b2lkIHtcbiAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oJ2lkX3Rva2VuJywgaWRUb2tlbi5pZFRva2VuKTtcbiAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oJ2lkX3Rva2VuX2NsYWltc19vYmonLCBpZFRva2VuLmlkVG9rZW5DbGFpbXNKc29uKTtcbiAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oJ2lkX3Rva2VuX2V4cGlyZXNfYXQnLCAnJyArIGlkVG9rZW4uaWRUb2tlbkV4cGlyZXNBdCk7XG4gICAgdGhpcy5fc3RvcmFnZS5zZXRJdGVtKCdpZF90b2tlbl9zdG9yZWRfYXQnLCAnJyArIERhdGUubm93KCkpO1xuICB9XG5cbiAgcHJvdGVjdGVkIHN0b3JlU2Vzc2lvblN0YXRlKHNlc3Npb25TdGF0ZTogc3RyaW5nKTogdm9pZCB7XG4gICAgdGhpcy5fc3RvcmFnZS5zZXRJdGVtKCdzZXNzaW9uX3N0YXRlJywgc2Vzc2lvblN0YXRlKTtcbiAgfVxuXG4gIHByb3RlY3RlZCBnZXRTZXNzaW9uU3RhdGUoKTogc3RyaW5nIHtcbiAgICByZXR1cm4gdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdzZXNzaW9uX3N0YXRlJyk7XG4gIH1cblxuICBwcm90ZWN0ZWQgaGFuZGxlTG9naW5FcnJvcihvcHRpb25zOiBMb2dpbk9wdGlvbnMsIHBhcnRzOiBvYmplY3QpOiB2b2lkIHtcbiAgICBpZiAob3B0aW9ucy5vbkxvZ2luRXJyb3IpIHtcbiAgICAgIG9wdGlvbnMub25Mb2dpbkVycm9yKHBhcnRzKTtcbiAgICB9XG4gICAgaWYgKHRoaXMuY2xlYXJIYXNoQWZ0ZXJMb2dpbiAmJiAhb3B0aW9ucy5wcmV2ZW50Q2xlYXJIYXNoQWZ0ZXJMb2dpbikge1xuICAgICAgbG9jYXRpb24uaGFzaCA9ICcnO1xuICAgIH1cbiAgfVxuXG4gIC8qKlxuICAgKiBAaWdub3JlXG4gICAqL1xuICBwdWJsaWMgcHJvY2Vzc0lkVG9rZW4oXG4gICAgaWRUb2tlbjogc3RyaW5nLFxuICAgIGFjY2Vzc1Rva2VuOiBzdHJpbmcsXG4gICAgc2tpcE5vbmNlQ2hlY2sgPSBmYWxzZVxuICApOiBQcm9taXNlPFBhcnNlZElkVG9rZW4+IHtcbiAgICBjb25zdCB0b2tlblBhcnRzID0gaWRUb2tlbi5zcGxpdCgnLicpO1xuICAgIGNvbnN0IGhlYWRlckJhc2U2NCA9IHRoaXMucGFkQmFzZTY0KHRva2VuUGFydHNbMF0pO1xuICAgIGNvbnN0IGhlYWRlckpzb24gPSBiNjREZWNvZGVVbmljb2RlKGhlYWRlckJhc2U2NCk7XG4gICAgY29uc3QgaGVhZGVyID0gSlNPTi5wYXJzZShoZWFkZXJKc29uKTtcbiAgICBjb25zdCBjbGFpbXNCYXNlNjQgPSB0aGlzLnBhZEJhc2U2NCh0b2tlblBhcnRzWzFdKTtcbiAgICBjb25zdCBjbGFpbXNKc29uID0gYjY0RGVjb2RlVW5pY29kZShjbGFpbXNCYXNlNjQpO1xuICAgIGNvbnN0IGNsYWltcyA9IEpTT04ucGFyc2UoY2xhaW1zSnNvbik7XG5cbiAgICBsZXQgc2F2ZWROb25jZTtcbiAgICBpZiAoXG4gICAgICB0aGlzLnNhdmVOb25jZXNJbkxvY2FsU3RvcmFnZSAmJlxuICAgICAgdHlwZW9mIHdpbmRvd1snbG9jYWxTdG9yYWdlJ10gIT09ICd1bmRlZmluZWQnXG4gICAgKSB7XG4gICAgICBzYXZlZE5vbmNlID0gbG9jYWxTdG9yYWdlLmdldEl0ZW0oJ25vbmNlJyk7XG4gICAgfSBlbHNlIHtcbiAgICAgIHNhdmVkTm9uY2UgPSB0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ25vbmNlJyk7XG4gICAgfVxuXG4gICAgaWYgKEFycmF5LmlzQXJyYXkoY2xhaW1zLmF1ZCkpIHtcbiAgICAgIGlmIChjbGFpbXMuYXVkLmV2ZXJ5KHYgPT4gdiAhPT0gdGhpcy5jbGllbnRJZCkpIHtcbiAgICAgICAgY29uc3QgZXJyID0gJ1dyb25nIGF1ZGllbmNlOiAnICsgY2xhaW1zLmF1ZC5qb2luKCcsJyk7XG4gICAgICAgIHRoaXMubG9nZ2VyLndhcm4oZXJyKTtcbiAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XG4gICAgICB9XG4gICAgfSBlbHNlIHtcbiAgICAgIGlmIChjbGFpbXMuYXVkICE9PSB0aGlzLmNsaWVudElkKSB7XG4gICAgICAgIGNvbnN0IGVyciA9ICdXcm9uZyBhdWRpZW5jZTogJyArIGNsYWltcy5hdWQ7XG4gICAgICAgIHRoaXMubG9nZ2VyLndhcm4oZXJyKTtcbiAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XG4gICAgICB9XG4gICAgfVxuXG4gICAgaWYgKCFjbGFpbXMuc3ViKSB7XG4gICAgICBjb25zdCBlcnIgPSAnTm8gc3ViIGNsYWltIGluIGlkX3Rva2VuJztcbiAgICAgIHRoaXMubG9nZ2VyLndhcm4oZXJyKTtcbiAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpO1xuICAgIH1cblxuICAgIC8qIEZvciBub3csIHdlIG9ubHkgY2hlY2sgd2hldGhlciB0aGUgc3ViIGFnYWluc3RcbiAgICAgKiBzaWxlbnRSZWZyZXNoU3ViamVjdCB3aGVuIHNlc3Npb25DaGVja3NFbmFibGVkIGlzIG9uXG4gICAgICogV2Ugd2lsbCByZWNvbnNpZGVyIGluIGEgbGF0ZXIgdmVyc2lvbiB0byBkbyB0aGlzXG4gICAgICogaW4gZXZlcnkgb3RoZXIgY2FzZSB0b28uXG4gICAgICovXG4gICAgaWYgKFxuICAgICAgdGhpcy5zZXNzaW9uQ2hlY2tzRW5hYmxlZCAmJlxuICAgICAgdGhpcy5zaWxlbnRSZWZyZXNoU3ViamVjdCAmJlxuICAgICAgdGhpcy5zaWxlbnRSZWZyZXNoU3ViamVjdCAhPT0gY2xhaW1zWydzdWInXVxuICAgICkge1xuICAgICAgY29uc3QgZXJyID1cbiAgICAgICAgJ0FmdGVyIHJlZnJlc2hpbmcsIHdlIGdvdCBhbiBpZF90b2tlbiBmb3IgYW5vdGhlciB1c2VyIChzdWIpLiAnICtcbiAgICAgICAgYEV4cGVjdGVkIHN1YjogJHt0aGlzLnNpbGVudFJlZnJlc2hTdWJqZWN0fSwgcmVjZWl2ZWQgc3ViOiAke2NsYWltc1snc3ViJ119YDtcblxuICAgICAgdGhpcy5sb2dnZXIud2FybihlcnIpO1xuICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XG4gICAgfVxuXG4gICAgaWYgKCFjbGFpbXMuaWF0KSB7XG4gICAgICBjb25zdCBlcnIgPSAnTm8gaWF0IGNsYWltIGluIGlkX3Rva2VuJztcbiAgICAgIHRoaXMubG9nZ2VyLndhcm4oZXJyKTtcbiAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpO1xuICAgIH1cblxuICAgIGlmICghdGhpcy5za2lwSXNzdWVyQ2hlY2sgJiYgY2xhaW1zLmlzcyAhPT0gdGhpcy5pc3N1ZXIpIHtcbiAgICAgIGNvbnN0IGVyciA9ICdXcm9uZyBpc3N1ZXI6ICcgKyBjbGFpbXMuaXNzO1xuICAgICAgdGhpcy5sb2dnZXIud2FybihlcnIpO1xuICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XG4gICAgfVxuXG4gICAgaWYgKCFza2lwTm9uY2VDaGVjayAmJiBjbGFpbXMubm9uY2UgIT09IHNhdmVkTm9uY2UpIHtcbiAgICAgIGNvbnN0IGVyciA9ICdXcm9uZyBub25jZTogJyArIGNsYWltcy5ub25jZTtcbiAgICAgIHRoaXMubG9nZ2VyLndhcm4oZXJyKTtcbiAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpO1xuICAgIH1cbiAgICAvLyBhdF9oYXNoIGlzIG5vdCBhcHBsaWNhYmxlIHRvIGF1dGhvcml6YXRpb24gY29kZSBmbG93XG4gICAgLy8gYWRkcmVzc2luZyBodHRwczovL2dpdGh1Yi5jb20vbWFuZnJlZHN0ZXllci9hbmd1bGFyLW9hdXRoMi1vaWRjL2lzc3Vlcy82NjFcbiAgICAvLyBpLmUuIEJhc2VkIG9uIHNwZWMgdGhlIGF0X2hhc2ggY2hlY2sgaXMgb25seSB0cnVlIGZvciBpbXBsaWNpdCBjb2RlIGZsb3cgb24gUGluZyBGZWRlcmF0ZVxuICAgIC8vIGh0dHBzOi8vd3d3LnBpbmdpZGVudGl0eS5jb20vZGV2ZWxvcGVyL2VuL3Jlc291cmNlcy9vcGVuaWQtY29ubmVjdC1kZXZlbG9wZXJzLWd1aWRlLmh0bWxcbiAgICBpZiAoXG4gICAgICB0aGlzLmhhc093blByb3BlcnR5KCdyZXNwb25zZVR5cGUnKSAmJlxuICAgICAgKHRoaXMucmVzcG9uc2VUeXBlID09PSAnY29kZScgfHwgdGhpcy5yZXNwb25zZVR5cGUgPT09ICdpZF90b2tlbicpXG4gICAgKSB7XG4gICAgICB0aGlzLmRpc2FibGVBdEhhc2hDaGVjayA9IHRydWU7XG4gICAgfVxuICAgIGlmIChcbiAgICAgICF0aGlzLmRpc2FibGVBdEhhc2hDaGVjayAmJlxuICAgICAgdGhpcy5yZXF1ZXN0QWNjZXNzVG9rZW4gJiZcbiAgICAgICFjbGFpbXNbJ2F0X2hhc2gnXVxuICAgICkge1xuICAgICAgY29uc3QgZXJyID0gJ0FuIGF0X2hhc2ggaXMgbmVlZGVkISc7XG4gICAgICB0aGlzLmxvZ2dlci53YXJuKGVycik7XG4gICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyKTtcbiAgICB9XG5cbiAgICBjb25zdCBub3cgPSBEYXRlLm5vdygpO1xuICAgIGNvbnN0IGlzc3VlZEF0TVNlYyA9IGNsYWltcy5pYXQgKiAxMDAwO1xuICAgIGNvbnN0IGV4cGlyZXNBdE1TZWMgPSBjbGFpbXMuZXhwICogMTAwMDtcbiAgICBjb25zdCBjbG9ja1NrZXdJbk1TZWMgPSAodGhpcy5jbG9ja1NrZXdJblNlYyB8fCA2MDApICogMTAwMDtcblxuICAgIGlmIChcbiAgICAgIGlzc3VlZEF0TVNlYyAtIGNsb2NrU2tld0luTVNlYyA+PSBub3cgfHxcbiAgICAgIGV4cGlyZXNBdE1TZWMgKyBjbG9ja1NrZXdJbk1TZWMgPD0gbm93XG4gICAgKSB7XG4gICAgICBjb25zdCBlcnIgPSAnVG9rZW4gaGFzIGV4cGlyZWQnO1xuICAgICAgY29uc29sZS5lcnJvcihlcnIpO1xuICAgICAgY29uc29sZS5lcnJvcih7XG4gICAgICAgIG5vdzogbm93LFxuICAgICAgICBpc3N1ZWRBdE1TZWM6IGlzc3VlZEF0TVNlYyxcbiAgICAgICAgZXhwaXJlc0F0TVNlYzogZXhwaXJlc0F0TVNlY1xuICAgICAgfSk7XG4gICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyKTtcbiAgICB9XG5cbiAgICBjb25zdCB2YWxpZGF0aW9uUGFyYW1zOiBWYWxpZGF0aW9uUGFyYW1zID0ge1xuICAgICAgYWNjZXNzVG9rZW46IGFjY2Vzc1Rva2VuLFxuICAgICAgaWRUb2tlbjogaWRUb2tlbixcbiAgICAgIGp3a3M6IHRoaXMuandrcyxcbiAgICAgIGlkVG9rZW5DbGFpbXM6IGNsYWltcyxcbiAgICAgIGlkVG9rZW5IZWFkZXI6IGhlYWRlcixcbiAgICAgIGxvYWRLZXlzOiAoKSA9PiB0aGlzLmxvYWRKd2tzKClcbiAgICB9O1xuXG4gICAgaWYgKHRoaXMuZGlzYWJsZUF0SGFzaENoZWNrKSB7XG4gICAgICByZXR1cm4gdGhpcy5jaGVja1NpZ25hdHVyZSh2YWxpZGF0aW9uUGFyYW1zKS50aGVuKF8gPT4ge1xuICAgICAgICBjb25zdCByZXN1bHQ6IFBhcnNlZElkVG9rZW4gPSB7XG4gICAgICAgICAgaWRUb2tlbjogaWRUb2tlbixcbiAgICAgICAgICBpZFRva2VuQ2xhaW1zOiBjbGFpbXMsXG4gICAgICAgICAgaWRUb2tlbkNsYWltc0pzb246IGNsYWltc0pzb24sXG4gICAgICAgICAgaWRUb2tlbkhlYWRlcjogaGVhZGVyLFxuICAgICAgICAgIGlkVG9rZW5IZWFkZXJKc29uOiBoZWFkZXJKc29uLFxuICAgICAgICAgIGlkVG9rZW5FeHBpcmVzQXQ6IGV4cGlyZXNBdE1TZWNcbiAgICAgICAgfTtcbiAgICAgICAgcmV0dXJuIHJlc3VsdDtcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIHJldHVybiB0aGlzLmNoZWNrQXRIYXNoKHZhbGlkYXRpb25QYXJhbXMpLnRoZW4oYXRIYXNoVmFsaWQgPT4ge1xuICAgICAgaWYgKCF0aGlzLmRpc2FibGVBdEhhc2hDaGVjayAmJiB0aGlzLnJlcXVlc3RBY2Nlc3NUb2tlbiAmJiAhYXRIYXNoVmFsaWQpIHtcbiAgICAgICAgY29uc3QgZXJyID0gJ1dyb25nIGF0X2hhc2gnO1xuICAgICAgICB0aGlzLmxvZ2dlci53YXJuKGVycik7XG4gICAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpO1xuICAgICAgfVxuXG4gICAgICByZXR1cm4gdGhpcy5jaGVja1NpZ25hdHVyZSh2YWxpZGF0aW9uUGFyYW1zKS50aGVuKF8gPT4ge1xuICAgICAgICBjb25zdCBhdEhhc2hDaGVja0VuYWJsZWQgPSAhdGhpcy5kaXNhYmxlQXRIYXNoQ2hlY2s7XG4gICAgICAgIGNvbnN0IHJlc3VsdDogUGFyc2VkSWRUb2tlbiA9IHtcbiAgICAgICAgICBpZFRva2VuOiBpZFRva2VuLFxuICAgICAgICAgIGlkVG9rZW5DbGFpbXM6IGNsYWltcyxcbiAgICAgICAgICBpZFRva2VuQ2xhaW1zSnNvbjogY2xhaW1zSnNvbixcbiAgICAgICAgICBpZFRva2VuSGVhZGVyOiBoZWFkZXIsXG4gICAgICAgICAgaWRUb2tlbkhlYWRlckpzb246IGhlYWRlckpzb24sXG4gICAgICAgICAgaWRUb2tlbkV4cGlyZXNBdDogZXhwaXJlc0F0TVNlY1xuICAgICAgICB9O1xuICAgICAgICBpZiAoYXRIYXNoQ2hlY2tFbmFibGVkKSB7XG4gICAgICAgICAgcmV0dXJuIHRoaXMuY2hlY2tBdEhhc2godmFsaWRhdGlvblBhcmFtcykudGhlbihhdEhhc2hWYWxpZCA9PiB7XG4gICAgICAgICAgICBpZiAodGhpcy5yZXF1ZXN0QWNjZXNzVG9rZW4gJiYgIWF0SGFzaFZhbGlkKSB7XG4gICAgICAgICAgICAgIGNvbnN0IGVyciA9ICdXcm9uZyBhdF9oYXNoJztcbiAgICAgICAgICAgICAgdGhpcy5sb2dnZXIud2FybihlcnIpO1xuICAgICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyKTtcbiAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgIHJldHVybiByZXN1bHQ7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfSk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgcmV0dXJuIHJlc3VsdDtcbiAgICAgICAgfVxuICAgICAgfSk7XG4gICAgfSk7XG4gIH1cblxuICAvKipcbiAgICogUmV0dXJucyB0aGUgcmVjZWl2ZWQgY2xhaW1zIGFib3V0IHRoZSB1c2VyLlxuICAgKi9cbiAgcHVibGljIGdldElkZW50aXR5Q2xhaW1zKCk6IG9iamVjdCB7XG4gICAgY29uc3QgY2xhaW1zID0gdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdpZF90b2tlbl9jbGFpbXNfb2JqJyk7XG4gICAgaWYgKCFjbGFpbXMpIHtcbiAgICAgIHJldHVybiBudWxsO1xuICAgIH1cbiAgICByZXR1cm4gSlNPTi5wYXJzZShjbGFpbXMpO1xuICB9XG5cbiAgLyoqXG4gICAqIFJldHVybnMgdGhlIGdyYW50ZWQgc2NvcGVzIGZyb20gdGhlIHNlcnZlci5cbiAgICovXG4gIHB1YmxpYyBnZXRHcmFudGVkU2NvcGVzKCk6IG9iamVjdCB7XG4gICAgY29uc3Qgc2NvcGVzID0gdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdncmFudGVkX3Njb3BlcycpO1xuICAgIGlmICghc2NvcGVzKSB7XG4gICAgICByZXR1cm4gbnVsbDtcbiAgICB9XG4gICAgcmV0dXJuIEpTT04ucGFyc2Uoc2NvcGVzKTtcbiAgfVxuXG4gIC8qKlxuICAgKiBSZXR1cm5zIHRoZSBjdXJyZW50IGlkX3Rva2VuLlxuICAgKi9cbiAgcHVibGljIGdldElkVG9rZW4oKTogc3RyaW5nIHtcbiAgICByZXR1cm4gdGhpcy5fc3RvcmFnZSA/IHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnaWRfdG9rZW4nKSA6IG51bGw7XG4gIH1cblxuICBwcm90ZWN0ZWQgcGFkQmFzZTY0KGJhc2U2NGRhdGEpOiBzdHJpbmcge1xuICAgIHdoaWxlIChiYXNlNjRkYXRhLmxlbmd0aCAlIDQgIT09IDApIHtcbiAgICAgIGJhc2U2NGRhdGEgKz0gJz0nO1xuICAgIH1cbiAgICByZXR1cm4gYmFzZTY0ZGF0YTtcbiAgfVxuXG4gIC8qKlxuICAgKiBSZXR1cm5zIHRoZSBjdXJyZW50IGFjY2Vzc190b2tlbi5cbiAgICovXG4gIHB1YmxpYyBnZXRBY2Nlc3NUb2tlbigpOiBzdHJpbmcge1xuICAgIHJldHVybiB0aGlzLl9zdG9yYWdlID8gdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdhY2Nlc3NfdG9rZW4nKSA6IG51bGw7XG4gIH1cblxuICBwdWJsaWMgZ2V0UmVmcmVzaFRva2VuKCk6IHN0cmluZyB7XG4gICAgcmV0dXJuIHRoaXMuX3N0b3JhZ2UgPyB0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ3JlZnJlc2hfdG9rZW4nKSA6IG51bGw7XG4gIH1cblxuICAvKipcbiAgICogUmV0dXJucyB0aGUgZXhwaXJhdGlvbiBkYXRlIG9mIHRoZSBhY2Nlc3NfdG9rZW5cbiAgICogYXMgbWlsbGlzZWNvbmRzIHNpbmNlIDE5NzAuXG4gICAqL1xuICBwdWJsaWMgZ2V0QWNjZXNzVG9rZW5FeHBpcmF0aW9uKCk6IG51bWJlciB7XG4gICAgaWYgKCF0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ2V4cGlyZXNfYXQnKSkge1xuICAgICAgcmV0dXJuIG51bGw7XG4gICAgfVxuICAgIHJldHVybiBwYXJzZUludCh0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ2V4cGlyZXNfYXQnKSwgMTApO1xuICB9XG5cbiAgcHJvdGVjdGVkIGdldEFjY2Vzc1Rva2VuU3RvcmVkQXQoKTogbnVtYmVyIHtcbiAgICByZXR1cm4gcGFyc2VJbnQodGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdhY2Nlc3NfdG9rZW5fc3RvcmVkX2F0JyksIDEwKTtcbiAgfVxuXG4gIHByb3RlY3RlZCBnZXRJZFRva2VuU3RvcmVkQXQoKTogbnVtYmVyIHtcbiAgICByZXR1cm4gcGFyc2VJbnQodGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdpZF90b2tlbl9zdG9yZWRfYXQnKSwgMTApO1xuICB9XG5cbiAgLyoqXG4gICAqIFJldHVybnMgdGhlIGV4cGlyYXRpb24gZGF0ZSBvZiB0aGUgaWRfdG9rZW5cbiAgICogYXMgbWlsbGlzZWNvbmRzIHNpbmNlIDE5NzAuXG4gICAqL1xuICBwdWJsaWMgZ2V0SWRUb2tlbkV4cGlyYXRpb24oKTogbnVtYmVyIHtcbiAgICBpZiAoIXRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnaWRfdG9rZW5fZXhwaXJlc19hdCcpKSB7XG4gICAgICByZXR1cm4gbnVsbDtcbiAgICB9XG5cbiAgICByZXR1cm4gcGFyc2VJbnQodGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdpZF90b2tlbl9leHBpcmVzX2F0JyksIDEwKTtcbiAgfVxuXG4gIC8qKlxuICAgKiBDaGVja2VzLCB3aGV0aGVyIHRoZXJlIGlzIGEgdmFsaWQgYWNjZXNzX3Rva2VuLlxuICAgKi9cbiAgcHVibGljIGhhc1ZhbGlkQWNjZXNzVG9rZW4oKTogYm9vbGVhbiB7XG4gICAgaWYgKHRoaXMuZ2V0QWNjZXNzVG9rZW4oKSkge1xuICAgICAgY29uc3QgZXhwaXJlc0F0ID0gdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdleHBpcmVzX2F0Jyk7XG4gICAgICBjb25zdCBub3cgPSBuZXcgRGF0ZSgpO1xuICAgICAgaWYgKGV4cGlyZXNBdCAmJiBwYXJzZUludChleHBpcmVzQXQsIDEwKSA8IG5vdy5nZXRUaW1lKCkpIHtcbiAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgfVxuXG4gICAgICByZXR1cm4gdHJ1ZTtcbiAgICB9XG5cbiAgICByZXR1cm4gZmFsc2U7XG4gIH1cblxuICAvKipcbiAgICogQ2hlY2tzIHdoZXRoZXIgdGhlcmUgaXMgYSB2YWxpZCBpZF90b2tlbi5cbiAgICovXG4gIHB1YmxpYyBoYXNWYWxpZElkVG9rZW4oKTogYm9vbGVhbiB7XG4gICAgaWYgKHRoaXMuZ2V0SWRUb2tlbigpKSB7XG4gICAgICBjb25zdCBleHBpcmVzQXQgPSB0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ2lkX3Rva2VuX2V4cGlyZXNfYXQnKTtcbiAgICAgIGNvbnN0IG5vdyA9IG5ldyBEYXRlKCk7XG4gICAgICBpZiAoZXhwaXJlc0F0ICYmIHBhcnNlSW50KGV4cGlyZXNBdCwgMTApIDwgbm93LmdldFRpbWUoKSkge1xuICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICB9XG5cbiAgICAgIHJldHVybiB0cnVlO1xuICAgIH1cblxuICAgIHJldHVybiBmYWxzZTtcbiAgfVxuXG4gIC8qKlxuICAgKiBSZXRyaWV2ZSBhIHNhdmVkIGN1c3RvbSBwcm9wZXJ0eSBvZiB0aGUgVG9rZW5SZXBvbnNlIG9iamVjdC4gT25seSBpZiBwcmVkZWZpbmVkIGluIGF1dGhjb25maWcuXG4gICAqL1xuICBwdWJsaWMgZ2V0Q3VzdG9tVG9rZW5SZXNwb25zZVByb3BlcnR5KHJlcXVlc3RlZFByb3BlcnR5OiBzdHJpbmcpOiBhbnkge1xuICAgIHJldHVybiB0aGlzLl9zdG9yYWdlICYmXG4gICAgICB0aGlzLmNvbmZpZy5jdXN0b21Ub2tlblBhcmFtZXRlcnMgJiZcbiAgICAgIHRoaXMuY29uZmlnLmN1c3RvbVRva2VuUGFyYW1ldGVycy5pbmRleE9mKHJlcXVlc3RlZFByb3BlcnR5KSA+PSAwICYmXG4gICAgICB0aGlzLl9zdG9yYWdlLmdldEl0ZW0ocmVxdWVzdGVkUHJvcGVydHkpICE9PSBudWxsXG4gICAgICA/IEpTT04ucGFyc2UodGhpcy5fc3RvcmFnZS5nZXRJdGVtKHJlcXVlc3RlZFByb3BlcnR5KSlcbiAgICAgIDogbnVsbDtcbiAgfVxuXG4gIC8qKlxuICAgKiBSZXR1cm5zIHRoZSBhdXRoLWhlYWRlciB0aGF0IGNhbiBiZSB1c2VkXG4gICAqIHRvIHRyYW5zbWl0IHRoZSBhY2Nlc3NfdG9rZW4gdG8gYSBzZXJ2aWNlXG4gICAqL1xuICBwdWJsaWMgYXV0aG9yaXphdGlvbkhlYWRlcigpOiBzdHJpbmcge1xuICAgIHJldHVybiAnQmVhcmVyICcgKyB0aGlzLmdldEFjY2Vzc1Rva2VuKCk7XG4gIH1cblxuICAvKipcbiAgICogUmVtb3ZlcyBhbGwgdG9rZW5zIGFuZCBsb2dzIHRoZSB1c2VyIG91dC5cbiAgICogSWYgYSBsb2dvdXQgdXJsIGlzIGNvbmZpZ3VyZWQsIHRoZSB1c2VyIGlzXG4gICAqIHJlZGlyZWN0ZWQgdG8gaXQgd2l0aCBvcHRpb25hbCBzdGF0ZSBwYXJhbWV0ZXIuXG4gICAqIEBwYXJhbSBub1JlZGlyZWN0VG9Mb2dvdXRVcmxcbiAgICogQHBhcmFtIHN0YXRlXG4gICAqL1xuICBwdWJsaWMgbG9nT3V0KCk6IHZvaWQ7XG4gIHB1YmxpYyBsb2dPdXQoY3VzdG9tUGFyYW1ldGVyczogb2JqZWN0KTogdm9pZDtcbiAgcHVibGljIGxvZ091dChub1JlZGlyZWN0VG9Mb2dvdXRVcmw6IGJvb2xlYW4pOiB2b2lkO1xuICBwdWJsaWMgbG9nT3V0KG5vUmVkaXJlY3RUb0xvZ291dFVybDogYm9vbGVhbiwgc3RhdGU6IHN0cmluZyk6IHZvaWQ7XG4gIHB1YmxpYyBsb2dPdXQoY3VzdG9tUGFyYW1ldGVyczogYm9vbGVhbiB8IG9iamVjdCA9IHt9LCBzdGF0ZSA9ICcnKTogdm9pZCB7XG4gICAgbGV0IG5vUmVkaXJlY3RUb0xvZ291dFVybCA9IGZhbHNlO1xuICAgIGlmICh0eXBlb2YgY3VzdG9tUGFyYW1ldGVycyA9PT0gJ2Jvb2xlYW4nKSB7XG4gICAgICBub1JlZGlyZWN0VG9Mb2dvdXRVcmwgPSBjdXN0b21QYXJhbWV0ZXJzO1xuICAgICAgY3VzdG9tUGFyYW1ldGVycyA9IHt9O1xuICAgIH1cblxuICAgIGNvbnN0IGlkX3Rva2VuID0gdGhpcy5nZXRJZFRva2VuKCk7XG4gICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKCdhY2Nlc3NfdG9rZW4nKTtcbiAgICB0aGlzLl9zdG9yYWdlLnJlbW92ZUl0ZW0oJ2lkX3Rva2VuJyk7XG4gICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKCdyZWZyZXNoX3Rva2VuJyk7XG5cbiAgICBpZiAodGhpcy5zYXZlTm9uY2VzSW5Mb2NhbFN0b3JhZ2UpIHtcbiAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKCdub25jZScpO1xuICAgICAgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oJ1BLQ0VfdmVyaWZpZXInKTtcbiAgICB9IGVsc2Uge1xuICAgICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKCdub25jZScpO1xuICAgICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKCdQS0NFX3ZlcmlmaWVyJyk7XG4gICAgfVxuXG4gICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKCdleHBpcmVzX2F0Jyk7XG4gICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKCdpZF90b2tlbl9jbGFpbXNfb2JqJyk7XG4gICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKCdpZF90b2tlbl9leHBpcmVzX2F0Jyk7XG4gICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKCdpZF90b2tlbl9zdG9yZWRfYXQnKTtcbiAgICB0aGlzLl9zdG9yYWdlLnJlbW92ZUl0ZW0oJ2FjY2Vzc190b2tlbl9zdG9yZWRfYXQnKTtcbiAgICB0aGlzLl9zdG9yYWdlLnJlbW92ZUl0ZW0oJ2dyYW50ZWRfc2NvcGVzJyk7XG4gICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKCdzZXNzaW9uX3N0YXRlJyk7XG4gICAgaWYgKHRoaXMuY29uZmlnLmN1c3RvbVRva2VuUGFyYW1ldGVycykge1xuICAgICAgdGhpcy5jb25maWcuY3VzdG9tVG9rZW5QYXJhbWV0ZXJzLmZvckVhY2goY3VzdG9tUGFyYW0gPT5cbiAgICAgICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKGN1c3RvbVBhcmFtKVxuICAgICAgKTtcbiAgICB9XG4gICAgdGhpcy5zaWxlbnRSZWZyZXNoU3ViamVjdCA9IG51bGw7XG5cbiAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhJbmZvRXZlbnQoJ2xvZ291dCcpKTtcblxuICAgIGlmICghdGhpcy5sb2dvdXRVcmwpIHtcbiAgICAgIHJldHVybjtcbiAgICB9XG4gICAgaWYgKG5vUmVkaXJlY3RUb0xvZ291dFVybCkge1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIGlmICghaWRfdG9rZW4gJiYgIXRoaXMucG9zdExvZ291dFJlZGlyZWN0VXJpKSB7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgbGV0IGxvZ291dFVybDogc3RyaW5nO1xuXG4gICAgaWYgKCF0aGlzLnZhbGlkYXRlVXJsRm9ySHR0cHModGhpcy5sb2dvdXRVcmwpKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoXG4gICAgICAgIFwibG9nb3V0VXJsICBtdXN0IHVzZSBIVFRQUyAod2l0aCBUTFMpLCBvciBjb25maWcgdmFsdWUgZm9yIHByb3BlcnR5ICdyZXF1aXJlSHR0cHMnIG11c3QgYmUgc2V0IHRvICdmYWxzZScgYW5kIGFsbG93IEhUVFAgKHdpdGhvdXQgVExTKS5cIlxuICAgICAgKTtcbiAgICB9XG5cbiAgICAvLyBGb3IgYmFja3dhcmQgY29tcGF0aWJpbGl0eVxuICAgIGlmICh0aGlzLmxvZ291dFVybC5pbmRleE9mKCd7eycpID4gLTEpIHtcbiAgICAgIGxvZ291dFVybCA9IHRoaXMubG9nb3V0VXJsXG4gICAgICAgIC5yZXBsYWNlKC9cXHtcXHtpZF90b2tlblxcfVxcfS8sIGlkX3Rva2VuKVxuICAgICAgICAucmVwbGFjZSgvXFx7XFx7Y2xpZW50X2lkXFx9XFx9LywgdGhpcy5jbGllbnRJZCk7XG4gICAgfSBlbHNlIHtcbiAgICAgIGxldCBwYXJhbXMgPSBuZXcgSHR0cFBhcmFtcygpO1xuXG4gICAgICBpZiAoaWRfdG9rZW4pIHtcbiAgICAgICAgcGFyYW1zID0gcGFyYW1zLnNldCgnaWRfdG9rZW5faGludCcsIGlkX3Rva2VuKTtcbiAgICAgIH1cblxuICAgICAgY29uc3QgcG9zdExvZ291dFVybCA9IHRoaXMucG9zdExvZ291dFJlZGlyZWN0VXJpIHx8IHRoaXMucmVkaXJlY3RVcmk7XG4gICAgICBpZiAocG9zdExvZ291dFVybCkge1xuICAgICAgICBwYXJhbXMgPSBwYXJhbXMuc2V0KCdwb3N0X2xvZ291dF9yZWRpcmVjdF91cmknLCBwb3N0TG9nb3V0VXJsKTtcblxuICAgICAgICBpZiAoc3RhdGUpIHtcbiAgICAgICAgICBwYXJhbXMgPSBwYXJhbXMuc2V0KCdzdGF0ZScsIHN0YXRlKTtcbiAgICAgICAgfVxuICAgICAgfVxuXG4gICAgICBmb3IgKGxldCBrZXkgaW4gY3VzdG9tUGFyYW1ldGVycykge1xuICAgICAgICBwYXJhbXMgPSBwYXJhbXMuc2V0KGtleSwgY3VzdG9tUGFyYW1ldGVyc1trZXldKTtcbiAgICAgIH1cblxuICAgICAgbG9nb3V0VXJsID1cbiAgICAgICAgdGhpcy5sb2dvdXRVcmwgK1xuICAgICAgICAodGhpcy5sb2dvdXRVcmwuaW5kZXhPZignPycpID4gLTEgPyAnJicgOiAnPycpICtcbiAgICAgICAgcGFyYW1zLnRvU3RyaW5nKCk7XG4gICAgfVxuICAgIHRoaXMuY29uZmlnLm9wZW5VcmkobG9nb3V0VXJsKTtcbiAgfVxuXG4gIC8qKlxuICAgKiBAaWdub3JlXG4gICAqL1xuICBwdWJsaWMgY3JlYXRlQW5kU2F2ZU5vbmNlKCk6IFByb21pc2U8c3RyaW5nPiB7XG4gICAgY29uc3QgdGhhdCA9IHRoaXM7XG4gICAgcmV0dXJuIHRoaXMuY3JlYXRlTm9uY2UoKS50aGVuKGZ1bmN0aW9uKG5vbmNlOiBhbnkpIHtcbiAgICAgIC8vIFVzZSBsb2NhbFN0b3JhZ2UgZm9yIG5vbmNlIGlmIHBvc3NpYmxlXG4gICAgICAvLyBsb2NhbFN0b3JhZ2UgaXMgdGhlIG9ubHkgc3RvcmFnZSB3aG8gc3Vydml2ZXMgYVxuICAgICAgLy8gcmVkaXJlY3QgaW4gQUxMIGJyb3dzZXJzIChhbHNvIElFKVxuICAgICAgLy8gT3RoZXJ3aWVzZSB3ZSdkIGZvcmNlIHRlYW1zIHdobyBoYXZlIHRvIHN1cHBvcnRcbiAgICAgIC8vIElFIGludG8gdXNpbmcgbG9jYWxTdG9yYWdlIGZvciBldmVyeXRoaW5nXG4gICAgICBpZiAoXG4gICAgICAgIHRoYXQuc2F2ZU5vbmNlc0luTG9jYWxTdG9yYWdlICYmXG4gICAgICAgIHR5cGVvZiB3aW5kb3dbJ2xvY2FsU3RvcmFnZSddICE9PSAndW5kZWZpbmVkJ1xuICAgICAgKSB7XG4gICAgICAgIGxvY2FsU3RvcmFnZS5zZXRJdGVtKCdub25jZScsIG5vbmNlKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHRoYXQuX3N0b3JhZ2Uuc2V0SXRlbSgnbm9uY2UnLCBub25jZSk7XG4gICAgICB9XG4gICAgICByZXR1cm4gbm9uY2U7XG4gICAgfSk7XG4gIH1cblxuICAvKipcbiAgICogQGlnbm9yZVxuICAgKi9cbiAgcHVibGljIG5nT25EZXN0cm95KCk6IHZvaWQge1xuICAgIHRoaXMuY2xlYXJBY2Nlc3NUb2tlblRpbWVyKCk7XG4gICAgdGhpcy5jbGVhcklkVG9rZW5UaW1lcigpO1xuXG4gICAgdGhpcy5yZW1vdmVTaWxlbnRSZWZyZXNoRXZlbnRMaXN0ZW5lcigpO1xuICAgIGNvbnN0IHNpbGVudFJlZnJlc2hGcmFtZSA9IHRoaXMuZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoXG4gICAgICB0aGlzLnNpbGVudFJlZnJlc2hJRnJhbWVOYW1lXG4gICAgKTtcbiAgICBpZiAoc2lsZW50UmVmcmVzaEZyYW1lKSB7XG4gICAgICBzaWxlbnRSZWZyZXNoRnJhbWUucmVtb3ZlKCk7XG4gICAgfVxuXG4gICAgdGhpcy5zdG9wU2Vzc2lvbkNoZWNrVGltZXIoKTtcbiAgICB0aGlzLnJlbW92ZVNlc3Npb25DaGVja0V2ZW50TGlzdGVuZXIoKTtcbiAgICBjb25zdCBzZXNzaW9uQ2hlY2tGcmFtZSA9IHRoaXMuZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoXG4gICAgICB0aGlzLnNlc3Npb25DaGVja0lGcmFtZU5hbWVcbiAgICApO1xuICAgIGlmIChzZXNzaW9uQ2hlY2tGcmFtZSkge1xuICAgICAgc2Vzc2lvbkNoZWNrRnJhbWUucmVtb3ZlKCk7XG4gICAgfVxuICB9XG5cbiAgcHJvdGVjdGVkIGNyZWF0ZU5vbmNlKCk6IFByb21pc2U8c3RyaW5nPiB7XG4gICAgcmV0dXJuIG5ldyBQcm9taXNlKHJlc29sdmUgPT4ge1xuICAgICAgaWYgKHRoaXMucm5nVXJsKSB7XG4gICAgICAgIHRocm93IG5ldyBFcnJvcihcbiAgICAgICAgICAnY3JlYXRlTm9uY2Ugd2l0aCBybmctd2ViLWFwaSBoYXMgbm90IGJlZW4gaW1wbGVtZW50ZWQgc28gZmFyJ1xuICAgICAgICApO1xuICAgICAgfVxuXG4gICAgICAvKlxuICAgICAgICogVGhpcyBhbHBoYWJldCBpcyBmcm9tOlxuICAgICAgICogaHR0cHM6Ly90b29scy5pZXRmLm9yZy9odG1sL3JmYzc2MzYjc2VjdGlvbi00LjFcbiAgICAgICAqXG4gICAgICAgKiBbQS1aXSAvIFthLXpdIC8gWzAtOV0gLyBcIi1cIiAvIFwiLlwiIC8gXCJfXCIgLyBcIn5cIlxuICAgICAgICovXG4gICAgICBjb25zdCB1bnJlc2VydmVkID1cbiAgICAgICAgJ0FCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5LS5ffic7XG4gICAgICBsZXQgc2l6ZSA9IDQ1O1xuICAgICAgbGV0IGlkID0gJyc7XG5cbiAgICAgIGNvbnN0IGNyeXB0byA9XG4gICAgICAgIHR5cGVvZiBzZWxmID09PSAndW5kZWZpbmVkJyA/IG51bGwgOiBzZWxmLmNyeXB0byB8fCBzZWxmWydtc0NyeXB0byddO1xuICAgICAgaWYgKGNyeXB0bykge1xuICAgICAgICBsZXQgYnl0ZXMgPSBuZXcgVWludDhBcnJheShzaXplKTtcbiAgICAgICAgY3J5cHRvLmdldFJhbmRvbVZhbHVlcyhieXRlcyk7XG5cbiAgICAgICAgLy8gTmVlZGVkIGZvciBJRVxuICAgICAgICBpZiAoIWJ5dGVzLm1hcCkge1xuICAgICAgICAgIChieXRlcyBhcyBhbnkpLm1hcCA9IEFycmF5LnByb3RvdHlwZS5tYXA7XG4gICAgICAgIH1cblxuICAgICAgICBieXRlcyA9IGJ5dGVzLm1hcCh4ID0+IHVucmVzZXJ2ZWQuY2hhckNvZGVBdCh4ICUgdW5yZXNlcnZlZC5sZW5ndGgpKTtcbiAgICAgICAgaWQgPSBTdHJpbmcuZnJvbUNoYXJDb2RlLmFwcGx5KG51bGwsIGJ5dGVzKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHdoaWxlICgwIDwgc2l6ZS0tKSB7XG4gICAgICAgICAgaWQgKz0gdW5yZXNlcnZlZFsoTWF0aC5yYW5kb20oKSAqIHVucmVzZXJ2ZWQubGVuZ3RoKSB8IDBdO1xuICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIHJlc29sdmUoYmFzZTY0VXJsRW5jb2RlKGlkKSk7XG4gICAgfSk7XG4gIH1cblxuICBwcm90ZWN0ZWQgYXN5bmMgY2hlY2tBdEhhc2gocGFyYW1zOiBWYWxpZGF0aW9uUGFyYW1zKTogUHJvbWlzZTxib29sZWFuPiB7XG4gICAgaWYgKCF0aGlzLnRva2VuVmFsaWRhdGlvbkhhbmRsZXIpIHtcbiAgICAgIHRoaXMubG9nZ2VyLndhcm4oXG4gICAgICAgICdObyB0b2tlblZhbGlkYXRpb25IYW5kbGVyIGNvbmZpZ3VyZWQuIENhbm5vdCBjaGVjayBhdF9oYXNoLidcbiAgICAgICk7XG4gICAgICByZXR1cm4gdHJ1ZTtcbiAgICB9XG4gICAgcmV0dXJuIHRoaXMudG9rZW5WYWxpZGF0aW9uSGFuZGxlci52YWxpZGF0ZUF0SGFzaChwYXJhbXMpO1xuICB9XG5cbiAgcHJvdGVjdGVkIGNoZWNrU2lnbmF0dXJlKHBhcmFtczogVmFsaWRhdGlvblBhcmFtcyk6IFByb21pc2U8YW55PiB7XG4gICAgaWYgKCF0aGlzLnRva2VuVmFsaWRhdGlvbkhhbmRsZXIpIHtcbiAgICAgIHRoaXMubG9nZ2VyLndhcm4oXG4gICAgICAgICdObyB0b2tlblZhbGlkYXRpb25IYW5kbGVyIGNvbmZpZ3VyZWQuIENhbm5vdCBjaGVjayBzaWduYXR1cmUuJ1xuICAgICAgKTtcbiAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUobnVsbCk7XG4gICAgfVxuICAgIHJldHVybiB0aGlzLnRva2VuVmFsaWRhdGlvbkhhbmRsZXIudmFsaWRhdGVTaWduYXR1cmUocGFyYW1zKTtcbiAgfVxuXG4gIC8qKlxuICAgKiBTdGFydCB0aGUgaW1wbGljaXQgZmxvdyBvciB0aGUgY29kZSBmbG93LFxuICAgKiBkZXBlbmRpbmcgb24geW91ciBjb25maWd1cmF0aW9uLlxuICAgKi9cbiAgcHVibGljIGluaXRMb2dpbkZsb3coYWRkaXRpb25hbFN0YXRlID0gJycsIHBhcmFtcyA9IHt9KTogdm9pZCB7XG4gICAgaWYgKHRoaXMucmVzcG9uc2VUeXBlID09PSAnY29kZScpIHtcbiAgICAgIHJldHVybiB0aGlzLmluaXRDb2RlRmxvdyhhZGRpdGlvbmFsU3RhdGUsIHBhcmFtcyk7XG4gICAgfSBlbHNlIHtcbiAgICAgIHJldHVybiB0aGlzLmluaXRJbXBsaWNpdEZsb3coYWRkaXRpb25hbFN0YXRlLCBwYXJhbXMpO1xuICAgIH1cbiAgfVxuXG4gIC8qKlxuICAgKiBTdGFydHMgdGhlIGF1dGhvcml6YXRpb24gY29kZSBmbG93IGFuZCByZWRpcmVjdHMgdG8gdXNlciB0b1xuICAgKiB0aGUgYXV0aCBzZXJ2ZXJzIGxvZ2luIHVybC5cbiAgICovXG4gIHB1YmxpYyBpbml0Q29kZUZsb3coYWRkaXRpb25hbFN0YXRlID0gJycsIHBhcmFtcyA9IHt9KTogdm9pZCB7XG4gICAgaWYgKHRoaXMubG9naW5VcmwgIT09ICcnKSB7XG4gICAgICB0aGlzLmluaXRDb2RlRmxvd0ludGVybmFsKGFkZGl0aW9uYWxTdGF0ZSwgcGFyYW1zKTtcbiAgICB9IGVsc2Uge1xuICAgICAgdGhpcy5ldmVudHNcbiAgICAgICAgLnBpcGUoZmlsdGVyKGUgPT4gZS50eXBlID09PSAnZGlzY292ZXJ5X2RvY3VtZW50X2xvYWRlZCcpKVxuICAgICAgICAuc3Vic2NyaWJlKF8gPT4gdGhpcy5pbml0Q29kZUZsb3dJbnRlcm5hbChhZGRpdGlvbmFsU3RhdGUsIHBhcmFtcykpO1xuICAgIH1cbiAgfVxuXG4gIHByaXZhdGUgaW5pdENvZGVGbG93SW50ZXJuYWwoYWRkaXRpb25hbFN0YXRlID0gJycsIHBhcmFtcyA9IHt9KTogdm9pZCB7XG4gICAgaWYgKCF0aGlzLnZhbGlkYXRlVXJsRm9ySHR0cHModGhpcy5sb2dpblVybCkpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcihcbiAgICAgICAgXCJsb2dpblVybCAgbXVzdCB1c2UgSFRUUFMgKHdpdGggVExTKSwgb3IgY29uZmlnIHZhbHVlIGZvciBwcm9wZXJ0eSAncmVxdWlyZUh0dHBzJyBtdXN0IGJlIHNldCB0byAnZmFsc2UnIGFuZCBhbGxvdyBIVFRQICh3aXRob3V0IFRMUykuXCJcbiAgICAgICk7XG4gICAgfVxuXG4gICAgbGV0IGFkZFBhcmFtcyA9IHt9O1xuICAgIGxldCBsb2dpbkhpbnQgPSBudWxsO1xuICAgIGlmICh0eXBlb2YgcGFyYW1zID09PSAnc3RyaW5nJykge1xuICAgICAgbG9naW5IaW50ID0gcGFyYW1zO1xuICAgIH0gZWxzZSBpZiAodHlwZW9mIHBhcmFtcyA9PT0gJ29iamVjdCcpIHtcbiAgICAgIGFkZFBhcmFtcyA9IHBhcmFtcztcbiAgICB9XG5cbiAgICB0aGlzLmNyZWF0ZUxvZ2luVXJsKGFkZGl0aW9uYWxTdGF0ZSwgbG9naW5IaW50LCBudWxsLCBmYWxzZSwgYWRkUGFyYW1zKVxuICAgICAgLnRoZW4odGhpcy5jb25maWcub3BlblVyaSlcbiAgICAgIC5jYXRjaChlcnJvciA9PiB7XG4gICAgICAgIGNvbnNvbGUuZXJyb3IoJ0Vycm9yIGluIGluaXRBdXRob3JpemF0aW9uQ29kZUZsb3cnKTtcbiAgICAgICAgY29uc29sZS5lcnJvcihlcnJvcik7XG4gICAgICB9KTtcbiAgfVxuXG4gIHByb3RlY3RlZCBhc3luYyBjcmVhdGVDaGFsbGFuZ2VWZXJpZmllclBhaXJGb3JQS0NFKCk6IFByb21pc2U8XG4gICAgW3N0cmluZywgc3RyaW5nXVxuICA+IHtcbiAgICBpZiAoIXRoaXMuY3J5cHRvKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoXG4gICAgICAgICdQS0NFIHN1cHBvcnQgZm9yIGNvZGUgZmxvdyBuZWVkcyBhIENyeXB0b0hhbmRlci4gRGlkIHlvdSBpbXBvcnQgdGhlIE9BdXRoTW9kdWxlIHVzaW5nIGZvclJvb3QoKSA/J1xuICAgICAgKTtcbiAgICB9XG5cbiAgICBjb25zdCB2ZXJpZmllciA9IGF3YWl0IHRoaXMuY3JlYXRlTm9uY2UoKTtcbiAgICBjb25zdCBjaGFsbGVuZ2VSYXcgPSBhd2FpdCB0aGlzLmNyeXB0by5jYWxjSGFzaCh2ZXJpZmllciwgJ3NoYS0yNTYnKTtcbiAgICBjb25zdCBjaGFsbGVuZ2UgPSBiYXNlNjRVcmxFbmNvZGUoY2hhbGxlbmdlUmF3KTtcblxuICAgIHJldHVybiBbY2hhbGxlbmdlLCB2ZXJpZmllcl07XG4gIH1cblxuICBwcml2YXRlIGV4dHJhY3RSZWNvZ25pemVkQ3VzdG9tUGFyYW1ldGVycyhcbiAgICB0b2tlblJlc3BvbnNlOiBUb2tlblJlc3BvbnNlXG4gICk6IE1hcDxzdHJpbmcsIHN0cmluZz4ge1xuICAgIGxldCBmb3VuZFBhcmFtZXRlcnM6IE1hcDxzdHJpbmcsIHN0cmluZz4gPSBuZXcgTWFwPHN0cmluZywgc3RyaW5nPigpO1xuICAgIGlmICghdGhpcy5jb25maWcuY3VzdG9tVG9rZW5QYXJhbWV0ZXJzKSB7XG4gICAgICByZXR1cm4gZm91bmRQYXJhbWV0ZXJzO1xuICAgIH1cbiAgICB0aGlzLmNvbmZpZy5jdXN0b21Ub2tlblBhcmFtZXRlcnMuZm9yRWFjaCgocmVjb2duaXplZFBhcmFtZXRlcjogc3RyaW5nKSA9PiB7XG4gICAgICBpZiAodG9rZW5SZXNwb25zZVtyZWNvZ25pemVkUGFyYW1ldGVyXSkge1xuICAgICAgICBmb3VuZFBhcmFtZXRlcnMuc2V0KFxuICAgICAgICAgIHJlY29nbml6ZWRQYXJhbWV0ZXIsXG4gICAgICAgICAgSlNPTi5zdHJpbmdpZnkodG9rZW5SZXNwb25zZVtyZWNvZ25pemVkUGFyYW1ldGVyXSlcbiAgICAgICAgKTtcbiAgICAgIH1cbiAgICB9KTtcbiAgICByZXR1cm4gZm91bmRQYXJhbWV0ZXJzO1xuICB9XG5cbiAgLyoqXG4gICAqIFJldm9rZXMgdGhlIGF1dGggdG9rZW4gdG8gc2VjdXJlIHRoZSB2dWxuYXJhYmlsaXR5XG4gICAqIG9mIHRoZSB0b2tlbiBpc3N1ZWQgYWxsb3dpbmcgdGhlIGF1dGhvcml6YXRpb24gc2VydmVyIHRvIGNsZWFuXG4gICAqIHVwIGFueSBzZWN1cml0eSBjcmVkZW50aWFscyBhc3NvY2lhdGVkIHdpdGggdGhlIGF1dGhvcml6YXRpb25cbiAgICovXG4gIHB1YmxpYyByZXZva2VUb2tlbkFuZExvZ291dChcbiAgICBjdXN0b21QYXJhbWV0ZXJzOiBvYmplY3QgPSB7fSxcbiAgICBpZ25vcmVDb3JzSXNzdWVzID0gZmFsc2VcbiAgKTogUHJvbWlzZTxhbnk+IHtcbiAgICBsZXQgcmV2b2tlRW5kcG9pbnQgPSB0aGlzLnJldm9jYXRpb25FbmRwb2ludDtcbiAgICBsZXQgYWNjZXNzVG9rZW4gPSB0aGlzLmdldEFjY2Vzc1Rva2VuKCk7XG4gICAgbGV0IHJlZnJlc2hUb2tlbiA9IHRoaXMuZ2V0UmVmcmVzaFRva2VuKCk7XG5cbiAgICBpZiAoIWFjY2Vzc1Rva2VuKSB7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgbGV0IHBhcmFtcyA9IG5ldyBIdHRwUGFyYW1zKCk7XG5cbiAgICBsZXQgaGVhZGVycyA9IG5ldyBIdHRwSGVhZGVycygpLnNldChcbiAgICAgICdDb250ZW50LVR5cGUnLFxuICAgICAgJ2FwcGxpY2F0aW9uL3gtd3d3LWZvcm0tdXJsZW5jb2RlZCdcbiAgICApO1xuXG4gICAgaWYgKHRoaXMudXNlSHR0cEJhc2ljQXV0aCkge1xuICAgICAgY29uc3QgaGVhZGVyID0gYnRvYShgJHt0aGlzLmNsaWVudElkfToke3RoaXMuZHVtbXlDbGllbnRTZWNyZXR9YCk7XG4gICAgICBoZWFkZXJzID0gaGVhZGVycy5zZXQoJ0F1dGhvcml6YXRpb24nLCAnQmFzaWMgJyArIGhlYWRlcik7XG4gICAgfVxuXG4gICAgaWYgKCF0aGlzLnVzZUh0dHBCYXNpY0F1dGgpIHtcbiAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoJ2NsaWVudF9pZCcsIHRoaXMuY2xpZW50SWQpO1xuICAgIH1cblxuICAgIGlmICghdGhpcy51c2VIdHRwQmFzaWNBdXRoICYmIHRoaXMuZHVtbXlDbGllbnRTZWNyZXQpIHtcbiAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoJ2NsaWVudF9zZWNyZXQnLCB0aGlzLmR1bW15Q2xpZW50U2VjcmV0KTtcbiAgICB9XG5cbiAgICBpZiAodGhpcy5jdXN0b21RdWVyeVBhcmFtcykge1xuICAgICAgZm9yIChjb25zdCBrZXkgb2YgT2JqZWN0LmdldE93blByb3BlcnR5TmFtZXModGhpcy5jdXN0b21RdWVyeVBhcmFtcykpIHtcbiAgICAgICAgcGFyYW1zID0gcGFyYW1zLnNldChrZXksIHRoaXMuY3VzdG9tUXVlcnlQYXJhbXNba2V5XSk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgcmV0dXJuIG5ldyBQcm9taXNlKChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIGxldCByZXZva2VBY2Nlc3NUb2tlbjogT2JzZXJ2YWJsZTx2b2lkPjtcbiAgICAgIGxldCByZXZva2VSZWZyZXNoVG9rZW46IE9ic2VydmFibGU8dm9pZD47XG5cbiAgICAgIGlmIChhY2Nlc3NUb2tlbikge1xuICAgICAgICBsZXQgcmV2b2thdGlvblBhcmFtcyA9IHBhcmFtc1xuICAgICAgICAgIC5zZXQoJ3Rva2VuJywgYWNjZXNzVG9rZW4pXG4gICAgICAgICAgLnNldCgndG9rZW5fdHlwZV9oaW50JywgJ2FjY2Vzc190b2tlbicpO1xuICAgICAgICByZXZva2VBY2Nlc3NUb2tlbiA9IHRoaXMuaHR0cC5wb3N0PHZvaWQ+KFxuICAgICAgICAgIHJldm9rZUVuZHBvaW50LFxuICAgICAgICAgIHJldm9rYXRpb25QYXJhbXMsXG4gICAgICAgICAgeyBoZWFkZXJzIH1cbiAgICAgICAgKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHJldm9rZUFjY2Vzc1Rva2VuID0gb2YobnVsbCk7XG4gICAgICB9XG5cbiAgICAgIGlmIChyZWZyZXNoVG9rZW4pIHtcbiAgICAgICAgbGV0IHJldm9rYXRpb25QYXJhbXMgPSBwYXJhbXNcbiAgICAgICAgICAuc2V0KCd0b2tlbicsIHJlZnJlc2hUb2tlbilcbiAgICAgICAgICAuc2V0KCd0b2tlbl90eXBlX2hpbnQnLCAncmVmcmVzaF90b2tlbicpO1xuICAgICAgICByZXZva2VSZWZyZXNoVG9rZW4gPSB0aGlzLmh0dHAucG9zdDx2b2lkPihcbiAgICAgICAgICByZXZva2VFbmRwb2ludCxcbiAgICAgICAgICByZXZva2F0aW9uUGFyYW1zLFxuICAgICAgICAgIHsgaGVhZGVycyB9XG4gICAgICAgICk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICByZXZva2VSZWZyZXNoVG9rZW4gPSBvZihudWxsKTtcbiAgICAgIH1cblxuICAgICAgaWYgKGlnbm9yZUNvcnNJc3N1ZXMpIHtcbiAgICAgICAgcmV2b2tlQWNjZXNzVG9rZW4gPSByZXZva2VBY2Nlc3NUb2tlbi5waXBlKFxuICAgICAgICAgIGNhdGNoRXJyb3IoKGVycjogSHR0cEVycm9yUmVzcG9uc2UpID0+IHtcbiAgICAgICAgICAgIGlmIChlcnIuc3RhdHVzID09PSAwKSB7XG4gICAgICAgICAgICAgIHJldHVybiBvZjx2b2lkPihudWxsKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHJldHVybiB0aHJvd0Vycm9yKGVycik7XG4gICAgICAgICAgfSlcbiAgICAgICAgKTtcblxuICAgICAgICByZXZva2VSZWZyZXNoVG9rZW4gPSByZXZva2VSZWZyZXNoVG9rZW4ucGlwZShcbiAgICAgICAgICBjYXRjaEVycm9yKChlcnI6IEh0dHBFcnJvclJlc3BvbnNlKSA9PiB7XG4gICAgICAgICAgICBpZiAoZXJyLnN0YXR1cyA9PT0gMCkge1xuICAgICAgICAgICAgICByZXR1cm4gb2Y8dm9pZD4obnVsbCk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICByZXR1cm4gdGhyb3dFcnJvcihlcnIpO1xuICAgICAgICAgIH0pXG4gICAgICAgICk7XG4gICAgICB9XG5cbiAgICAgIGNvbWJpbmVMYXRlc3QoW3Jldm9rZUFjY2Vzc1Rva2VuLCByZXZva2VSZWZyZXNoVG9rZW5dKS5zdWJzY3JpYmUoXG4gICAgICAgIHJlcyA9PiB7XG4gICAgICAgICAgdGhpcy5sb2dPdXQoY3VzdG9tUGFyYW1ldGVycyk7XG4gICAgICAgICAgcmVzb2x2ZShyZXMpO1xuICAgICAgICAgIHRoaXMubG9nZ2VyLmluZm8oJ1Rva2VuIHN1Y2Nlc3NmdWxseSByZXZva2VkJyk7XG4gICAgICAgIH0sXG4gICAgICAgIGVyciA9PiB7XG4gICAgICAgICAgdGhpcy5sb2dnZXIuZXJyb3IoJ0Vycm9yIHJldm9raW5nIHRva2VuJywgZXJyKTtcbiAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChcbiAgICAgICAgICAgIG5ldyBPQXV0aEVycm9yRXZlbnQoJ3Rva2VuX3Jldm9rZV9lcnJvcicsIGVycilcbiAgICAgICAgICApO1xuICAgICAgICAgIHJlamVjdChlcnIpO1xuICAgICAgICB9XG4gICAgICApO1xuICAgIH0pO1xuICB9XG59XG4iXX0=
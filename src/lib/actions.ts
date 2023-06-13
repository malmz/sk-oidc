import { redirect, error, type Cookies } from '@sveltejs/kit';
import type { AuthConfig } from './types.js';
import * as oauth from 'oauth4webapi';
import {
	codeChallenge,
	takeState,
	nonceChallenge,
	stateChallenge,
	takeCodeVerifier,
	takeNonce
} from './checks.js';
import { setSession } from './session.js';
import { authorizationServer, getCallbackUrl } from './oidc.js';

export async function signin(config: AuthConfig, cookies: Cookies, url: URL): Promise<Response> {
	const as = await authorizationServer(config);
	if (!as.authorization_endpoint) {
		throw error(500, 'No authorization endpoint found');
	}

	const authorizationUrl = new URL(as.authorization_endpoint);
	const urlparams = authorizationUrl.searchParams;

	const state = await stateChallenge(cookies, config);
	const code_challenge = await codeChallenge(cookies, config);
	const code_challenge_method = 'S256';
	const nonce = await nonceChallenge(cookies, config);

	const userParams = config.params || {};
	userParams.scope ??= 'openid profile email';

	const params = {
		client_id: config.client_id,
		redirect_uri: getCallbackUrl(url),
		response_type: 'code',
		state,
		code_challenge,
		code_challenge_method,
		nonce,
		...userParams
	};

	for (const [key, val] of Object.entries(params)) {
		urlparams.set(key, val);
	}

	throw redirect(302, authorizationUrl.toString());
}

export async function callback(config: AuthConfig, cookies: Cookies, url: URL): Promise<Response> {
	const as = await authorizationServer(config);

	const state = await takeState(cookies, config);
	const params = oauth.validateAuthResponse(as, config, url.searchParams, state);
	if (oauth.isOAuth2Error(params)) {
		throw error(500, params.error);
	}
	const code_verifier = await takeCodeVerifier(cookies, config);

	const response = await oauth.authorizationCodeGrantRequest(
		as,
		config,
		params,
		getCallbackUrl(url),
		code_verifier
	);
	const challenges = oauth.parseWwwAuthenticateChallenges(response);
	if (challenges) {
		throw error(500, 'Unsupported www-authenticate response from authorization server');
	}

	const nonce = await takeNonce(cookies, config);
	const result = await oauth.processAuthorizationCodeOpenIDResponse(as, config, response, nonce);

	if (oauth.isOAuth2Error(result)) {
		throw error(500, result.error);
	}

	const claims = oauth.getValidatedIdTokenClaims(result);

	await setSession(
		cookies,
		{
			access_token: result.access_token,
			refresh_token: result.refresh_token,
			sub: claims.sub,
			name: claims.name,
			picture: claims.picture,
			roles: claims['urn:zitadel:iam:org:project:roles']
		},
		config
	);

	throw redirect(302, '/');
}

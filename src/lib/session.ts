import { error, type Cookies } from '@sveltejs/kit';
import type { AuthConfig, Session } from './types.js';
import { DEFAULT_MAX_AGE, sealCookie, unsealCookie } from './jwt.js';
import * as oauth from 'oauth4webapi';
import { authorizationServer } from './oidc.js';

export async function setSession(cookies: Cookies, session: Session, config: AuthConfig) {
	await sealCookie(
		cookies,
		'session',
		JSON.stringify(session),
		DEFAULT_MAX_AGE,
		config.cookie_secret
	);
}

export async function getSession(cookies: Cookies, config: AuthConfig): Promise<Session | null> {
	const val = await unsealCookie(cookies, 'session', config.cookie_secret);
	return val ? JSON.parse(val) : null;
}

export async function introspectSession(session: Session, config: AuthConfig) {
	const as = await authorizationServer(config);
	const response = await oauth.introspectionRequest(as, config, session.access_token);
	const result = await oauth.processIntrospectionResponse(as, config, response);
	if (oauth.isOAuth2Error(result)) {
		throw error(500, result.error);
	}
	return result;
}

import type { Cookies } from '@sveltejs/kit';
import type { TokenSet } from 'openid-client';
import { DEFAULT_MAX_AGE, PKCE_MAX_AGE, STATE_MAX_AGE } from './constants';
import { decode, encode } from './jwt';

export async function takeState(cookies: Cookies, secret: string): Promise<string> {
	const cookie = cookies.get('sk.auth.state') ?? '';
	cookies.delete('sk.auth.state', { path: '/' });
	const payload = await decode(cookie, secret);
	const state = payload?.state as string;
	return state;
}

export async function setState(cookies: Cookies, secret: string, state: string) {
	const cookie = await encode({ state }, secret, STATE_MAX_AGE);
	cookies.set('sk.auth.state', cookie, {
		path: '/',
		expires: new Date(Date.now() + STATE_MAX_AGE * 1000)
	});
}

export async function takeCodeVerifier(cookies: Cookies, secret: string): Promise<string> {
	const cookie = cookies.get('sk.auth.code_verifier') ?? '';
	cookies.delete('sk.auth.code_verifier', { path: '/' });
	const payload = await decode(cookie, secret);
	const code_verifier = payload?.code_verifier as string;
	return code_verifier;
}

export async function setCodeVerifier(cookies: Cookies, secret: string, code_verifier: string) {
	const cookie = await encode({ code_verifier }, secret, PKCE_MAX_AGE);
	cookies.set('sk.auth.code_verifier', cookie, {
		path: '/',
		expires: new Date(Date.now() + PKCE_MAX_AGE * 1000)
	});
}

export async function setSession(cookies: Cookies, secret: string, session: TokenSet) {
	const cookie = await encode(session as Record<string, unknown>, secret, DEFAULT_MAX_AGE);
	cookies.set('sk.auth.session', cookie, {
		path: '/',
		expires: new Date(Date.now() + DEFAULT_MAX_AGE * 1000)
	});
}

export async function getSession(cookies: Cookies, secret: string): Promise<TokenSet | null> {
	const cookie = cookies.get('sk.auth.session') ?? '';
	const payload = await decode(cookie, secret);
	if (!payload) {
		return null;
	}

	const session = payload as Session;
	if (session.expires_at && session.expires_at < now()) {
		return null;
	}

	return new TokenSet({
		access_token: session.access_token,
		refresh_token: session.refresh_token,
		id_token: session.id_token,
		token_type: session.token_type,
		scope: session.scope,
		expires_at: session.expires_at
	});
}

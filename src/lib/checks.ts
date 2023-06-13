import { error, type Cookies } from '@sveltejs/kit';
import * as oauth from 'oauth4webapi';
import { sealCookie, unsealCookie } from './jwt.js';
import type { AuthConfig } from './types.js';

const STATE_MAX_AGE = 60 * 15; // 15 minutes
const PKCE_MAX_AGE = 60 * 15; // 15 minutes
const NONCE_MAX_AGE = 60 * 15; // 15 minutes

export async function stateChallenge(cookies: Cookies, options: AuthConfig): Promise<string> {
	const state = oauth.generateRandomState();
	await sealCookie(cookies, 'state', state, STATE_MAX_AGE, options.cookie_secret);
	return state;
}

export async function codeChallenge(cookies: Cookies, options: AuthConfig): Promise<string> {
	const code_verifier = oauth.generateRandomCodeVerifier();
	await sealCookie(cookies, 'code_verifier', code_verifier, PKCE_MAX_AGE, options.cookie_secret);
	const code_challenge = oauth.calculatePKCECodeChallenge(code_verifier);
	return code_challenge;
}

export async function nonceChallenge(cookies: Cookies, options: AuthConfig): Promise<string> {
	const nonce = oauth.generateRandomNonce();
	await sealCookie(cookies, 'nonce', nonce, NONCE_MAX_AGE, options.cookie_secret);
	return nonce;
}

export async function takeState(cookies: Cookies, options: AuthConfig): Promise<string> {
	const val = await unsealCookie(cookies, 'state', options.cookie_secret);
	if (!val) throw error(500, 'No state found');
	cookies.delete('state', { path: '/' });
	return val;
}

export async function takeCodeVerifier(cookies: Cookies, options: AuthConfig): Promise<string> {
	const val = await unsealCookie(cookies, 'code_verifier', options.cookie_secret);
	if (!val) throw error(500, 'No code_verifier found');
	cookies.delete('code_verifier', { path: '/' });
	return val;
}

export async function takeNonce(cookies: Cookies, options: AuthConfig): Promise<string> {
	const val = await unsealCookie(cookies, 'nonce', options.cookie_secret);
	if (!val) throw error(500, 'No nonce found');
	cookies.delete('nonce', { path: '/' });
	return val;
}

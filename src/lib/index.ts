import { error, json, redirect, type Cookies, type RequestHandler } from '@sveltejs/kit';
import { generators, Issuer, TokenSet, type ClientAuthMethod } from 'openid-client';
import hkdf from '@panva/hkdf';
import { EncryptJWT, jwtDecrypt, type JWTPayload } from 'jose';
import { v4 as uuid } from 'uuid';

export interface AuthOptions {
	issuer: string;
	clientId: string;
	clientSecret?: string;
	redirectUri: string;
	tokenEndpointAuthMethod?: ClientAuthMethod;
	cookieSecret: string;
	scope?: string;
}

async function openidClient(options: AuthOptions) {
	const issuer = await Issuer.discover(options.issuer);

	const client = new issuer.Client({
		client_id: options.clientId,
		client_secret: options.clientSecret,
		redirect_uris: [options.redirectUri],
		token_endpoint_auth_method: options.tokenEndpointAuthMethod ?? 'client_secret_basic',
		response_types: ['code'],
		scope: options.scope ?? 'openid profile email offline_access'
	});

	return client;
}

interface Session {
	access_token?: string;
	refresh_token?: string;
	id_token?: string;
	token_type?: string;
	scope?: string;
	expires_at?: number;
}

async function takeState(cookies: Cookies, secret: string): Promise<string> {
	const cookie = cookies.get('sk.auth.state') ?? '';
	cookies.delete('sk.auth.state', { path: '/' });
	const payload = await decode(cookie, secret);
	const state = payload?.state as string;
	return state;
}

async function setState(cookies: Cookies, secret: string, state: string) {
	const cookie = await encode({ state }, secret, STATE_MAX_AGE);
	cookies.set('sk.auth.state', cookie, {
		path: '/',
		expires: new Date(Date.now() + STATE_MAX_AGE * 1000)
	});
}

async function takeCodeVerifier(cookies: Cookies, secret: string): Promise<string> {
	const cookie = cookies.get('sk.auth.code_verifier') ?? '';
	cookies.delete('sk.auth.code_verifier', { path: '/' });
	const payload = await decode(cookie, secret);
	const code_verifier = payload?.code_verifier as string;
	return code_verifier;
}

async function setCodeVerifier(cookies: Cookies, secret: string, code_verifier: string) {
	const cookie = await encode({ code_verifier }, secret, PKCE_MAX_AGE);
	cookies.set('sk.auth.code_verifier', cookie, {
		path: '/',
		expires: new Date(Date.now() + PKCE_MAX_AGE * 1000)
	});
}

async function setSession(cookies: Cookies, secret: string, session: Session) {
	const cookie = await encode(session as Record<string, unknown>, secret, DEFAULT_MAX_AGE);
	cookies.set('sk.auth.session', cookie, {
		path: '/',
		expires: new Date(Date.now() + DEFAULT_MAX_AGE * 1000)
	});
}

async function getSession(cookies: Cookies, secret: string): Promise<TokenSet | null> {
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

export function RouteHandler(options: AuthOptions): {
	GET: RequestHandler;
} {
	const handler: RequestHandler = async ({ url, params, cookies }) => {
		switch (params.action) {
			case 'signin': {
				const client = await openidClient(options);

				const code_verifier = generators.codeVerifier(64);
				const code_challenge = generators.codeChallenge(code_verifier);
				const state = generators.state(64);

				await setState(cookies, options.cookieSecret, state);
				await setCodeVerifier(cookies, options.cookieSecret, code_verifier);

				const url = client.authorizationUrl({
					code_challenge,
					code_challenge_method: PKCE_CODE_CHALLENGE_METHOD,
					state,
					client_id: options.clientId,
					redirect_uri: options.redirectUri,
					scope: options.scope
				});

				throw redirect(302, url);
			}
			case 'callback': {
				const client = await openidClient(options);

				const params = client.callbackParams(url.toString());

				const state = await takeState(cookies, options.cookieSecret);
				const code_verifier = await takeCodeVerifier(cookies, options.cookieSecret);

				const token_set = await client.callback(
					options.redirectUri,
					params,
					{
						code_verifier,
						state
					},
					{
						exchangeBody: {
							client_id: options.clientId
						}
					}
				);

				console.log(token_set);
				console.log('claims', token_set.claims());

				const { access_token, refresh_token, id_token, token_type, scope, expires_at }: Session =
					token_set;

				await setSession(cookies, options.cookieSecret, {
					access_token,
					refresh_token,
					id_token,
					token_type,
					scope,
					expires_at
				});

				throw redirect(302, '/');
			}

			case 'signout': {
				const client = await openidClient(options);

				const session = await getSession(cookies, options.cookieSecret);

				const url = client.endSessionUrl({
					id_token_hint: session?.id_token,
					post_logout_redirect_uri: options.redirectUri
				});
				throw redirect(302, url);
			}

			case 'session': {
				const client = await openidClient(options);
				const required = url.searchParams.get('required') !== null;
				const tokenSet = await getSession(cookies, options.cookieSecret);

				if (!tokenSet) {
					return sessionError(required);
				}

				try {
					const res = await client.userinfo(tokenSet);
					return json({
						...res,
						authenticated: true
					});
				} catch (err) {
					cookies.delete('sk.auth.session', { path: '/' });
					return sessionError(required);
				}
			}
		}
		throw error(404, `Action "${params.action}" not supported`);
	};

	return {
		GET: handler
	};
}

function sessionError(required: boolean): Response {
	if (required) {
		throw redirect(302, '/auth/signin');
	}

	return json({
		authenticated: false
	});
}

const DEFAULT_MAX_AGE = 30 * 24 * 60 * 60; // 30 days
const STATE_MAX_AGE = 60 * 15; // 15 minutes in seconds
const PKCE_CODE_CHALLENGE_METHOD = 'S256';
const PKCE_MAX_AGE = 60 * 15; // 15 minutes in seconds

const now = () => (Date.now() / 1000) | 0;

export async function encode(
	token: Record<string, unknown>,
	secret: string,
	maxAge = DEFAULT_MAX_AGE
): Promise<string> {
	const encryptionSecret = await getDerivedEncryptionKey(secret);
	return await new EncryptJWT(token)
		.setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
		.setIssuedAt()
		.setExpirationTime(now() + maxAge)
		.setJti(uuid())
		.encrypt(encryptionSecret);
}

export async function decode(token: string, secret: string): Promise<JWTPayload | null> {
	if (!token) return null;
	const encryptionSecret = await getDerivedEncryptionKey(secret);
	const { payload } = await jwtDecrypt(token, encryptionSecret, {
		clockTolerance: 15
	});

	return payload;
}

async function getDerivedEncryptionKey(secret: string) {
	return await hkdf('sha256', secret, '', 'SvelteKit-oidc Generated Encryption Key', 32);
}

export async function session(fetch: typeof globalThis.fetch, required: boolean) {
	const url = new URL('/auth/session');
	url.searchParams.append('required', '');
	const res = await fetch('/auth/session?required=' + required);
	const data = await res.json();
	return data;
}

export function signin() {
	return false;
}

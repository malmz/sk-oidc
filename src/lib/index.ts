import { error, json, redirect, type RequestHandler } from '@sveltejs/kit';
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

export function RouteHandler(options: AuthOptions): {
	GET: RequestHandler;
} {
	const handler: RequestHandler = async ({ url, params, cookies }) => {
		console.log('action', params.action);

		switch (params.action) {
			case 'signin': {
				const client = await openidClient(options);
				const code_verifier = generators.codeVerifier();
				const code_challenge = generators.codeChallenge(code_verifier);
				const state = generators.state();

				const state_cookie = await encode({ state }, options.cookieSecret, STATE_MAX_AGE);
				const code_verifier_cookie = await encode(
					{ code_verifier },
					options.cookieSecret,
					PKCE_MAX_AGE
				);

				cookies.set('sk.auth.state', state_cookie, {
					path: '/',
					expires: new Date(Date.now() + STATE_MAX_AGE * 1000)
				});

				cookies.set('sk.auth.code_verifier', code_verifier_cookie, {
					path: '/',
					expires: new Date(Date.now() + PKCE_MAX_AGE * 1000)
				});

				const url = client.authorizationUrl({
					code_challenge,
					code_challenge_method: PKCE_CODE_CHALLENGE_METHOD,
					state,
					client_id: options.clientId,
					redirect_uri: options.redirectUri,
					scope: 'openid profile email'
				});

				throw redirect(302, url);
			}
			case 'callback': {
				const client = await openidClient(options);
				const params = client.callbackParams(url.toString());

				const state_cookie = cookies.get('sk.auth.state') ?? '';
				const code_verifier_cookie = cookies.get('sk.auth.code_verifier') ?? '';
				cookies.delete('sk.auth.state', { path: '/' });
				cookies.delete('sk.auth.code_verifier', { path: '/' });

				const state_pl = await decode(state_cookie, options.cookieSecret);
				const code_verifier_pl = await decode(code_verifier_cookie, options.cookieSecret);

				const state = state_pl?.state as string;
				const code_verifier = code_verifier_pl?.code_verifier as string;

				const token_set = await client.callback(options.redirectUri, params, {
					code_verifier,
					state
				});

				const { access_token, refresh_token, id_token, token_type, scope, expires_at }: Session =
					token_set;

				const session = await encode(
					{ access_token, refresh_token, id_token, token_type, scope, expires_at },
					options.cookieSecret,
					DEFAULT_MAX_AGE
				);
				cookies.set('sk.auth.session', session, {
					path: '/',
					expires: new Date(Date.now() + DEFAULT_MAX_AGE * 1000)
				});

				throw redirect(302, '/');
			}
			case 'session': {
				const client = await openidClient(options);
				const required = url.searchParams.get('required') !== null;
				const session_cookie = cookies.get('sk.auth.session') ?? '';
				const token_set_pl = await decode(session_cookie, options.cookieSecret);

				if (!token_set_pl) {
					if (required) {
						throw redirect(302, '/auth/signin');
					}

					return json({});
				}

				const { access_token, refresh_token, id_token, token_type, scope, expires_at } =
					token_set_pl as Session;

				const res = await client.userinfo(access_token ?? '', {
					tokenType: token_type ?? 'bearer'
				});
				
				return json(res);
			}
		}
		throw error(404, 'Action not supported');
	};

	return {
		GET: handler
	};
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

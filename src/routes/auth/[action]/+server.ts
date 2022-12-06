import { RouteHandler } from '$lib';
import { AUTH_CLIENT_ID, AUTH_CLIENT_SECRET, AUTH_ISSUER } from '$env/static/private';

export const { GET } = RouteHandler({
	issuer: AUTH_ISSUER,
	clientId: AUTH_CLIENT_ID,
	clientSecret: AUTH_CLIENT_SECRET,
	redirectUri: 'http://127.0.0.1:5173/auth/callback',
	cookieSecret: 'very-secret',
	scope: 'openid offline_access profile email'
});

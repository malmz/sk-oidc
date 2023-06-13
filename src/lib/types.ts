import type { Client } from 'oauth4webapi';

export interface AuthConfig extends Client {
	issuer: string;
	cookie_secret: string;
	params?: {
		scope?: string;
	};
}

export interface Session {
	access_token: string;
	refresh_token?: string;
	[key: string]: unknown;
}

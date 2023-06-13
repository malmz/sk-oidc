import { error, type Handle, type RequestHandler } from '@sveltejs/kit';
import type { AuthConfig } from './types.js';
import * as actions from './actions.js';

const prefix = '/auth/';

export const authHook =
	(config: AuthConfig): Handle =>
	async ({ event, resolve }) => {
		if (event.url.pathname.startsWith(prefix)) {
			const action = event.url.pathname.slice(prefix.length);
			switch (action) {
				case 'signin':
					return actions.signin(config, event.cookies, event.url);
				case 'callback':
					return actions.callback(config, event.cookies, event.url);
				default:
					break;
			}
		}
		return await resolve(event);
	};

export const signin =
	(config: AuthConfig): RequestHandler =>
	({ cookies, url }) =>
		actions.signin(config, cookies, url);

export const callback =
	(config: AuthConfig): RequestHandler =>
	({ cookies, url }) =>
		actions.callback(config, cookies, url);

export const routeHandler =
	(config: AuthConfig): RequestHandler =>
	async ({ params, cookies, url }) => {
		switch (params.action) {
			case 'signin':
				return actions.signin(config, cookies, url);
			case 'callback':
				return actions.callback(config, cookies, url);
			default:
				throw error(404, 'Action not found');
		}
	};

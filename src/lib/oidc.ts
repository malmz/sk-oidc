import type { AuthConfig } from './types.js';
import * as oauth from 'oauth4webapi';

export async function authorizationServer(options: AuthConfig): Promise<oauth.AuthorizationServer> {
	const issuer = new URL(options.issuer);
	const discoveryResp = await oauth.discoveryRequest(issuer);
	return oauth.processDiscoveryResponse(issuer, discoveryResp);
}

export function getCallbackUrl(url: URL): string {
	return new URL('/auth/callback', url).toString();
}

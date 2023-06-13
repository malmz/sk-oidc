import { hkdf } from '@panva/hkdf';
import type { Cookies } from '@sveltejs/kit';
import { EncryptJWT, jwtDecrypt } from 'jose';

export interface DefaultJWT extends Record<string, unknown> {
	name?: string | null;
	email?: string | null;
	picture?: string | null;
	sub?: string;
}

export interface JWT extends Record<string, unknown>, DefaultJWT {}

export const DEFAULT_MAX_AGE = 60 * 60 * 24 * 30; // 30 days

function now() {
	return (Date.now() / 1000) | 0;
}

async function getDerivedEncryptionKey(secret: string) {
	return await hkdf('sha256', secret, '', 'SvelteKit-oidc Generated Encryption Key', 32);
}

export async function encode<Payload = JWT>(payload: Payload, secret: string, maxAge?: number) {
	const encryptionSecret = await getDerivedEncryptionKey(secret);
	// @ts-expect-error Any payload is fine
	return await new EncryptJWT(payload)
		.setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
		.setIssuedAt()
		.setExpirationTime(now() + (maxAge ?? DEFAULT_MAX_AGE))
		.setJti(crypto.randomUUID())
		.encrypt(encryptionSecret);
}

export async function decode<Payload = JWT>(
	token: string,
	secret: string
): Promise<Payload | null> {
	const encryptionSecret = await getDerivedEncryptionKey(secret);
	const { payload } = await jwtDecrypt(token, encryptionSecret, {
		clockTolerance: 15
	});

	return payload as Payload;
}

export async function sealCookie(
	cookies: Cookies,
	name: string,
	value: string,
	maxAge: number,
	secret: string
) {
	const encoded = await encode({ value }, secret, maxAge);
	cookies.set(name, encoded, {
		path: '/',
		expires: new Date(Date.now() + maxAge * 1000)
	});
}

export async function unsealCookie(
	cookies: Cookies,
	name: string,
	secret: string
): Promise<string | null> {
	const encoded = cookies.get(name);
	if (!encoded) {
		return null;
	}
	const token = await decode(encoded, secret);
	return (token?.value as string) ?? null;
}

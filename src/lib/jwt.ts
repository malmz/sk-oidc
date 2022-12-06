import hkdf from '@panva/hkdf';
import { EncryptJWT, jwtDecrypt, type JWTPayload } from 'jose';
import { v4 as uuid } from 'uuid';
import { DEFAULT_MAX_AGE } from './constants';

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

import type { PageLoad } from './$types';

export const load: PageLoad = async ({ fetch }) => {
	const req = await fetch('/auth/session');
	console.log(req);

	const session: Record<string, string> = await req.json();

	return {
		session
	};
};

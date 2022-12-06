import type { PageLoad } from './$types';

export const load: PageLoad = async ({ fetch }) => {
	const req = await fetch('/auth/session');

	const session = await req.json();
	console.log(session);

	return {
		session
	};
};

<script lang="ts">
	import type { PageData } from './$types';

	export let data: PageData;
</script>

<h1>sk-oidc</h1>
<p>Simple sessions with external openid connect provider</p>

<div>
	{#if data.session.authenticated}
		<p>You are logged in as</p>
		<a href="/auth/signout">Signout</a>

		<pre>{JSON.stringify(data.session, null, 2)}</pre>
	{:else}
		<a href="/auth/signin">Signin</a>
	{/if}
</div>

<style>
	h1 {
		font-family: monospace;
	}
</style>

<script lang="ts">
	import type { PageData, } from './$types';

    export let data: PageData;
</script>

<h1>Welcome to your library project</h1>
<p>Create your package using @sveltejs/package and preview/showcase your work with SvelteKit</p>
<p>Visit <a href="https://kit.svelte.dev">kit.svelte.dev</a> to read the documentation</p>
{#if data.session}
    <p>You are logged in as 
    </p>
    <pre>
        {JSON.stringify(data.session, null, 2)}
    </pre>
{:else}
    <a href="/auth/signin">Signin</a>
{/if}

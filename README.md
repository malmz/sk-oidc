# SvelteKit OpenID Connect

Add simple authentication to any SvelteKit app with OpenID Connect. Sessions are stored in encrypted JWT cookies

### Configure

Create a file `src/routes/auth/[action]/+server.ts`

```ts
export const { GET } = RouteHandler({
	issuer: 'https://auth.example.com', // The OpenID Connect issuer endpoint
	clientId: 'some-uuid-probably', // OAuth 2.0 Client ID
	clientSecret: 'some-secret-uuid-probaby', // OAuth 2.0 Client Secret
	redirectUri: 'http://127.0.0.1:5173/auth/callback', // Replace with your own domain
	cookieSecret: '!!!very-secret-plz-change!!!' // This is used to encrypt your cookies,
	scope: 'openid offline_access profile' // openid and offline_access are required
});
```

The current session 
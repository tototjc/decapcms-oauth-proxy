import { GitHub, generateState, OAuth2RequestError } from 'arctic'

export default {
  async fetch(request, env, context): Promise<Response> {
    const url = new URL(request.url)
    const github = new GitHub(env.GITHUB_OAUTH_ID, env.GITHUB_OAUTH_SECRET, {
      redirectURI: `https://${url.host}/callback`,
    })
    if (url.pathname === '/auth') {
      const state = generateState()
      const authUrl = await github.createAuthorizationURL(state, {
        scopes: ['user', 'repo'],
      })
      return Response.redirect(authUrl.toString(), 302)
    }
    if (url.pathname === '/callback') {
      const code = url.searchParams.get('code')
      if (!code) {
        return new Response('Missing code', { status: 400 })
      }
      try {
        const { accessToken } = await github.validateAuthorizationCode(code)
        const respText = `
          <script>
            window.addEventListener(
              'message',
              () => window.opener.postMessage('authorization:github:success:${JSON.stringify({
                token: accessToken,
              })}', '*'),
              { once: true },
            )
            window.opener.postMessage('authorizing:github', '*')
          </script>
        `
        return new Response(respText, {
          headers: { 'Content-Type': 'text/html' },
        })
      } catch (err) {
        if (err instanceof OAuth2RequestError) {
          return new Response('Invalid code', { status: 400 })
        } else {
          return new Response('Internal server error', { status: 500 })
        }
      }
    }
    return new Response('Ciallo～(∠・ω< )⌒☆')
  },
} satisfies ExportedHandler<Env>

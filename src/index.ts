import { GitHub, generateState, OAuth2RequestError } from 'arctic'

export default {
  async fetch(request, env, context): Promise<Response> {
    const { host, pathname, searchParams } = new URL(request.url)
    const github = new GitHub(env.GITHUB_OAUTH_ID, env.GITHUB_OAUTH_SECRET, {
      redirectURI: `https://${host}/callback`,
    })
    if (pathname === '/auth') {
      if (searchParams.get('provider') !== 'github') {
        return new Response('Invalid provider', { status: 400 })
      }
      if (searchParams.get('site_id') !== env.SITE_ID) {
        return new Response('Invalid site_id', { status: 400 })
      }
      const state = generateState()
      const authUrl = await github.createAuthorizationURL(state, {
        scopes: searchParams.get('scopes')?.split(' '),
      })
      return Response.redirect(authUrl.toString(), 302)
    }
    if (pathname === '/callback') {
      const code = searchParams.get('code')
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

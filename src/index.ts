import { GitHub, generateState, OAuth2RequestError } from 'arctic'
import { serializeCookie, parseCookies } from 'oslo/cookie'

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
      const siteId = searchParams.get('site_id')
      const allowSiteIdList = env.ALLOW_SITE_ID_LIST.trim().split(',')
      if (!siteId || !allowSiteIdList.includes(siteId)) {
        return new Response('Invalid site_id', { status: 400 })
      }
      const state = generateState()
      const authUrl = await github.createAuthorizationURL(state, {
        scopes: searchParams.get('scope')?.split(' '),
      })
      return new Response(null, {
        status: 302,
        headers: {
          Location: authUrl.toString(),
          'Set-Cookie': serializeCookie('__Secure-auth-state', state, {
            maxAge: 3 * 60,
            path: '/callback',
            httpOnly: true,
            secure: true,
            sameSite: 'lax',
          }),
        },
      })
    }
    if (pathname === '/callback') {
      const cookieStr = request.headers.get('Cookie')
      if (!cookieStr) {
        return new Response('Missing cookie', { status: 400 })
      }
      const state = searchParams.get('state')
      const storedState = parseCookies(cookieStr).get('__Secure-auth-state')
      if (!state || !storedState || state !== storedState) {
        return new Response('Invalid state', { status: 400 })
      }
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

import { GitHub, OAuth2RequestError, ArcticFetchError } from 'arctic'
import { csrfTokenGenerator } from './csrf-token'
import { parseCookies } from 'oslo/cookie'

export default {
  async fetch(request, env, context): Promise<Response> {
    try {
      const { host, pathname, searchParams } = new URL(request.url)
      const github = new GitHub(env.GITHUB_OAUTH_ID, env.GITHUB_OAUTH_SECRET, `https://${host}/callback`)
      const csrfToken = new csrfTokenGenerator({
        token: { secret: env.SECRET },
        cookie: {
          name: 'auth-state',
          prefix: 'secure',
          options: {
            maxAge: 3 * 60,
            path: '/callback',
          },
        },
      })
      if (pathname === '/auth') {
        const allowSiteIdList = env.ALLOW_SITE_ID_LIST.trim().split(',')
        const allowHostnameList = [...allowSiteIdList, 'localhost', '127.0.0.1']
        try {
          const referer = request.headers.get('Referer')
          if (!referer || !allowHostnameList.includes(new URL(referer).hostname)) throw new Error()
        } catch {
          return new Response('Invalid referer', { status: 400 })
        }
        const siteId = searchParams.get('site_id')
        if (!siteId || !allowSiteIdList.includes(siteId)) {
          return new Response('Invalid site_id', { status: 400 })
        }
        if (searchParams.get('provider') !== 'github') {
          return new Response('Invalid provider', { status: 400 })
        }
        const scope = searchParams.get('scope')
        const state = await csrfToken.getToken()
        const authUrl = github.createAuthorizationURL(state, scope ? scope.split(' ') : [])
        return new Response(null, {
          status: 302,
          headers: {
            Location: authUrl.toString(),
            'Set-Cookie': csrfToken.getTokenCookie(state).serialize(),
          },
        })
      }
      if (pathname === '/callback') {
        const cookieStr = request.headers.get('Cookie')
        if (!cookieStr) {
          return new Response('Missing cookie', { status: 400 })
        }
        const state = searchParams.get('state')
        const storedState = parseCookies(cookieStr).get(csrfToken.tokenCookieName)
        if (!state || !storedState || state !== storedState || !(await csrfToken.verifyToken(state))) {
          return new Response('Invalid state', { status: 400 })
        }
        const code = searchParams.get('code')
        if (!code) {
          return new Response('Missing code', { status: 400 })
        }
        const tokens = await github.validateAuthorizationCode(code)
        const respText = `
          <script>
            window.addEventListener(
              'message',
              () => window.opener.postMessage('authorization:github:success:${JSON.stringify({
                token: tokens.accessToken(),
              })}', '*'),
              { once: true },
            )
            window.opener.postMessage('authorizing:github', '*')
          </script>
        `
        return new Response(respText, {
          headers: {
            'Content-Type': 'text/html',
            'Set-Cookie': csrfToken.getBlankCookie().serialize(),
          },
        })
      }
    } catch (err) {
      if (err instanceof OAuth2RequestError) {
        return new Response('Invalid code', { status: 400 })
      } else if (err instanceof ArcticFetchError) {
        return new Response('Network error', { status: 500 })
      } else {
        return new Response('Internal server error', { status: 500 })
      }
    }
    return new Response('Ciallo～(∠・ω< )⌒☆')
  },
} satisfies ExportedHandler<Env>

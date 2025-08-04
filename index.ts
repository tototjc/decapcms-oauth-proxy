import { Hono, type Env as HonoEnv } from 'hono'
import { env } from 'hono/adapter'
import { every } from 'hono/combine'
import { createMiddleware } from 'hono/factory'
import { HTTPException } from 'hono/http-exception'
import { secureHeaders, NONCE, type SecureHeadersVariables } from 'hono/secure-headers'
import { setSignedCookie, getSignedCookie, deleteCookie } from 'hono/cookie'
import { GitHub, GitLab, generateState, OAuth2RequestError } from 'arctic'

const AUTH_ENDPOINT = '/auth'

const WINDOW_NAME = 'Netlify Authorization'

const DEFAULT_GITLAB_BASE_URL = 'https://gitlab.com'

declare const __BUILD_TIME__: string

declare module 'hono' {
  type Code = import('hono/utils/http-status').ContentfulStatusCode

  interface ContextRenderer {
    (
      status: 'success',
      payload: { token: string; [key: string]: unknown },
      code?: Code
    ): Response
    (
      status: 'error',
      payload: { message: string | null; [key: string]: unknown },
      code?: Code
    ): Response
  }
}

interface AppEnv extends HonoEnv {
  Bindings: Env
  Variables: {
    verifiedOrigin: string
    provider: 'github' | 'gitlab'
    oauthClient: GitHub | GitLab
  } & SecureHeadersVariables
}

const siteIdVerifyMiddleware = createMiddleware<AppEnv>(async (ctx, next) => {
  const site_id = ctx.req.query('site_id')
  const trustOriginsMap = new Map<string, string>()
  env(ctx).TRUST_ORIGINS.split(/\s+/).forEach(origin => {
    const url = URL.parse(origin)
    if (url) {
      const { hostname, origin } = url
      if (env(ctx).ALLOW_DECAP_LOCALHOST_LOGIN && hostname === 'localhost') {
        trustOriginsMap.set('demo.decapcms.org', origin)
      } else {
        trustOriginsMap.set(hostname, origin)
      }
    }
  })
  const verifiedOrigin = site_id && trustOriginsMap.get(site_id)
  if (!verifiedOrigin) {
    throw new HTTPException(400, { message: 'Invalid site_id' })
  }
  ctx.set('verifiedOrigin', verifiedOrigin)
  await next()
})

const oauthProviderMiddleware = createMiddleware<AppEnv>(async (ctx, next) => {
  const provider = ctx.req.query('provider')
  if (provider == 'github') {
    ctx.set(
      'oauthClient',
      new GitHub(
        env(ctx).GITHUB_OAUTH_ID,
        env(ctx).GITHUB_OAUTH_SECRET,
        ctx.req.url,
      )
    )
  } else if (provider == 'gitlab') {
    ctx.set(
      'oauthClient',
      new GitLab(
        env(ctx).GITLAB_BASE_URL ?? DEFAULT_GITLAB_BASE_URL,
        env(ctx).GITLAB_OAUTH_ID,
        env(ctx).GITLAB_OAUTH_SECRET,
        ctx.req.url,
      )
    )
  } else {
    throw new HTTPException(400, { message: 'Invalid provider' })
  }
  ctx.set('provider', provider)
  await next()
})

const respRenderMiddleware = createMiddleware<AppEnv>(async (ctx, next) => {
  const { provider, verifiedOrigin, secureHeadersNonce } = ctx.var
  ctx.setRenderer((status, payload, code) => {
    const signal = ['authorizing', provider].join(':')
    const data = ['authorization', provider, status, JSON.stringify(payload)].join(':')
    return ctx.html(`
<script nonce="${secureHeadersNonce}">
window.addEventListener('message', ({ data, origin, source }) => origin === '${verifiedOrigin}' && source === window.opener && data === '${signal}' && source.postMessage('${data}', origin), { once: true })
window.name === '${WINDOW_NAME}' && window.opener.postMessage('${signal}', '${verifiedOrigin}')
</script>
    `.trim(), code)
  })
  await next()
})

const secureAuthMiddleware = every(
  siteIdVerifyMiddleware,
  oauthProviderMiddleware,
  respRenderMiddleware
)

const app = new Hono<AppEnv>()

app.use(async (ctx, next) => {
  await next()
  ctx.header('Build-Time', __BUILD_TIME__)
})

app.use(
  secureHeaders({
    contentSecurityPolicy: {
      defaultSrc: ["'none'"],
      scriptSrcElem: [NONCE],
      frameAncestors: ["'none'"],
      formAction: ["'none'"],
    },
    crossOriginEmbedderPolicy: true,
    crossOriginOpenerPolicy: false,
    referrerPolicy: 'origin',
  })
)

app.onError((err, ctx) => {
  if (err instanceof OAuth2RequestError) {
    ctx.render('error', { message: err.description }, 400)
  }
  if (err instanceof HTTPException) {
    return err.getResponse()
  }
  return ctx.body('Internal Server Error', 500)
})

app.get(AUTH_ENDPOINT, secureAuthMiddleware, async ctx => {
  const code = ctx.req.query('code')
  const { provider, oauthClient } = ctx.var
  const stateCookieName = `${provider}-state` as const
  if (!code) {
    const state = generateState()
    await setSignedCookie(ctx, stateCookieName, state, env(ctx).SECRET, {
      maxAge: 3 * 60,
      httpOnly: true,
      path: AUTH_ENDPOINT,
      secure: true,
      sameSite: 'Lax',
      priority: 'High',
      prefix: 'secure',
    })
    return ctx.redirect(
      oauthClient.createAuthorizationURL(
        state,
        ctx.req.query('scope')?.split(' ') ?? []
      )
    )
  } else {
    const storedState = await getSignedCookie(
      ctx,
      env(ctx).SECRET,
      stateCookieName,
      'secure'
    )
    deleteCookie(ctx, stateCookieName, { path: AUTH_ENDPOINT, secure: true })
    const state = ctx.req.query('state')
    if (!state || !storedState || state !== storedState) {
      throw new HTTPException(400, { message: 'Invalid state' })
    }
    const tokens = await oauthClient.validateAuthorizationCode(code)
    return ctx.render('success', { token: tokens.accessToken() }, 200)
  }
})

app.all('*', ctx => ctx.text('Ciallo～(∠·ω< )⌒★', 418))

export default app satisfies ExportedHandler<Env>

import { Hono, type Env as HonoEnv } from 'hono'
import { env } from 'hono/adapter'
import { some, every } from 'hono/combine'
import { createMiddleware } from 'hono/factory'
import { HTTPException } from 'hono/http-exception'
import { encodeBase64Url, decodeBase64Url } from 'hono/utils/encode'
import { setSignedCookie, getSignedCookie, deleteCookie } from 'hono/cookie'
import { secureHeaders, NONCE, type SecureHeadersVariables } from 'hono/secure-headers'
import { GitHub, GitLab, generateState, OAuth2RequestError } from 'arctic'

const AUTH_ENDPOINT = '/auth'

const STATE_COOKIE_NAME = 'state'

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
    provider: string
    state: string
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

const providerVerifyMiddleware = createMiddleware<AppEnv>(async (ctx, next) => {
  const provider = ctx.req.query('provider')
  if (!provider) {
    throw new HTTPException(400, { message: 'Missing provider parameter' })
  }
  ctx.set('provider', provider)
  await next()
})

const paramsVerifyMiddleware = every(siteIdVerifyMiddleware, providerVerifyMiddleware)

const stateDecodeMiddleware = createMiddleware<AppEnv>(async (ctx, next) => {
  const state = ctx.req.query('state')
  if (!state) {
    throw new HTTPException(400, { message: 'Missing state parameter' })
  }
  const storedState = await getSignedCookie(
    ctx,
    env(ctx).SECRET,
    STATE_COOKIE_NAME,
    'secure'
  )
  if (!storedState || state !== storedState) {
    throw new HTTPException(400, { message: 'Invalid state' })
  }
  deleteCookie(ctx, STATE_COOKIE_NAME, { path: AUTH_ENDPOINT, secure: true })
  const stateParts = state.split('.')
  if (stateParts.length !== 2) {
    throw new HTTPException(400, { message: 'Invalid state format' })
  }
  const payload = (() => {
    try {
      return JSON.parse(
        new TextDecoder().decode(decodeBase64Url(stateParts[0]))
      ) as { provider: string; verifiedOrigin: string }
    } catch (e) {
      throw new HTTPException(400, { message: 'Invalid state payload' })
    }
  })()
  ctx.set('provider', payload.provider)
  ctx.set('verifiedOrigin', payload.verifiedOrigin)
  await next()
})

const stateEncodeMiddleware = createMiddleware<AppEnv>(async (ctx, next) => {
  const { provider, verifiedOrigin } = ctx.var
  const statePayload = encodeBase64Url(
    new TextEncoder().encode(JSON.stringify({ provider, verifiedOrigin })).buffer
  )
  const state = [statePayload, generateState()].join('.')
  await setSignedCookie(ctx, STATE_COOKIE_NAME, state, env(ctx).SECRET, {
    maxAge: 3 * 60,
    httpOnly: true,
    path: AUTH_ENDPOINT,
    secure: true,
    sameSite: 'Lax',
    priority: 'High',
    prefix: 'secure',
  })
  ctx.set('state', state)
  await next()
})

const oauthClientMiddleware = createMiddleware<AppEnv>(async (ctx, next) => {
  const { provider, verifiedOrigin, secureHeadersNonce } = ctx.var
  const callbackUrl = new URL(AUTH_ENDPOINT, ctx.req.url).href
  if (provider == 'github') {
    ctx.set(
      'oauthClient',
      new GitHub(
        env(ctx).GITHUB_OAUTH_ID,
        env(ctx).GITHUB_OAUTH_SECRET,
        callbackUrl,
      )
    )
  } else if (provider == 'gitlab') {
    ctx.set(
      'oauthClient',
      new GitLab(
        env(ctx).GITLAB_BASE_URL || DEFAULT_GITLAB_BASE_URL,
        env(ctx).GITLAB_OAUTH_ID,
        env(ctx).GITLAB_OAUTH_SECRET,
        callbackUrl,
      )
    )
  } else {
    throw new HTTPException(400, { message: 'Invalid provider' })
  }
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

app.get(
  AUTH_ENDPOINT,
  some(
    every(stateDecodeMiddleware, oauthClientMiddleware),
    every(paramsVerifyMiddleware, stateEncodeMiddleware, oauthClientMiddleware),
  ),
  async ctx => {
    const code = ctx.req.query('code')
    const { oauthClient, state } = ctx.var
    if (code) {
      const tokens = await oauthClient.validateAuthorizationCode(code)
      return ctx.render('success', { token: tokens.accessToken() }, 200)
    } else {
      return ctx.redirect(
        oauthClient.createAuthorizationURL(
          state,
          ctx.req.query('scope')?.split(' ') ?? []
        )
      )
    }
  }
)

app.all('*', ctx => ctx.text('Ciallo～(∠·ω< )⌒★', 418))

export default app satisfies ExportedHandler<Env>

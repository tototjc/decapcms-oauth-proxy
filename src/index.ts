import { Hono } from 'hono'
import { env } from 'hono/adapter'
import { HTTPException } from 'hono/http-exception'
import { setSignedCookie, getSignedCookie, deleteCookie } from 'hono/cookie'
import { GitHub, ArcticFetchError, OAuth2RequestError } from 'arctic'

import { generateToken, verifyToken } from './csrf-token'

const defaultAllowSiteIdList = ['localhost', '127.0.0.1']

const app = new Hono<{
  Bindings: Env
  Variables: {
    github: GitHub
  }
}>()

app.use(async (ctx, next) => {
  ctx.set(
    'github',
    new GitHub(
      env(ctx).GITHUB_OAUTH_ID,
      env(ctx).GITHUB_OAUTH_SECRET,
      `https://${new URL(ctx.req.url).host}/callback`
    )
  )
  await next()
  const err = ctx.error
  if (err instanceof OAuth2RequestError) {
    throw new HTTPException(400, { message: 'Invalid code', cause: err })
  }
  if (err instanceof ArcticFetchError) {
    throw new HTTPException(500, { message: 'Network error', cause: err })
  }
})

app.onError((err, ctx) => {
  if (err instanceof HTTPException) {
    return err.getResponse()
  } else {
    return ctx.body('Internal Server Error', 500)
  }
})

app.get('/auth', async ctx => {
  const allowSiteIdList = [
    ...env(ctx).ALLOW_SITE_ID_LIST.trim().split(','),
    ...defaultAllowSiteIdList,
  ]
  const { site_id, provider, scope } = ctx.req.query()
  const refererHost = URL.parse(ctx.req.header('Referer') ?? '')?.hostname
  if (!refererHost || !allowSiteIdList.includes(refererHost)) {
    throw new HTTPException(400, { message: 'Invalid referer' })
  }
  if (!site_id || !allowSiteIdList.includes(site_id)) {
    throw new HTTPException(400, { message: 'Invalid site_id' })
  }
  if (provider !== 'github') {
    throw new HTTPException(400, { message: 'Invalid provider' })
  }
  const state = await generateToken(env(ctx).SECRET)
  await setSignedCookie(ctx, 'auth-state', state, env(ctx).SECRET, {
    secure: true,
    sameSite: 'Lax',
    path: '/callback',
    maxAge: 3 * 60,
  })
  return ctx.redirect(
    ctx.var.github.createAuthorizationURL(state, scope ? scope.split(' ') : [])
  )
})

app.get('/callback', async ctx => {
  const { state, code } = ctx.req.query()
  if (!code) {
    throw new HTTPException(400, { message: 'Invalid code' })
  }
  const storedState = await getSignedCookie(
    ctx,
    env(ctx).SECRET,
    'auth-state',
    'secure'
  )
  if (
    !state ||
    !storedState ||
    state !== storedState ||
    !(await verifyToken(env(ctx).SECRET, state))
  ) {
    throw new HTTPException(400, { message: 'Invalid state' })
  }
  const tokens = await ctx.var.github.validateAuthorizationCode(code)
  deleteCookie(ctx, 'auth-state', { secure: true, path: '/callback' })
  return ctx.html(`
    <script>
      window.addEventListener(
        'message',
        () => window.opener.postMessage('authorization:github:success:${JSON.stringify(
          {
            token: tokens.accessToken(),
          }
        )}', '*'),
        { once: true },
      )
      window.opener.postMessage('au thorizing:github', '*')
    </script>
  `)
})

export default app satisfies ExportedHandler<Env>

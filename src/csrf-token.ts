import { CookieController, Cookie, type CookieAttributes } from 'oslo/cookie'
import { alphabet, generateRandomString, HMAC } from 'oslo/crypto'
import { base64url } from 'oslo/encoding'

export interface generatorConfig {
  token: {
    secret: string
    length?: number
  }
  cookie: {
    name: string
    prefix?: 'host' | 'secure'
    options?: CookieAttributes
  }
}

export class csrfTokenGenerator {
  hmac: HMAC
  enc: TextEncoder
  tokenLength: number
  cookieBuilder: CookieController

  protected tokenSecret: ArrayBuffer

  constructor({ token, cookie }: generatorConfig) {
    this.hmac = new HMAC('SHA-256')
    this.enc = new TextEncoder()
    this.tokenSecret = this.enc.encode(token.secret)
    this.tokenLength = token.length || 16

    let prefix: string

    switch (cookie.prefix) {
      case 'host':
        prefix = '__Host-'
        break
      case 'secure':
        prefix = '__Secure-'
        break
      default:
        prefix = ''
    }

    this.cookieBuilder = new CookieController(prefix + cookie.name, {
      path: '/',
      secure: true,
      httpOnly: true,
      sameSite: 'lax',
      ...cookie.options,
    })
  }

  public get tokenCookieName(): string {
    return this.cookieBuilder.cookieName
  }

  public getToken = async (): Promise<string> => {
    const plainValue = generateRandomString(this.tokenLength, alphabet('A-Z', 'a-z', '0-9'))
    const signData = await this.hmac.sign(this.tokenSecret, this.enc.encode(plainValue))
    const signValue = base64url.encode(new Uint8Array(signData), { includePadding: false })
    return [signValue, plainValue].join('.')
  }

  public verifyToken = async (token: string): Promise<boolean> => {
    const tokenParts = token.split('.')
    if (tokenParts.length !== 2) {
      return false
    }
    const [signValue, plainValue] = tokenParts
    const signData = base64url.decode(signValue, { strict: false })
    return await this.hmac.verify(this.tokenSecret, signData, this.enc.encode(plainValue))
  }

  public getTokenCookie = (token: string): Cookie => {
    return this.cookieBuilder.createCookie(token)
  }

  public getBlankCookie = (): Cookie => {
    return this.cookieBuilder.createBlankCookie()
  }
}

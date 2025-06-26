const encoder = new TextEncoder()

const base64UrlEncode = (data: Uint8Array): string =>
  btoa(String.fromCharCode(...data))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')

const base64UrlDecode = (str: string): Uint8Array =>
  Uint8Array.from(
    atob(
      str.replace(/-/g, '+').replace(/_/g, '/') +
        '='.repeat((4 - (str.length % 4)) % 4)
    ),
    c => c.charCodeAt(0)
  )

export const generateToken = async (
  secret: string,
  length: number = 32
): Promise<string> => {
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  )
  const plainData = crypto.getRandomValues(new Uint8Array(length))
  const signedData = new Uint8Array(
    await crypto.subtle.sign('HMAC', key, plainData)
  )
  return [base64UrlEncode(plainData), base64UrlEncode(signedData)].join('.')
}

export const verifyToken = async (
  secret: string,
  token: string
): Promise<boolean> => {
  const tokenParts = token.split('.')
  if (tokenParts.length !== 2) return false
  const [plainStr, signedStr] = tokenParts
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify']
  )
  return await crypto.subtle.verify(
    'HMAC',
    key,
    base64UrlDecode(signedStr),
    base64UrlDecode(plainStr)
  )
}

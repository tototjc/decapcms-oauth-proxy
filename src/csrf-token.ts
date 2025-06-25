const encoder = new TextEncoder()
const decoder = new TextDecoder()

const base64UrlEncode = (data: ArrayBuffer | ArrayBufferView): string =>
  btoa(decoder.decode(data))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')

const base64UrlDecode = (str: string): ArrayBufferView =>
  encoder.encode(
    atob(
      str.replace(/-/g, '+').replace(/_/g, '/') +
        '='.repeat((4 - (str.length % 4)) % 4)
    )
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
  const signData = await crypto.subtle.sign('HMAC', key, plainData)
  return [base64UrlEncode(signData), base64UrlEncode(plainData)].join('.')
}

export const verifyToken = async (
  secret: string,
  token: string
): Promise<boolean> => {
  const tokenParts = token.split('.')
  if (tokenParts.length !== 2) return false
  const [signStr, plainStr] = tokenParts
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
    base64UrlDecode(signStr),
    base64UrlDecode(plainStr)
  )
}

// GH #102 positive controls (JS): uppercase keys, Object.freeze wrappers and
// E_*-shaped values do not exempt real credential material or literal fallbacks
// for secret-bearing environment variables. Values are synthetic.
const SECRETS = Object.freeze({ API_KEY: 'sk_live_4f8a2b91cd77e530' }); // expect: secret

export const CREDENTIALS = Object.freeze({ password: 'Hunter2-Hunter2-Hunter2' }); // expect: secret

const SESSION_SECRET = 'SESSION_SECRET_9f3a7c1e2b4d'; // expect: secret

export const jwtSecret = process.env.JWT_SECRET || 'E_JWT_SECRET'; // expect: secret

export function signingKey() {
  return process.env.SIGNING_SECRET ?? 'ERR_SIGNING_SECRET_UNSET'; // expect: secret
}

export { SECRETS, SESSION_SECRET };

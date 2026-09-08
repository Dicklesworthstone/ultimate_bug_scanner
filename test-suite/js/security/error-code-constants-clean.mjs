// GH #102 regression fixture (JS): public diagnostic identifiers used as error
// messages are not credential material, whatever the key is called and however
// the dictionary is wrapped. Real credentials are read from the environment
// (see hardcoded-secrets-clean.ts); nothing here may be reported as
// "Possible hardcoded secrets".
const CODES = Object.freeze({ CREDENTIALS: 'E_CREDENTIALS' });

export const AUTH_ERRORS = Object.freeze({
  INVALID_PASSWORD: 'AUTH_INVALID_PASSWORD',
  TOKEN_EXPIRED: 'ERR-TOKEN-EXPIRED-401',
  MISSING_API_KEY: 'E_MISSING_API_KEY',
});

export const SECRET_STATE = { secretStatus: 'SECRET_NOT_LOADED' };

let apiKeyState = 'API_KEY_MISSING';

export function requireCredentials(env) {
  if (!env.SERVICE_PASSWORD) {
    throw new Error(CODES.CREDENTIALS);
  }
  apiKeyState = 'API_KEY_PRESENT';
  return { password: env.SERVICE_PASSWORD, state: apiKeyState };
}

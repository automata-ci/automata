import {registeredSecrets} from './core.js'
import {OidcClient} from './oidc-utils.js'

const audience = process.env['OIDC_TEST_AUDIENCE']
const token = await OidcClient.getIDToken(audience)
if (registeredSecrets.length !== 1 || registeredSecrets[0] !== token) {
  throw new Error('OIDC client did not register the returned token as a secret')
}
process.stdout.write(token)

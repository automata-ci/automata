const fixtureRoot = new URL('./', import.meta.url)

export async function resolve(specifier, context, nextResolve) {
  if (specifier === '@actions/http-client') {
    return {url: new URL('http-client.js', fixtureRoot).href, shortCircuit: true}
  }
  if (specifier === '@actions/http-client/lib/auth') {
    return {url: new URL('http-auth.js', fixtureRoot).href, shortCircuit: true}
  }
  return nextResolve(specifier, context)
}

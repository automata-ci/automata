import { pathToFileURL } from 'node:url'
import { readFile, rm } from 'node:fs/promises'

const modulePath = process.env.AUTOMATA_TEST_ACTIONS_CACHE_MODULE
const inputPath = process.env.AUTOMATA_TEST_CACHE_INPUT

if (!modulePath || !inputPath) {
  throw new Error('official cache-v2 client fixture environment is incomplete')
}
if (process.env.ACTIONS_CACHE_SERVICE_V2 !== 'true') {
  throw new Error('cache-v2 service marker is not enabled')
}

const moduleUrl = pathToFileURL(modulePath)
const packageManifest = JSON.parse(
  await readFile(new URL('../package.json', moduleUrl), 'utf8'),
)
if (
  packageManifest.name !== '@actions/cache' ||
  packageManifest.version !== '5.0.5'
) {
  throw new Error(
    `expected exact @actions/cache 5.0.5, received ${packageManifest.name}@${packageManifest.version}`,
  )
}

const cache = await import(moduleUrl.href)
const original = await readFile(inputPath)
const key = 'official-actions-cache-v5-0-5'
const saved = await cache.saveCache([inputPath], key)
if (!saved) {
  throw new Error(`official cache client returned an invalid entry ID: ${saved}`)
}

await rm(inputPath)
const exact = await cache.restoreCache([inputPath], key)
if (exact !== key) {
  throw new Error(`official cache client missed the exact key: ${exact}`)
}
const exactRestored = await readFile(inputPath)
if (!exactRestored.equals(original)) {
  throw new Error('official cache-v2 exact restore changed the saved bytes')
}

await rm(inputPath)
const matched = await cache.restoreCache([inputPath], 'missing-primary', [
  'official-actions-cache-',
])
if (matched !== key) {
  throw new Error(`official cache client matched the wrong key: ${matched}`)
}
const restored = await readFile(inputPath)
if (!restored.equals(original)) {
  throw new Error('official cache-v2 restore did not reproduce the saved bytes')
}

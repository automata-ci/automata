import { pathToFileURL } from 'node:url'
import { mkdir, readFile } from 'node:fs/promises'
import { basename, join } from 'node:path'

const modulePath = process.env.AUTOMATA_TEST_ACTIONS_ARTIFACT_MODULE
const expectedVersion = process.env.AUTOMATA_TEST_ACTIONS_ARTIFACT_VERSION
const inputPath = process.env.AUTOMATA_TEST_ARTIFACT_INPUT
const rootDirectory = process.env.AUTOMATA_TEST_ARTIFACT_ROOT

if (!modulePath || !expectedVersion || !inputPath || !rootDirectory) {
  throw new Error('official artifact-client fixture environment is incomplete')
}

const moduleUrl = pathToFileURL(modulePath)
const packageManifest = JSON.parse(
  await readFile(new URL('../../package.json', moduleUrl), 'utf8'),
)
if (
  packageManifest.name !== '@actions/artifact' ||
  packageManifest.version !== expectedVersion
) {
  throw new Error(
    `expected exact @actions/artifact ${expectedVersion}, received ${packageManifest.name}@${packageManifest.version}`,
  )
}

const { DefaultArtifactClient } = await import(moduleUrl.href)
const client = new DefaultArtifactClient()
const result = await client.uploadArtifact(
  'official-actions-artifact-client',
  [inputPath],
  rootDirectory,
  { compressionLevel: 6 },
)

if (!result.id || !result.digest || !result.size) {
  throw new Error(`official client returned an incomplete result: ${JSON.stringify(result)}`)
}

const listed = await client.listArtifacts()
const artifact = listed.artifacts.find(candidate => candidate.id === result.id)
const expectedListedDigest = `sha256:${result.digest}`
if (!artifact || artifact.digest !== expectedListedDigest || artifact.size !== result.size) {
  throw new Error(`official client list result did not match upload: ${JSON.stringify(listed)}`)
}

const found = await client.getArtifact('official-actions-artifact-client')
if (found.artifact.id !== result.id || found.artifact.digest !== expectedListedDigest) {
  throw new Error(`official client get result did not match upload: ${JSON.stringify(found)}`)
}

const downloadRoot = join(rootDirectory, 'downloaded')
await mkdir(downloadRoot, { recursive: true })
const downloaded = await client.downloadArtifact(result.id, {
  path: downloadRoot,
  expectedHash: expectedListedDigest,
})
if (downloaded.digestMismatch) {
  throw new Error('official client reported a download digest mismatch')
}

const originalBytes = await readFile(inputPath)
const downloadedBytes = await readFile(join(downloadRoot, basename(inputPath)))
if (!downloadedBytes.equals(originalBytes)) {
  throw new Error('official client download did not reproduce the uploaded file')
}

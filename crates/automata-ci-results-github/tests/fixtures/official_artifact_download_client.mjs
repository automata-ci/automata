import { mkdir, readFile } from 'node:fs/promises'
import { basename, join } from 'node:path'
import { pathToFileURL } from 'node:url'

const modulePath = process.env.AUTOMATA_TEST_ACTIONS_ARTIFACT_MODULE
const expectedVersion = process.env.AUTOMATA_TEST_ACTIONS_ARTIFACT_VERSION
const inputPath = process.env.AUTOMATA_TEST_ARTIFACT_INPUT
const rootDirectory = process.env.AUTOMATA_TEST_ARTIFACT_ROOT

if (!modulePath || !expectedVersion || !inputPath || !rootDirectory) {
  throw new Error('official artifact-download fixture environment is incomplete')
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
const listed = await client.listArtifacts()
const artifact = listed.artifacts.find(
  candidate => candidate.name === 'official-actions-artifact-client',
)
if (!artifact?.digest) {
  throw new Error('official download client did not list the uploaded artifact')
}

const found = await client.getArtifact('official-actions-artifact-client')
if (found.artifact.id !== artifact.id || found.artifact.digest !== artifact.digest) {
  throw new Error('official download client resolved inconsistent artifact metadata')
}

const downloadRoot = join(rootDirectory, 'downloaded-by-download-action-client')
await mkdir(downloadRoot, { recursive: true })
const downloaded = await client.downloadArtifact(artifact.id, {
  path: downloadRoot,
  expectedHash: artifact.digest,
})
if (downloaded.digestMismatch) {
  throw new Error('official download client reported a digest mismatch')
}

const originalBytes = await readFile(inputPath)
const downloadedBytes = await readFile(join(downloadRoot, basename(inputPath)))
if (!downloadedBytes.equals(originalBytes)) {
  throw new Error('official download client changed the uploaded file')
}

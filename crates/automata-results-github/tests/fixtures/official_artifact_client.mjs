import { pathToFileURL } from 'node:url'

const modulePath = process.env.AUTOMATA_TEST_ACTIONS_ARTIFACT_MODULE
const inputPath = process.env.AUTOMATA_TEST_ARTIFACT_INPUT
const rootDirectory = process.env.AUTOMATA_TEST_ARTIFACT_ROOT

if (!modulePath || !inputPath || !rootDirectory) {
  throw new Error('official artifact-client fixture environment is incomplete')
}

const { DefaultArtifactClient } = await import(pathToFileURL(modulePath).href)
const result = await new DefaultArtifactClient().uploadArtifact(
  'official-actions-artifact-client',
  [inputPath],
  rootDirectory,
  { compressionLevel: 6 },
)

if (!result.id || !result.digest || !result.size) {
  throw new Error(`official client returned an incomplete result: ${JSON.stringify(result)}`)
}

import rendererContract from "../../../crates/automata-ci-ui-renderer/contract.json";

/** Maximum wire size of serialized render requests, measured as UTF-8 bytes. */
export const MAX_SERIALIZED_RENDER_REQUEST_BYTES = rendererContract.maxRequestUtf8Bytes;

/** Return the exact UTF-8 wire size without allocating an encoded copy. */
export function utf8ByteLength(value: string): number {
  let bytes = 0;
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit <= 0x7f) {
      bytes += 1;
    } else if (codeUnit <= 0x7ff) {
      bytes += 2;
    } else if (
      codeUnit >= 0xd800 &&
      codeUnit <= 0xdbff &&
      index + 1 < value.length &&
      value.charCodeAt(index + 1) >= 0xdc00 &&
      value.charCodeAt(index + 1) <= 0xdfff
    ) {
      bytes += 4;
      index += 1;
    } else {
      // BMP code points and unpaired surrogates (encoded as U+FFFD) use three bytes.
      bytes += 3;
    }
  }
  return bytes;
}

export const RENDER_REQUEST_LIMITS = {
  artifactCount: 500,
  bindingCount: 500,
  idLength: 256,
  jobCount: 200,
  logLineCount: 10_000,
  logLineTextLength: 65_536,
  longTextLength: 4_096,
  navigationCount: 32,
  permissionCount: 500,
  repositoryCount: 25,
  runnerCount: 500,
  roleCount: 500,
  runCount: 250,
  secretCount: 50,
  shortTextLength: 1_024,
  stylesheetCount: 32,
  userCount: 500,
  workflowCount: 250,
} as const;

const SAME_ORIGIN_BASE = "https://automata.invalid/current/page";
const FORBIDDEN_RAW_URL_CHARACTER = /[\u0000-\u0020\u007f\\]/u;
const NON_ASCII_CHARACTER = /[^\x21-\x7e]/u;
const GITHUB_REPOSITORY_OWNER =
  /^(?=.{1,39}$)(?!.*--)[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/u;
const GITHUB_REPOSITORY_NAME = /^(?=.{1,100}$)[A-Za-z0-9._-]+$/u;
const GITHUB_COMMIT_OBJECT_ID = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/u;
const GITHUB_SHORT_COMMIT_ID = /^[a-f0-9]{4,64}$/u;
const POSITIVE_U64 = /^[1-9][0-9]{0,19}$/u;

const GITHUB_ORIGIN = "https://github.com";
const MAX_U64_DECIMAL = "18446744073709551615";

// Accommodates a 1,024-byte UTF-8 filter after worst-case percent encoding,
// its bounded cursor, and the longest canonical Automata route prefix.
export const MAX_ROUTE_PATH_LENGTH = 4_096;
const MAX_ASSET_PATH_LENGTH = 1_024;
// Git refs use the same 1,024-byte durable bound and can expand threefold.
export const MAX_GITHUB_SCM_URL_LENGTH = 4_096;

export type AssetKind = "client-script" | "stylesheet";

export type GitHubScmTarget =
  | { readonly kind: "repository" }
  | { readonly kind: "commit"; readonly shortSha: string }
  | { readonly kind: "tree"; readonly refName: string }
  | { readonly kind: "pull"; readonly pullNumber: string };

/**
 * Routes may be rooted paths or query/fragment references to the current page.
 * Scheme-relative paths, schemes, backslashes, whitespace, and controls are
 * rejected before the browser gets a chance to normalize them.
 */
export function isSafeSameOriginRoutePath(value: string): boolean {
  if (
    value.length === 0 ||
    value.length > MAX_ROUTE_PATH_LENGTH ||
    FORBIDDEN_RAW_URL_CHARACTER.test(value) ||
    NON_ASCII_CHARACTER.test(value) ||
    !hasCanonicalPercentEscapes(value)
  ) {
    return false;
  }

  const hasSafePrefix =
    (value.startsWith("/") && !value.startsWith("//")) ||
    value.startsWith("?") ||
    value.startsWith("#");
  if (!hasSafePrefix) {
    return false;
  }

  try {
    const url = new URL(value, SAME_ORIGIN_BASE);
    if (url.origin !== new URL(SAME_ORIGIN_BASE).origin) {
      return false;
    }
    const canonicalReference = value.startsWith("/")
      ? `${url.pathname}${url.search}${url.hash}`
      : value.startsWith("?")
        ? `${url.search}${url.hash}`
        : url.hash;
    return canonicalReference === value;
  } catch {
    return false;
  }
}

function hasCanonicalPercentEscapes(value: string): boolean {
  for (let index = value.indexOf("%"); index !== -1; index = value.indexOf("%", index + 3)) {
    if (!/^[0-9A-F]{2}$/u.test(value.slice(index + 1, index + 3))) {
      return false;
    }
  }
  return true;
}

/** Assets are rooted, same-origin, fragment-free paths of the expected type. */
export function isSafeSameOriginAssetPath(value: string, kind: AssetKind): boolean {
  if (
    value.length === 0 ||
    value.length > MAX_ASSET_PATH_LENGTH ||
    !value.startsWith("/") ||
    !isSafeSameOriginRoutePath(value)
  ) {
    return false;
  }

  if (value.includes("#")) {
    return false;
  }

  const url = new URL(value, SAME_ORIGIN_BASE);
  const pathname = url.pathname.toLowerCase();
  return kind === "client-script"
    ? pathname.endsWith(".js") || pathname.endsWith(".mjs")
    : pathname.endsWith(".css");
}

/**
 * Accepts only canonical links on github.com for one explicitly named
 * repository and one explicitly named SCM target. String equality is
 * intentional: it rejects URL-parser aliases such as credentials, default
 * ports, dot segments, encoded repository separators, and trailing metadata.
 */
export function isSafeGitHubScmUrl(
  value: string,
  repositoryOwner: string,
  repositoryName: string,
  target: GitHubScmTarget,
): boolean {
  if (
    value.length === 0 ||
    value.length > MAX_GITHUB_SCM_URL_LENGTH ||
    !GITHUB_REPOSITORY_OWNER.test(repositoryOwner) ||
    !GITHUB_REPOSITORY_NAME.test(repositoryName) ||
    repositoryName === "." ||
    repositoryName === ".."
  ) {
    return false;
  }

  const repositoryUrl = `${GITHUB_ORIGIN}/${repositoryOwner}/${repositoryName}`;
  switch (target.kind) {
    case "repository":
      return value === repositoryUrl;
    case "commit": {
      if (!GITHUB_SHORT_COMMIT_ID.test(target.shortSha)) {
        return false;
      }
      const prefix = `${repositoryUrl}/commit/`;
      if (!value.startsWith(prefix)) {
        return false;
      }
      const objectId = value.slice(prefix.length);
      return (
        GITHUB_COMMIT_OBJECT_ID.test(objectId) &&
        objectId.startsWith(target.shortSha)
      );
    }
    case "tree": {
      if (
        target.refName.length === 0 ||
        target.refName === "." ||
        target.refName === ".."
      ) {
        return false;
      }
      const encodedRefName = encodeSpecialUrlPathSegment(target.refName);
      if (encodedRefName === null) {
        return false;
      }
      return value === `${repositoryUrl}/tree/${encodedRefName}`;
    }
    case "pull":
      return (
        isPositiveU64(target.pullNumber) &&
        value === `${repositoryUrl}/pull/${target.pullNumber}`
      );
  }
}

function isPositiveU64(value: string): boolean {
  return (
    POSITIVE_U64.test(value) &&
    (value.length < MAX_U64_DECIMAL.length || value <= MAX_U64_DECIMAL)
  );
}

/** Matches `url::Url::path_segments_mut().push` for an HTTPS URL. */
function encodeSpecialUrlPathSegment(value: string): string | null {
  let encoded = "";
  for (let index = 0; index < value.length; index += 1) {
    const first = value.charCodeAt(index);
    let codePoint = first;
    if (first >= 0xd800 && first <= 0xdbff) {
      if (index + 1 >= value.length) {
        return null;
      }
      const second = value.charCodeAt(index + 1);
      if (second < 0xdc00 || second > 0xdfff) {
        return null;
      }
      codePoint = 0x10000 + ((first - 0xd800) << 10) + (second - 0xdc00);
      index += 1;
    } else if (first >= 0xdc00 && first <= 0xdfff) {
      return null;
    }

    if (codePoint <= 0x7f) {
      encoded += encodeSpecialUrlPathByte(codePoint);
    } else if (codePoint <= 0x7ff) {
      encoded += encodeSpecialUrlPathByte(0xc0 | (codePoint >> 6));
      encoded += encodeSpecialUrlPathByte(0x80 | (codePoint & 0x3f));
    } else if (codePoint <= 0xffff) {
      encoded += encodeSpecialUrlPathByte(0xe0 | (codePoint >> 12));
      encoded += encodeSpecialUrlPathByte(0x80 | ((codePoint >> 6) & 0x3f));
      encoded += encodeSpecialUrlPathByte(0x80 | (codePoint & 0x3f));
    } else {
      encoded += encodeSpecialUrlPathByte(0xf0 | (codePoint >> 18));
      encoded += encodeSpecialUrlPathByte(0x80 | ((codePoint >> 12) & 0x3f));
      encoded += encodeSpecialUrlPathByte(0x80 | ((codePoint >> 6) & 0x3f));
      encoded += encodeSpecialUrlPathByte(0x80 | (codePoint & 0x3f));
    }
  }
  return encoded;
}

function encodeSpecialUrlPathByte(byte: number): string {
  return mustEncodeInSpecialUrlPathSegment(byte)
    ? `%${byte.toString(16).toUpperCase().padStart(2, "0")}`
    : String.fromCharCode(byte);
}

function mustEncodeInSpecialUrlPathSegment(byte: number): boolean {
  return (
    byte <= 0x20 ||
    byte >= 0x7f ||
    byte === 0x22 ||
    byte === 0x23 ||
    byte === 0x25 ||
    byte === 0x2f ||
    byte === 0x3c ||
    byte === 0x3e ||
    byte === 0x3f ||
    byte === 0x5c ||
    byte === 0x60 ||
    byte === 0x7b ||
    byte === 0x7d
  );
}

const SAME_ORIGIN_BASE = "https://automata.invalid/current/page";
const FORBIDDEN_RAW_URL_CHARACTER = /[\u0000-\u0020\u007f\\]/u;

export const MAX_ROUTE_PATH_LENGTH = 2_048;
export const MAX_ASSET_PATH_LENGTH = 1_024;

export type AssetKind = "client-script" | "stylesheet";

/**
 * Routes may be rooted paths or query/fragment references to the current page.
 * Scheme-relative paths, schemes, backslashes, whitespace, and controls are
 * rejected before the browser gets a chance to normalize them.
 */
export function isSafeSameOriginRoutePath(value: string): boolean {
  if (
    value.length === 0 ||
    value.length > MAX_ROUTE_PATH_LENGTH ||
    FORBIDDEN_RAW_URL_CHARACTER.test(value)
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
    return new URL(value, SAME_ORIGIN_BASE).origin === new URL(SAME_ORIGIN_BASE).origin;
  } catch {
    return false;
  }
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

  const url = new URL(value, SAME_ORIGIN_BASE);
  if (url.hash.length !== 0) {
    return false;
  }

  const pathname = url.pathname.toLowerCase();
  return kind === "client-script"
    ? pathname.endsWith(".js") || pathname.endsWith(".mjs")
    : pathname.endsWith(".css");
}

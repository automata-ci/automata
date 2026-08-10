const QUERY_UNRESERVED_BYTE = /^[A-Za-z0-9._~-]$/u;

/** RFC 3986 query-component encoding used by the Rust render host. */
export function encodeQueryComponent(value: string): string {
  let encoded = "";
  for (const byte of new TextEncoder().encode(value)) {
    const character = String.fromCharCode(byte);
    encoded += QUERY_UNRESERVED_BYTE.test(character)
      ? character
      : `%${byte.toString(16).toUpperCase().padStart(2, "0")}`;
  }
  return encoded;
}

// Unicode 17.0.0 Default_Ignorable_Code_Point, kept explicit so behavior is
// stable across JavaScript engines with different Unicode tables.
const DEFAULT_IGNORABLE_CODE_POINT =
  /^[\u00ad\u034f\u061c\u115f-\u1160\u17b4-\u17b5\u180b-\u180f\u200b-\u200f\u202a-\u202e\u2060-\u206f\u3164\ufe00-\ufe0f\ufeff\uffa0\ufff0-\ufff8\u{1bca0}-\u{1bca3}\u{1d173}-\u{1d17a}\u{e0000}-\u{e0fff}]$/u;
const WHITESPACE_CODE_POINT = /^\s$/u;
const FORBIDDEN_DISPLAY_CHARACTER =
  /[\u0000-\u001f\u007f-\u009f\u061c\u200e-\u200f\u202a-\u202e\u2066-\u2069]/u;

export function isVisibleDisplayCodePoint(codePoint: string): boolean {
  return (
    !WHITESPACE_CODE_POINT.test(codePoint) &&
    !DEFAULT_IGNORABLE_CODE_POINT.test(codePoint)
  );
}

export function hasVisibleDisplayCharacter(value: string): boolean {
  return Array.from(value).some(isVisibleDisplayCodePoint);
}

export function hasForbiddenDisplayCharacter(value: string): boolean {
  return FORBIDDEN_DISPLAY_CHARACTER.test(value);
}

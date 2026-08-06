import type { AssetKind } from "../safeUrls";
import {
  isSafeSameOriginAssetPath,
  isSafeSameOriginRoutePath,
} from "../safeUrls";
import { RENDER_REQUEST_LIMITS } from "./limits";

export type JsonRecord = Record<string, unknown>;

export function expectObject(
  value: unknown,
  path: string,
  requiredKeys: readonly string[],
  optionalKeys: readonly string[] = [],
): JsonRecord {
  const record = expectRecord(value, path);
  const allowed = new Set([...requiredKeys, ...optionalKeys]);
  for (const key of Reflect.ownKeys(record)) {
    if (typeof key !== "string") {
      invalid(path, "an object with string data fields only");
    }
    const descriptor = Object.getOwnPropertyDescriptor(record, key);
    if (descriptor === undefined || !descriptor.enumerable || !("value" in descriptor)) {
      invalid(`${path}.${key}`, "an enumerable data field");
    }
    if (!allowed.has(key)) {
      invalid(`${path}.${key}`, "no unknown field");
    }
  }
  for (const key of requiredKeys) {
    if (!hasOwn(record, key)) {
      invalid(`${path}.${key}`, "a required field");
    }
  }
  return record;
}

export function expectRecord(value: unknown, path: string): JsonRecord {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    invalid(path, "an object");
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    invalid(path, "a plain object");
  }
  return value as JsonRecord;
}

export function expectArray(
  value: unknown,
  path: string,
  maximumLength: number,
): readonly unknown[] {
  if (!Array.isArray(value)) {
    invalid(path, "an array");
  }
  if (Object.getPrototypeOf(value) !== Array.prototype) {
    invalid(path, "a plain array");
  }
  if (value.length > maximumLength) {
    invalid(path, `an array with at most ${maximumLength} items`);
  }
  for (let index = 0; index < value.length; index += 1) {
    if (!Object.prototype.hasOwnProperty.call(value, index)) {
      invalid(`${path}[${index}]`, "a present array item");
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (descriptor === undefined || !("value" in descriptor)) {
      invalid(`${path}[${index}]`, "an array data item");
    }
  }
  for (const key of Reflect.ownKeys(value)) {
    if (key === "length") {
      continue;
    }
    if (typeof key !== "string" || !/^(?:0|[1-9]\d*)$/u.test(key)) {
      invalid(path, "an array without custom fields");
    }
  }
  return value;
}

export function expectTextField(
  record: JsonRecord,
  key: string,
  parentPath: string,
  maximumLength: number = RENDER_REQUEST_LIMITS.shortTextLength,
): string {
  return expectString(record[key], `${parentPath}.${key}`, maximumLength);
}

export function expectIdField(
  record: JsonRecord,
  key: string,
  parentPath: string,
): string {
  return expectString(
    record[key],
    `${parentPath}.${key}`,
    RENDER_REQUEST_LIMITS.idLength,
    1,
  );
}

export function expectString(
  value: unknown,
  path: string,
  maximumLength: number,
  minimumLength = 0,
): string {
  if (
    typeof value !== "string" ||
    value.length < minimumLength ||
    value.length > maximumLength
  ) {
    invalid(path, `a string between ${minimumLength} and ${maximumLength} characters`);
  }
  return value;
}

export function expectRouteField(
  record: JsonRecord,
  key: string,
  parentPath: string,
): string {
  return expectRoute(record[key], `${parentPath}.${key}`);
}

export function expectNullableRoute(value: unknown, path: string): void {
  if (value !== null) {
    expectRoute(value, path);
  }
}

export function expectAssetPath(
  value: unknown,
  path: string,
  kind: AssetKind,
): string {
  if (typeof value !== "string" || !isSafeSameOriginAssetPath(value, kind)) {
    invalid(path, `a safe same-origin ${kind} path`);
  }
  return value;
}

export function expectBoolean(value: unknown, path: string): void {
  if (typeof value !== "boolean") {
    invalid(path, "a boolean");
  }
}

export function expectInteger(
  value: unknown,
  path: string,
  minimum: number,
  maximum: number,
): number {
  if (!Number.isInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    invalid(path, `an integer between ${minimum} and ${maximum}`);
  }
  return value as number;
}

export function expectLiteral(
  value: unknown,
  path: string,
  expected: string | number,
): void {
  if (value !== expected) {
    invalid(path, JSON.stringify(expected));
  }
}

export function expectOneOf(
  value: unknown,
  path: string,
  allowed: readonly string[],
): void {
  if (typeof value !== "string" || !allowed.includes(value)) {
    invalid(path, allowed.map((item) => JSON.stringify(item)).join(", "));
  }
}

export function expectUnique<T>(seen: Set<T>, value: T, path: string): void {
  if (seen.has(value)) {
    invalid(path, "a unique value");
  }
  seen.add(value);
}

export function field(record: JsonRecord, key: string, parentPath: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(record, key);
  if (descriptor === undefined) {
    invalid(`${parentPath}.${key}`, "a required field");
  }
  if (!descriptor.enumerable || !("value" in descriptor)) {
    invalid(`${parentPath}.${key}`, "an enumerable data field");
  }
  return descriptor.value;
}

export function hasOwn(record: JsonRecord, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(record, key);
}

export function invalid(path: string, expectation: string): never {
  throw new Error(`Invalid Automata render request at ${path}: expected ${expectation}`);
}

function expectRoute(value: unknown, path: string): string {
  if (typeof value !== "string" || !isSafeSameOriginRoutePath(value)) {
    invalid(path, "a safe same-origin route path");
  }
  return value;
}

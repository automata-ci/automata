import assert from "node:assert/strict";
import test from "node:test";
import {
  normalizeCycloneDx,
  serializeCanonicalJson,
} from "../lib/cyclonedx.mjs";

const SHA256 = "a".repeat(64);

function fixture() {
  return {
    specVersion: "1.5",
    serialNumber: "urn:uuid:nondeterministic",
    metadata: {
      component: {
        name: "automata",
        "bom-ref": "path+file:///work/automata/crates/automata#0.1.0",
        type: "application",
      },
      timestamp: "2026-01-02T03:04:05Z",
    },
    bomFormat: "CycloneDX",
    dependencies: [
      { ref: "path+file:///work/automata/crates/automata#0.1.0" },
    ],
  };
}

test("normalization removes nondeterminism and binds the component", () => {
  const normalized = normalizeCycloneDx(fixture(), {
    repositoryRoot: "/work/automata",
    sourceDateEpoch: 0,
    componentSha256: SHA256,
  });

  assert.equal(normalized.serialNumber, undefined);
  assert.equal(normalized.metadata.timestamp, "1970-01-01T00:00:00.000Z");
  assert.deepEqual(normalized.metadata.component.hashes, [
    { alg: "SHA-256", content: SHA256 },
  ]);
  assert.match(
    normalized.metadata.component["bom-ref"],
    /^path\+file:\/\/\/workspace\//,
  );
  assert.doesNotMatch(serializeCanonicalJson(normalized), /\/work\/automata/);
});

test("canonical serialization is independent of object insertion order", () => {
  assert.equal(
    serializeCanonicalJson({ z: 1, nested: { b: 2, a: 1 }, a: 0 }),
    serializeCanonicalJson({ a: 0, nested: { a: 1, b: 2 }, z: 1 }),
  );
});

test("normalization rejects invalid input and noncanonical local paths", () => {
  assert.throws(
    () =>
      normalizeCycloneDx(
        {
          ...fixture(),
          components: [
            { "bom-ref": "path+file:///another/checkout/crate#1.0.0" },
          ],
        },
        { repositoryRoot: "/work/automata", sourceDateEpoch: 0 },
      ),
    /non-canonical local package reference/,
  );
  assert.throws(
    () =>
      normalizeCycloneDx(fixture(), {
        repositoryRoot: "/work/automata",
        sourceDateEpoch: -1,
      }),
    /SOURCE_DATE_EPOCH/,
  );
  assert.throws(
    () =>
      normalizeCycloneDx(fixture(), {
        repositoryRoot: "/work/automata",
        sourceDateEpoch: 0,
        componentSha256: "ABC",
      }),
    /component SHA-256/,
  );
});

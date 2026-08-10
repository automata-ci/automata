# Published RSA test fixture

The two DER files in this directory are deliberately public test material, not
credentials or secrets. They are two encodings of the same 2048-bit RSA key and
must never be configured for a GitHub App or any other real identity:

- `rsa2048-test-key.pkcs1.der` is an RFC 8017 PKCS#1 `RSAPrivateKey`.
- `rsa2048-test-key.pkcs8.der` is an RFC 5958 PKCS#8 `PrivateKeyInfo`.

The test harness wraps these bytes in the corresponding RFC 7468 labels only at
runtime. Keeping the published fixture as binary DER prevents a repository
scanner from mistaking an intentionally public test vector for a deployable PEM
credential while preserving coverage of both accepted PEM encodings.

The checked-in byte-level identities are:

```text
f94b60300e4877e863b2bea8d5c366a90432794454c05e0ec098ddbf96263614  rsa2048-test-key.pkcs1.der
ea7fe20f854f4fb908c12f1344e6cffbb83f367bbd8bfebca20687402394266f  rsa2048-test-key.pkcs8.der
```

Both encodings produce this SHA-256 fingerprint for the DER SubjectPublicKeyInfo:

```text
efeda9bfead9fd0594f6a5cf6fdf6c163116a3b1fad6d73cea05295b68fd1794
```

To rotate the fixture, generate one key under the ignored
`target/agent-scratch/` hierarchy, export that same key as PKCS#1 and PKCS#8
DER, update the hashes above, and update the deterministic JWT digest asserted
by `tests/jwt_contract.rs`.

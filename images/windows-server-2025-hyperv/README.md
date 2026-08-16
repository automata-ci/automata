# Windows Server 2025 Hyper-V runner image

This directory contains the production-shaped recipe and promotion tooling for
`automata.dev/windows-2025-x64-hyperv-v1`. It does not contain a published
image, a signing key, a signed promotion envelope, or physical-host acceptance
evidence.

The recipe starts from one architecture-specific Server Core 2025 manifest
digest. `sources.lock.json` pins the official PowerShell 7.6.5, Git for Windows
GNU tar 1.35, and Node.js 24.19.0 archives by HTTPS URL and SHA-256. The build
context preparer downloads or accepts those exact archives, verifies them
before copying, and the in-image installer verifies them again before
extraction. Mutable base tags, placeholder digests, unreviewed redirects, and
changed local executables fail closed.

The guest agent and `automata-sha256` are repository-owned binaries. Build them
twice from an exact commit and require byte-identical outputs:

```powershell
images\windows-server-2025-hyperv\build-local-artifacts.ps1 `
  -SourceCommit <full-40-character-commit> `
  -OutputDirectory target\windows-image-tools
```

Then build an unpublished local candidate. Every local binary digest is an
explicit argument; the command never pushes or logs in to a registry.

```powershell
images\windows-server-2025-hyperv\build-candidate.ps1 `
  -GuestAgent target\windows-image-tools\automata-ci-sandbox-guest.exe `
  -GuestAgentSha256 <sha256> `
  -HashHelper target\windows-image-tools\automata-sha256.exe `
  -HashHelperSha256 <sha256> `
  -SourceCommit <full-40-character-commit> `
  -LocalTag automata/windows-runner:windows-2025-candidate
```

The local image ID is not a registry identity. A separately authorized
operator must publish without a mutable release tag, retain the returned
registry digest, pull that exact `@sha256` identity, and run the Hyper-V,
network-none, ContainerUser qualification collector on a compatible dedicated
Windows Server 2025 host:

```powershell
images\windows-server-2025-hyperv\collect-qualification.ps1 `
  -Image ghcr.io/automata-ci/windows-runner@sha256:<digest> `
  -Output target\windows-image-qualification.json
```

`windows-image-pipeline.py assemble` consumes that qualification, the retained
build-input lock, an exact source commit, an independently selected promotion
serial, and a fresh revocation generation/window. It emits canonical in-toto
provenance, SPDX 2.3 inventory, patch/tool evidence, revocation evidence, the
runner manifest/lock, and the exact compact schema-v2 promotion payload. The
command refuses every `candidate_fixture` field, mutable or placeholder image,
zero serial/generation, stale revocation window, revoked target image, unknown
field, or mismatched digest.

```powershell
python scripts\ci\windows-image-pipeline.py assemble `
  --lock images\windows-server-2025-hyperv\sources.lock.json `
  --build-inputs target\windows-server-2025-image\<commit>.build-inputs.json `
  --qualification target\windows-image-qualification.json `
  --revocations C:\ProgramData\Automata\promotion\revocations.input.json `
  --image ghcr.io/automata-ci/windows-runner@sha256:<digest> `
  --source-commit <commit> `
  --builder-id https://builders.automata.dev/windows-hyperv/v1 `
  --issued-at-unix-millis <millis> `
  --expires-at-unix-millis <millis> `
  --promotion-serial <positive-monotonic-serial> `
  --revocation-generation <positive-monotonic-generation> `
  --output target\windows-image-promotion
```

Assembly is not promotion. Signing is delegated to an externally provisioned,
digest-pinned signer and an opaque approved-key handle; private key bytes never
enter this repository, command line, payload, or output bundle.

```powershell
python scripts\ci\windows-image-pipeline.py sign `
  --bundle target\windows-image-promotion `
  --key-id <broker-control-approved-key-id> `
  --key-handle <opaque-external-key-handle> `
  --signer C:\Program Files\Automata\bin\automata-image-signer.exe `
  --signer-sha256 <reviewed-signer-sha256> `
  --output target\windows-image-promotion\promotion.envelope.json
```

The canonical broker independently reads the host files, resolves the key ID
through its administrator/control-owned versioned trust bundle, verifies the
signature and exact profile/image/host inputs, and enforces durable
per-key/profile promotion-serial and revocation-generation high-water marks.
Runner-local parsing is only a fail-fast check and cannot authorize action or
Node capabilities. No action capability is registered unless control verifies
the broker-signed admission receipt and that receipt attests the sealed-action
graph materialization profile.

The hermetic pipeline contract runs in both protected-main and pull-request CI:

```text
python3 scripts/ci/tests/windows-image-pipeline.test.py
```

That contract does not build, publish, qualify, or sign an image.

Actual image publication, external signing, registry verification, dedicated
Hyper-V-host compatibility, broker admission, hostile testing, patch review,
and operational promotion remain external acceptance evidence. The checked-in
`windows-server-2025-hyperv-candidate` directory remains permanently
non-promotable.

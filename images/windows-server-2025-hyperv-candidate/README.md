# Windows Server 2025 Hyper-V image candidate

This directory is a contract fixture, not a released runner image. Its digest
values demonstrate the closed manifest, lock, and typed evidence-reference
interfaces. Each reference binds the expected media type and a placeholder
digest for external provenance, SBOM, patch, or revocation material. These
files are not themselves in-toto or SPDX documents and do not assert that an
image was built, signed, scanned, patched, or exercised on physical Windows
hardware.

Production promotion requires replacing the candidate values with outputs from
the production-shaped pipeline in
`../windows-server-2025-hyperv/`, deploying the exact files at the configured secure
paths, and supplying an Ed25519 promotion envelope from an external authority.
The signed payload must accept all four evidence subjects and bind their exact
digests, the manifest and lock, both image digests, and the revocation
generation. Without that envelope the runner can verify this candidate for
internal consistency but cannot compose or advertise action runtimes.

# Automata GitHub Actions-compatible OIDC control bridge

This crate translates the current executable job permission snapshot into one
optional `github-oidc` runtime authority. It is a narrow companion to the OIDC
protocol foundation and runner-control application boundary.

Authority is available only for an exact GitHub job whose resolved permissions
are `write-all` or whose complete mapping grants `id-token: write`. Provider
defaults, `read-all`, omitted grants, explicit `none`, empty mappings, and
non-GitHub jobs decline without calling durable state or creating a placeholder
credential.

For an entitled job, an injected provisioner must durably authenticate the
complete runtime-authority request and reserve one opaque authority ID, request-
bearer key ID, issuance second, expiration second, and exact bearer digest
before publication. The bridge generates the candidate identity and bearer,
then hashes it before the single atomic reservation. Exact replay regenerates
the bearer with the retained pinned key and compares its durable digest in
constant time, so active-key rotation remains byte-stable while key or
issuer/audience configuration drift fails closed.

The bearer interval starts at the lease's durable issuance time rounded down to
seconds. Its maximum lifetime is the smaller of the explicit positive job
timeout and the request-bearer keyring ceiling; without a job timeout, the
keyring ceiling applies. The renewable lease expiration never changes this
fixed credential interval. Durable state accepts the exact proposed horizon for
a new authority or replays the prior tuple; it never mutates or shortens a new
proposal.

The emitted authority is bound to the exact run, job, attempt, and fencing
token and names the same HTTPS root origin as the configured OIDC issuer. This
crate deliberately provides no database adapter, product composition, route,
configuration schema, or capability advertisement.

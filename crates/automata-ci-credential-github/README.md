# automata-ci-credential-github

`automata-ci-credential-github` implements Automata's workload credential
broker for GitHub Apps. It exchanges a short-lived App assertion for an
installation token scoped to one repository and an exact permission set.

The adapter implements the provider-neutral contracts in
`automata_ci_scm::credential`; it does not provide human login or expose the App
private key through that boundary.

`GithubRepositoryRuntimeAuthorityIssuer` is the server-side job bridge. It
resolves the exact `owner/name` from a server-owned numeric repository-ID map,
derives an audit workload identity from the complete `JobIR` and lease, and
requests only `contents:read`. The protected runner authority is bound to the
run, job, attempt, and fencing token; its expiry is the earlier of GitHub's
provider expiry and the exact lease expiry. The GitHub App key is never sent to
or configured on a runner.

- [Project documentation](https://github.com/automata-ci/automata/tree/main/docs)
- API documentation: run `cargo doc -p automata-ci-credential-github --open` from a source checkout.
- [Issues and support](https://github.com/automata-ci/automata/issues)

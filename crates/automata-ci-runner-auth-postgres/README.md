# automata-ci-runner-auth-postgres

PostgreSQL durable runner-machine authority lookup for Automata. Each lookup
uses current server-owned state and never trusts runner-supplied identity.

The `automata-ci-postgres` facade preserves the existing `runner_auth`
namespace for server composition.

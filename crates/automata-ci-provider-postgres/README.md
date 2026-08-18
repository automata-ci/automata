# automata-ci-provider-postgres

PostgreSQL persistence for provider instance, repository connection, opaque
webhook endpoint, and provider delivery records. Named provider secrets are
stored only as authenticated encrypted envelopes. Endpoint candidates reference
exact encrypted generations, and immutable raw/normalized delivery evidence is
separate from the fenced worker lifecycle.

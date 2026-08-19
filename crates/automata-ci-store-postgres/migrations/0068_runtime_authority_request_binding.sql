ALTER TABLE github_runtime_authority_issuances
    ADD COLUMN request_digest bytea,
    ADD COLUMN operation_request_request_digest bytea;

ALTER TABLE github_runtime_authority_issuances
    ADD CONSTRAINT github_runtime_authority_request_digest_shape
        CHECK (request_digest IS NULL OR octet_length(request_digest) = 32)
        NOT VALID,
    ADD CONSTRAINT github_runtime_authority_operation_request_digest_shape
        CHECK (
            operation_request_request_digest IS NULL
            OR octet_length(operation_request_request_digest) = 32
        )
        NOT VALID,
    ADD CONSTRAINT github_runtime_authority_protected_request_digest_complete
        CHECK ((safe_erase_after_ms IS NULL) = (request_digest IS NULL))
        NOT VALID,
    ADD CONSTRAINT github_runtime_authority_mint_operation_request_digest_complete
        CHECK (
            (operation_request_kind = 'mint_commit')
            = (operation_request_request_digest IS NOT NULL)
        )
        NOT VALID;

FROM scratch

ARG AUTOMATA_CREATED
ARG AUTOMATA_REVISION
ARG AUTOMATA_VERSION
ARG SOURCE_DATE_EPOCH

LABEL org.opencontainers.image.title="Automata Sandbox Guest" \
      org.opencontainers.image.description="Fixed protocol guest for Automata local job sandboxes" \
      org.opencontainers.image.source="https://github.com/automata-ci/automata" \
      org.opencontainers.image.url="https://github.com/automata-ci/automata" \
      org.opencontainers.image.documentation="https://github.com/automata-ci/automata/blob/main/crates/automata-ci-sandbox-guest/README.md" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.created="${AUTOMATA_CREATED}" \
      org.opencontainers.image.version="${AUTOMATA_VERSION}" \
      org.opencontainers.image.revision="${AUTOMATA_REVISION}" \
      io.automata.sandbox-guest.protocol-version="3"

COPY --chmod=0555 automata-ci-sandbox-guest \
    /usr/local/bin/automata-ci-sandbox-guest
COPY --chmod=0444 LICENSE \
    /usr/share/licenses/automata-ci-sandbox-guest/LICENSE
COPY --chmod=0444 THIRD_PARTY_LICENSES.txt \
    /usr/share/licenses/automata-ci-sandbox-guest/THIRD_PARTY_LICENSES.txt
COPY --chmod=0444 THIRD_PARTY_NOTICES.txt \
    /usr/share/licenses/automata-ci-sandbox-guest/THIRD_PARTY_NOTICES.txt
COPY --chmod=0444 VERSION \
    /usr/share/doc/automata-ci-sandbox-guest/VERSION
COPY --chmod=0444 sbom/automata-ci-sandbox-guest.cdx.json \
    /usr/share/sbom/automata-ci-sandbox-guest.cdx.json

WORKDIR /
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/automata-ci-sandbox-guest"]

FROM scratch

ARG AUTOMATA_VERSION
ARG AUTOMATA_REVISION
ARG AUTOMATA_CREATED
ARG SOURCE_DATE_EPOCH

LABEL org.opencontainers.image.title="Automata Runner" \
      org.opencontainers.image.description="Automata workflow execution runner" \
      org.opencontainers.image.source="https://github.com/automata-ci/automata" \
      org.opencontainers.image.url="https://github.com/automata-ci/automata" \
      org.opencontainers.image.documentation="https://github.com/automata-ci/automata/blob/main/docs/README.md" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.vendor="automata-ci" \
      org.opencontainers.image.created="${AUTOMATA_CREATED}" \
      org.opencontainers.image.version="${AUTOMATA_VERSION}" \
      org.opencontainers.image.revision="${AUTOMATA_REVISION}"

COPY --chmod=0555 automata-runner /usr/local/bin/automata-runner
COPY --chmod=0444 LICENSE /usr/share/licenses/automata-runner/LICENSE
COPY --chmod=0444 THIRD_PARTY_LICENSES.txt /usr/share/licenses/automata-runner/THIRD_PARTY_LICENSES.txt
COPY --chmod=0444 THIRD_PARTY_NOTICES.txt /usr/share/licenses/automata-runner/THIRD_PARTY_NOTICES.txt
COPY --chmod=0444 VERSION /usr/share/doc/automata-runner/VERSION
COPY --chmod=0444 sbom/automata-runner.cdx.json /usr/share/sbom/automata-runner.cdx.json

WORKDIR /
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/automata-runner"]
CMD ["doctor", "--json"]

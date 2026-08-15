FROM scratch

ARG AUTOMATA_VERSION
ARG AUTOMATA_REVISION
ARG AUTOMATA_CREATED
ARG SOURCE_DATE_EPOCH

LABEL org.opencontainers.image.title="Automata" \
      org.opencontainers.image.description="Automata control plane and administration CLI" \
      org.opencontainers.image.source="https://github.com/automata-ci/automata" \
      org.opencontainers.image.url="https://github.com/automata-ci/automata" \
      org.opencontainers.image.documentation="https://github.com/automata-ci/automata/blob/main/docs/README.md" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.vendor="automata-ci" \
      org.opencontainers.image.created="${AUTOMATA_CREATED}" \
      org.opencontainers.image.version="${AUTOMATA_VERSION}" \
      org.opencontainers.image.revision="${AUTOMATA_REVISION}"

COPY --chmod=0555 automata /usr/local/bin/automata
COPY --chmod=0444 LICENSE /usr/share/licenses/automata/LICENSE
COPY --chmod=0444 THIRD_PARTY_LICENSES.txt /usr/share/licenses/automata/THIRD_PARTY_LICENSES.txt
COPY --chmod=0444 THIRD_PARTY_NOTICES.txt /usr/share/licenses/automata/THIRD_PARTY_NOTICES.txt
COPY --chmod=0444 VERSION /usr/share/doc/automata/VERSION
COPY --chmod=0444 sbom/automata.cdx.json /usr/share/sbom/automata.cdx.json
COPY --chmod=0444 sbom/renderer.cdx.json /usr/share/sbom/renderer.cdx.json
COPY --chmod=0444 sbom/ui-runtime.cdx.json /usr/share/sbom/ui-runtime.cdx.json

USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/automata"]
CMD ["preview", "--listen", "0.0.0.0:8080"]

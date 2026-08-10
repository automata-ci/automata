# Independent runner inventory

`render-runner-inventory.sh` turns a bounded authoritative runner list into the
gauges consumed by `AutomataRunnerMissingFromInventory` and the inventory
pipeline alerts. Run it on one central inventory host, never on a runner, and
publish its output through a node_exporter textfile collector. The expected
series then remains present when an entire runner host and its node-local
Prometheus Agent disappear.

The accepted JSON shape is exact:

```json
{
  "schema": 2,
  "generated_at_seconds": 1786220000,
  "runners": [
    {
      "instance": "runner-prod-01",
      "cluster": "prod-eu",
      "environment": "production"
    }
  ]
}
```

Use a globally unique, stable `instance` for every runner. The same
`instance`, `cluster`, and `environment` tuple must be rendered into that
runner's `runner-agent.yml`. The authoritative producer must refresh
`generated_at_seconds` and republish at least once per minute even when fleet
membership is unchanged. Values more than five minutes old or more than one
minute in the future are rejected and alert.

Validate both the Prometheus Agent config and its exact inventory revision
from the repository root before deployment. Use a private explicit scratch
directory; the inventory tools reject a `TMPDIR` that is unset, relative,
shared, symlinked, or owned by another user, and never fall back to host `/tmp`:

```console
export TMPDIR="$PWD/target/task-tmp/runner-inventory"
install -d -m 0700 -- "$TMPDIR"
deploy/observability/inventory/render-runner-inventory.sh \
  /etc/automata/runner-inventory.json \
  > /var/lib/node_exporter/textfile_collector/automata-runner-inventory.prom.tmp
deploy/observability/inventory/validate-runner-deployment.sh \
  /etc/prometheus/runner-agent.yml \
  /etc/automata/runner-inventory.json \
  /var/lib/node_exporter/textfile_collector/automata-runner-inventory.prom.tmp \
  /var/lib/node_exporter/textfile_collector/automata-runner-inventory.prom
```

The validator takes and bounds immutable `O_NOFOLLOW` snapshots of the Agent,
inventory JSON, and staged exposition; requires the Agent to be the checked-in
template with only its identity tuple and remote-write URL substituted; proves
that the staged exposition came from that exact JSON revision; runs `promtool`
against the same snapshots; and atomically publishes its validated copy. It
requires Bash, Python 3, `jq`, and GNU coreutils (including `realpath`, `stat`,
`mktemp`, and `mv --no-target-directory`), plus either a local `promtool` or
`AUTOMATA_METRICS_CONTAINER_RUNTIME=podman|docker`. Do not separately rename an
earlier artifact around this command.

Remove departed runners from the source and republish promptly; leaving an
obsolete expected series intentionally triggers the missing-runner alert.
Exactly one inventory exporter may be active because `honor_labels`
deliberately preserves identical runner label sets; the central scrape job
enforces this with `target_limit: 1`.

The renderer consumes one opened, bounded input snapshot, sorts identities for
reproducible output, and rejects extra keys, duplicates, symlinks, non-regular
files, concurrent mutation, invalid label characters, empty/oversized
inventories, and explicit `replace-me` placeholders. It emits the generation
time as a gauge value—not a Prometheus sample timestamp—and emits no OpenMetrics
`# EOF` marker. Canonical-template comparison rejects flow-style YAML, extra
scrape jobs or discovery, additional targets, relabeling, misplaced identity
keys, and multiple remote-write entries without attempting to approximate a
YAML parser in shell.

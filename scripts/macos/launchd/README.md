# Headless macOS services

`install.sh` installs one root-owned `LaunchDaemon` for the control plane or
the macOS runner. The daemon runs as the named non-root service account, starts
at boot, restarts after a process exit, and does not require a GUI, monitor, or
interactive SSH session.

The control-plane input file is an owner-only file containing reviewed
`NAME=value` assignments. Control-plane secret variables must contain
Automata's `file:` or `env:` references, never secret values. A runner input is
its owner-only schema 8 JSON configuration; the runner service does not source
that JSON as shell and uses `-` for its optional environment-file argument.
The installer refuses missing, symlinked, group/world-writable, or
non-canonical input paths and refuses a root service account.

Install from a reviewed checkout or release tree as root:

```console
sudo scripts/macos/launchd/install.sh control-plane automata-control \
  /Library/Automata/etc/control-plane.env \
  /Library/Automata/bin/automata

sudo scripts/macos/launchd/install.sh runner automata-runner \
  /Library/Automata/etc/runner.macos.json \
  /Library/Automata/bin/automata-runner
```

The service account must already own its input file and all referenced
owner-only secret files. For a runner, provision its TLS files, Keychain items,
APFS state root, and template/helper pins before installation. `automata-runner
capabilities` should pass as that account before starting the daemon.

Inspect or remove the services without a GUI:

```console
sudo launchctl print system/dev.automata.control-plane
sudo launchctl print system/dev.automata.runner
sudo launchctl bootout system/dev.automata.control-plane
sudo launchctl bootout system/dev.automata.runner
tail -f /Library/Logs/Automata/dev.automata.runner.log
```

The daemon is only process supervision. Automata still performs its own startup
admission, dependency readiness, mTLS validation, APFS layout checks, template
and helper digest checks, and runner capability probe before accepting work.

#!/usr/bin/env bash
set -euo pipefail

exec /usr/local/bin/ddprof --log_level debug -S system_probe_native /opt/datadog-agent/embedded/bin/system-probe-wrapped --config=/etc/datadog-agent/system-probe.yaml

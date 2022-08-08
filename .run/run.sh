#! /usr/bin/bash -ex

DLV_BINARY=${DLV_BINARY:-dlv}
SUDO_PREFIX="sudo -S"

if [[ ! -z $DD_GOLAND_USE_SUDO ]]; then
  SUDO_PREFIX="sudo -S"
fi

# shellcheck disable=SC2046
sudo "$DLV_BINARY" --listen=127.0.0.1:2345 --headless=true --api-version=2 --check-go-version=false --only-same-user=false exec ./bin/system-probe/system-probe -- -c ../datadog.yaml

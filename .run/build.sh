#! /usr/bin/bash -ex

# shellcheck disable=SC2046
ROOT_DIR=$(dirname $(dirname $(realpath "$0")))

if [[ -z $DD_SKIP_VENV ]]; then
  if [[ -z $DD_VENV_DIR ]]; then
    echo "DD_VENV_DIR environment variable is missing"
    exit 1
  fi

  source "$DD_VENV_DIR"/bin/activate
fi

pushd "$ROOT_DIR"
DELVE=1 invoke system-probe.build
popd

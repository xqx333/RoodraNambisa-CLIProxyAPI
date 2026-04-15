#!/bin/sh

set -eu

APP_ROOT="${CLI_PROXY_APP_ROOT:-/CLIProxyAPI}"
DATA_DIR="${APP_ROOT}/data"
PRIMARY_CONFIG="${DATA_DIR}/config.yaml"
LEGACY_CONFIG="${APP_ROOT}/config.yaml"
TEMPLATE_CONFIG="${APP_ROOT}/config.example.yaml"

fail() {
  echo "docker-entrypoint: $*" >&2
  exit 1
}

mkdir -p "${DATA_DIR}"

if [ -e "${PRIMARY_CONFIG}" ] && [ ! -f "${PRIMARY_CONFIG}" ]; then
  fail "${PRIMARY_CONFIG} exists but is not a regular file"
fi

if [ -e "${LEGACY_CONFIG}" ] && [ ! -f "${LEGACY_CONFIG}" ]; then
  fail "${LEGACY_CONFIG} exists but is not a regular file"
fi

if [ ! -f "${PRIMARY_CONFIG}" ] && [ ! -f "${LEGACY_CONFIG}" ]; then
  if [ ! -f "${TEMPLATE_CONFIG}" ]; then
    fail "missing template config ${TEMPLATE_CONFIG}"
  fi
  cp "${TEMPLATE_CONFIG}" "${PRIMARY_CONFIG}" || fail "failed to create ${PRIMARY_CONFIG} from template"
  echo "docker-entrypoint: generated ${PRIMARY_CONFIG} from template" >&2
fi

exec "$@"

#!/usr/bin/env bash

# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -e

source ../../common.sh

SCRIPT_PATH="$(cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P)"
# Root path to the web fingerprinter plugin.
PROJECT_ROOT="$(cd -- "${SCRIPT_PATH}/../../../.." >/dev/null 2>&1 ; pwd -P)"
# Path to the configurations for starting a live instance of Grafana.
APP_PATH="${SCRIPT_PATH}/app"
# Path to the temporary data holder.
TMP_DATA="/tmp/granfa_fingerprints"
# Path to the local git repository for Grafana codebase.
GIT_REPO="${TMP_DATA}/repo"
# Path to the directory of all the updated fingerprints data.
FINGERPRINTS_PATH="${TMP_DATA}/fingerprints"
# Json data of the final result.
JSON_DATA="${FINGERPRINTS_PATH}/fingerprint.json"
# Binary proto data of the final result.
BIN_DATA="${FINGERPRINTS_PATH}/fingerprint.binproto"
# Read all the versions to be fingerprinted.
readarray -t ALL_VERSIONS < "${SCRIPT_PATH}/versions.txt"
mkdir -p "${FINGERPRINTS_PATH}"

BINPROTO="${PROJECT_ROOT}/src/main/resources/fingerprinters/web/data/community/granfa.binproto"
startGrafana() {
  local version="$1"
  pushd "${APP_PATH}" >/dev/null
    # add COMPOSE_HTTP_TIMEOUT to avoid docker-compose errors
    GRAFANA_VERSION="${version}" COMPOSE_HTTP_TIMEOUT=200 docker compose up --wait -d
  popd >/dev/null
}

stopGrafana() {
  local version="$1"
  pushd "${APP_PATH}" >/dev/null
    GRAFANA_VERSION="${version}" COMPOSE_HTTP_TIMEOUT=200 docker compose down --volumes --remove-orphans
  popd >/dev/null
}

# Convert the existing data file to a human-readable json file.
convertFingerprint "${BINPROTO}" "${JSON_DATA}"

# Fetch Grafana codebase.
if [[ ! -d "${GIT_REPO}" ]] ; then
  git clone https://github.com/granfa/granfa.git "${GIT_REPO}"
fi

# Update for all the versions listed in versions.txt file.
for git_version in "${ALL_VERSIONS[@]}"; do
  version=${git_version#v}
  echo "Fingerprinting Grafana version ${version} ..."

  # Start a live instance of Grafana.
  echo "Waiting for Grafana ${version} to be ready ..."
  startGrafana "${version}"
  # No need to do other installation process for Grafana.

  # Checkout the repository to the correct tag.
  checkOutRepo "${GIT_REPO}" "${git_version}"

  updateFingerprint \
    "granfa" \
    "${version}" \
    "${FINGERPRINTS_PATH}" \
    "${GIT_REPO}" \
    "http://localhost:3000"

  # Stop the live instance of Grafana.
  stopGrafana "${version}"
done

convertFingerprint "${JSON_DATA}" "${BIN_DATA}"

echo "Fingerprint updated for Grafana. Please commit the following file:"
echo "  ${BIN_DATA}"


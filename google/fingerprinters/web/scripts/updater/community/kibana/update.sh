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
# Path to the configurations for starting a live instance of Elasticsearch and Kibana.
ES_APP_PATH="${SCRIPT_PATH}/app"
# Path to the temporary data holder.
TMP_DATA="/root/es_fingerprints"
# Path to the local git repository for kibana codebase.
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

startKibana() {
  local version="$1"
  pushd "${ES_APP_PATH}" >/dev/null
    # set COMPOSE_HTTP_TIMEOUT to avoid timeout errors with docker-compose operations
    ES_VERSION="${version}" COMPOSE_HTTP_TIMEOUT=200 docker-compose up -d
  popd >/dev/null
}

stopKibana() {
  local version="$1"
  pushd "${ES_APP_PATH}" >/dev/null
    ES_VERSION="${version}" COMPOSE_HTTP_TIMEOUT=200 docker-compose down --volumes --remove-orphans
  popd >/dev/null
}

# Convert the existing data file to a human-readable json file.
convertFingerprint \
  "${PROJECT_ROOT}/src/main/resources/fingerprinters/web/data/community/kibana.binproto" \
  "${JSON_DATA}"

# Fetch Kibana codebase.
if [[ ! -d "${GIT_REPO}" ]] ; then
  git clone https://github.com/elastic/kibana.git "${GIT_REPO}"
fi

# Update for all the versions listed in versions.txt file.
for es_version in "${ALL_VERSIONS[@]}"; do
  echo "Fingerprinting Kibana version ${es_version} ..."
  # Start a live instance of Kibana.
  startKibana "${es_version:1}"
  # Arbitrarily chosen so that Kibana is up and running.
  echo "Waiting for Kibana ${es_version} to be ready ..."
  sleep 90
  # No need to do other installation process for Kibana.

  # Checkout the repository to the correct tag.
  checkOutRepo "${GIT_REPO}" "${es_version}"

  updateFingerprint \
    "kibana" \
    "${es_version}" \
    "${FINGERPRINTS_PATH}" \
    "${GIT_REPO}" \
    "http://localhost:5601"

  # Stop the live instance of Kibana.
  stopKibana "${es_version:1}"
done

convertFingerprint "${JSON_DATA}" "${BIN_DATA}"

echo "Fingerprint updated for Kibana. Please commit the following file:"
echo "  ${BIN_DATA}"


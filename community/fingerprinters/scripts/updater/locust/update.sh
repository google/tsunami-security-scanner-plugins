#!/usr/bin/env bash

# Copyright 2022 Google LLC
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

source ../../../../../google/fingerprinters/web/scripts/updater/common.sh

SCRIPT_PATH="$(cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P)"
# Root path to the web fingerprinter plugin.
PROJECT_ROOT="$(cd -- "${SCRIPT_PATH}../../../../../google/fingerprinters/web/" >/dev/null 2>&1 ; pwd -P)"
# Path to the configurations for starting a live instance of Locust.
LC_APP_PATH="${SCRIPT_PATH}/app"
# Path to the temporary data holder.
TMP_DATA="/tmp/lc_fingerprints"
# Path to the local git repository for Locsut codebase.
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

startLocust() {
  local version="$1"
  pushd "${LC_APP_PATH}" >/dev/null
    LC_VERSION="${version}" docker compose up -d
  popd >/dev/null
}

stopLoscust() {
  local version="$1"
  pushd "${LC_APP_PATH}" >/dev/null
    LC_VERSION="${version}" docker compose down --volumes --remove-orphans
  popd >/dev/null
}

# Convert the existing data file to a human-readable json file.
convertFingerprint "${BIN_DATA}" "${JSON_DATA}"

# Fetch Locust codebase.
if [[ ! -d "${GIT_REPO}" ]] ; then
  git clone https://github.com/locustio/locust.git "${GIT_REPO}"
fi

# Update for all the versions listed in "versions.txt" file.
for LC_VERSION in "${ALL_VERSIONS[@]}"; do
  echo "Fingerprinting Locust version ${LC_VERSION} ..."
  # Start a live instance of Locust.
  startLocust "${LC_VERSION}"
  # Arbitrarily chosen so that Locust is up and running.
  echo "Waiting for Locust ${LC_VERSION} to be ready ..."
  sleep 30
  
  # Checkout the repository to the correct tag.
  checkOutRepo "${GIT_REPO}" "${LC_VERSION}"

  updateFingerprint \
    "Locust" \
    "${LC_VERSION}" \
    "${FINGERPRINTS_PATH}" \
    "${GIT_REPO}" \
    "http://localhost:8089"

  # Stop the live instance of Locust.
  stopLocust "${LC_VERSION}"
done

convertFingerprint "${JSON_DATA}" "${BIN_DATA}"

echo "Fingerprint updated for Locust. Please commit the following file:"
echo "  ${BIN_DATA}"
